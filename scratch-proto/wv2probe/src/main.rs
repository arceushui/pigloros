//! THROWAWAY WebView2 probe for Redmine #471 (ADR-110 r6 prototype gates).
//! Never merged. Drives WebView2 directly through webview2-com 0.39.1 /
//! windows 0.62.2 on the hosted windows-latest runner and reports:
//!  G11  can a controller be created in the hosted session at all;
//!  G1   SharedBuffer delivery with IsWebMessageEnabled = false;
//!  G2   JS Atomics <-> Rust SeqCst handoff stress (A/B mismatch count);
//!  G3   lost `sharedbufferreceived` events over N fresh-environment runs;
//!  G4   Controller::Close -> BrowserProcessExited latency over N runs;
//!  G6   settings readback (§5.2 subset);
//!  G12  request headers seen by the loopback listener (Sec-Fetch-*, count);
//!  G16  preconnect sockets closed by the 1 s first-byte timeout.

#[cfg(not(windows))]
fn main() {
    println!("wv2probe: Windows only");
}

#[cfg(windows)]
fn main() {
    std::process::exit(probe::main());
}

#[cfg(windows)]
mod probe {
    use std::cell::{Cell, RefCell};
    use std::fmt::Write as _;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::rc::Rc;
    use std::result::Result;
    use std::sync::atomic::{fence, AtomicI32, AtomicU32, AtomicU64, Ordering};
    use std::sync::{mpsc, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use sha2::Digest as _;
    use webview2_com::Microsoft::Web::WebView2::Win32::*;
    use webview2_com::*;
    use windows::core::{Interface, BOOL, HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{E_POINTER, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::HiDpi::{
        SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetClientRect, GetForegroundWindow,
        PeekMessageW, RegisterClassW, SetForegroundWindow, ShowWindow, TranslateMessage,
        CW_USEDEFAULT, MSG, PM_REMOVE, SW_SHOWNORMAL, WNDCLASSW, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };

    const PORT: u16 = 49291;
    const OWNER_URL: &str = "http://localhost:49291/owner.html";

    // ---------------------------------------------------------------- page

    const STYLE: &str = "body{font:14px sans-serif;margin:16px}";
    const SCRIPT: &str = r#"
(function () {
  "use strict";
  function st(s) { document.title = s; }
  var wv = window.chrome && window.chrome.webview;
  if (!wv) { st("ERR:no-chrome.webview"); return; }
  if (typeof wv.addEventListener !== "function") { st("ERR:no-addEventListener"); return; }
  if (typeof wv.releaseBuffer !== "function") { st("ERR:no-releaseBuffer"); return; }
  var req = null, rep = null, kind = "?";
  function release() {
    try { if (rep) wv.releaseBuffer(rep); } catch (x) { st("ERR:release-reply:" + x); }
    try { if (req) wv.releaseBuffer(req); } catch (x) { st("ERR:release-request:" + x); }
    rep = null; req = null;
  }
  function stress(b, n) {
    var a = new Int32Array(b), mism = 0, t0 = Date.now();
    for (var i = 0; i < n; i++) {
      var want = 2 * i + 1, spins = 0;
      while (Atomics.load(a, 0) !== want) {
        if (++spins > 2000000000) { st("ERR:stress-timeout:" + i); return; }
      }
      var x = a[1], y = a[2];
      if (x !== y || x !== (i ^ 0x5a5a5a5a)) mism++;
      a[4] = x ^ 0x0f0f0f0f; a[5] = y ^ 0x0f0f0f0f;
      Atomics.store(a, 0, want + 1);
    }
    a[3] = mism;
    wv.releaseBuffer(b);
    st("STRESS:" + n + ":" + mism + ":" + (Date.now() - t0) + ":" + kind);
  }
  function go() {
    var rq = new DataView(req), rp = new DataView(rep);
    if (rq.getUint32(0, true) !== 0x31425750) { st("ERR:magic"); release(); return; }
    var gen = rq.getUint32(12, true);
    if (rp.getUint32(12, true) !== gen) { st("ERR:gen"); release(); return; }
    if (rq.getUint32(40, true) !== 2) { st("ERR:req-state"); release(); return; }
    var s = new Int32Array(rep);
    if (Atomics.compareExchange(s, 10, 0, 1) !== 0) { st("ERR:cas"); release(); return; }
    var u8 = new Uint8Array(rep), n = 96;
    for (var k = 0; k < n; k++) u8[64 + k] = (gen * 7 + k) & 255;
    rp.setUint32(36, n, true);
    Atomics.store(s, 10, 2);
    st("WROTE:" + gen + ":" + kind);
    var poll = function () {
      if (rep === null) return;
      if (Atomics.load(s, 10) === 4) {
        for (var k = 64; k < u8.length; k++) u8[k] = 0;
        Atomics.store(s, 10, 5);
        release();
        st("RELEASED:" + gen + ":" + kind);
        return;
      }
      setTimeout(poll, 20);
    };
    setTimeout(poll, 20);
  }
  wv.addEventListener("sharedbufferreceived", function (e) {
    try {
      var d = e.additionalData || {};
      var b = e.getBuffer();
      kind = Object.prototype.toString.call(b);
      if (d.role === "stress") { stress(b, d.n); return; }
      if (d.role === "request") req = b; else if (d.role === "reply") rep = b;
      if (req && rep) go();
    } catch (x) { st("ERR:handler:" + x); }
  });
  st("LISTENING:" + typeof SharedArrayBuffer + ":" + (self.crossOriginIsolated ? "coi" : "nocoi"));
})();
"#;

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&sha2::Sha256::digest(data));
        out
    }

    fn b64(d: &[u8; 32]) -> String {
        let mut out = [0u8; 44];
        let n = base64::engine::general_purpose::STANDARD
            .encode_slice(d, &mut out)
            .expect("b64");
        String::from_utf8_lossy(&out[..n]).into_owned()
    }

    fn hex(d: &[u8]) -> String {
        let mut s = String::new();
        for b in d {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn csp() -> String {
        format!(
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; \
             script-src 'sha256-{}'; style-src 'sha256-{}'; img-src 'none'; connect-src 'none'",
            b64(&sha256(SCRIPT.as_bytes())),
            b64(&sha256(STYLE.as_bytes()))
        )
    }

    fn owner_response() -> &'static [u8] {
        static R: OnceLock<Vec<u8>> = OnceLock::new();
        R.get_or_init(|| {
            let body = format!(
                "<!doctype html><html><head><meta charset=\"utf-8\"><title>owner</title>\
                 <style>{STYLE}</style><script>{SCRIPT}</script></head><body>PiglorOS owner probe</body></html>"
            );
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
                 Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
                 Cross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\n\
                 Permissions-Policy: publickey-credentials-create=(self), publickey-credentials-get=(self), \
                 clipboard-read=(), clipboard-write=(), camera=(), microphone=(), geolocation=()\r\n\
                 Content-Security-Policy: {}\r\nConnection: close\r\n\r\n",
                body.len(),
                csp()
            );
            let mut v = head.into_bytes();
            v.extend_from_slice(body.as_bytes());
            v
        })
    }

    // ------------------------------------------------------------ listener

    static SERVED: AtomicU32 = AtomicU32::new(0);
    static CONNS_V4: AtomicU32 = AtomicU32::new(0);
    static CONNS_V6: AtomicU32 = AtomicU32::new(0);
    static ACTIVE: AtomicU32 = AtomicU32::new(0);
    static MAX_ACTIVE: AtomicU32 = AtomicU32::new(0);
    static PRECONNECT_TIMEOUT: AtomicU32 = AtomicU32::new(0);
    static EOF_NO_BYTES: AtomicU32 = AtomicU32::new(0);
    static HEADER_TIMEOUT: AtomicU32 = AtomicU32::new(0);
    static TOO_MANY_HEADERS: AtomicU32 = AtomicU32::new(0);
    static MAX_HEADERS: AtomicU32 = AtomicU32::new(0);
    static BAD_ADMISSION: AtomicU32 = AtomicU32::new(0);
    static NON_OWNER: AtomicU32 = AtomicU32::new(0);
    static FIRST_HEADERS: OnceLock<String> = OnceLock::new();
    static ODD: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn note_odd(s: String) {
        if let Ok(mut v) = ODD.lock() {
            if v.len() < 40 {
                v.push(s);
            }
        }
    }

    fn start_listener() -> Result<(), String> {
        let v4 = TcpListener::bind(("127.0.0.1", PORT)).map_err(|e| format!("bind v4: {e}"))?;
        let v6 = TcpListener::bind(("::1", PORT));
        std::thread::spawn(move || accept_loop(v4, false));
        match v6 {
            Ok(l) => {
                std::thread::spawn(move || accept_loop(l, true));
            }
            Err(e) => println!("PROBE listener_v6_bind_error={e}"),
        }
        Ok(())
    }

    fn accept_loop(l: TcpListener, v6: bool) {
        loop {
            while ACTIVE.load(Ordering::SeqCst) >= 3 {
                std::thread::sleep(Duration::from_millis(1));
            }
            let Ok((s, _)) = l.accept() else { continue };
            if v6 {
                CONNS_V6.fetch_add(1, Ordering::SeqCst);
            } else {
                CONNS_V4.fetch_add(1, Ordering::SeqCst);
            }
            let a = ACTIVE.fetch_add(1, Ordering::SeqCst) + 1;
            MAX_ACTIVE.fetch_max(a, Ordering::SeqCst);
            std::thread::spawn(move || {
                handle(s);
                ACTIVE.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }

    fn handle(mut s: TcpStream) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
        let mut buf = [0u8; 8192];
        let mut n = 0usize;
        let t0 = Instant::now();
        loop {
            match s.read(&mut buf[n..]) {
                Ok(0) => {
                    if n == 0 {
                        EOF_NO_BYTES.fetch_add(1, Ordering::SeqCst);
                    }
                    return;
                }
                Ok(k) => n += k,
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    if n == 0 {
                        PRECONNECT_TIMEOUT.fetch_add(1, Ordering::SeqCst);
                    } else {
                        HEADER_TIMEOUT.fetch_add(1, Ordering::SeqCst);
                    }
                    return;
                }
                Err(_) => return,
            }
            if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if n == buf.len() {
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                return;
            }
            let left = Duration::from_secs(2).saturating_sub(t0.elapsed());
            if left.is_zero() {
                HEADER_TIMEOUT.fetch_add(1, Ordering::SeqCst);
                return;
            }
            let _ = s.set_read_timeout(Some(left));
        }
        let mut headers = [httparse::EMPTY_HEADER; 24];
        let mut req = httparse::Request::new(&mut headers);
        let status = req.parse(&buf[..n]);
        match status {
            Ok(httparse::Status::Complete(_)) => {}
            Err(httparse::Error::TooManyHeaders) => {
                TOO_MANY_HEADERS.fetch_add(1, Ordering::SeqCst);
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                return;
            }
            other => {
                note_odd(format!("parse={other:?}"));
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                return;
            }
        }
        let count = req.headers.iter().filter(|h| !h.name.is_empty()).count() as u32;
        MAX_HEADERS.fetch_max(count, Ordering::SeqCst);
        let get = |name: &str| {
            req.headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .map(|h| String::from_utf8_lossy(h.value).into_owned())
        };
        let path = req.path.unwrap_or("").to_owned();
        let method = req.method.unwrap_or("").to_owned();
        let admitted = method == "GET"
            && req.version == Some(1)
            && get("host").as_deref() == Some("localhost:49291")
            && get("sec-fetch-dest").as_deref() == Some("document")
            && get("sec-fetch-mode").as_deref() == Some("navigate")
            && get("content-length").is_none()
            && get("transfer-encoding").is_none();
        if path == "/owner.html" {
            if !admitted {
                BAD_ADMISSION.fetch_add(1, Ordering::SeqCst);
                let mut d = String::new();
                for h in req.headers.iter().filter(|h| !h.name.is_empty()) {
                    let _ = write!(d, "{}: {} | ", h.name, String::from_utf8_lossy(h.value));
                }
                note_odd(format!("not-admitted {method} {path} {d}"));
            }
            let _ = FIRST_HEADERS.get_or_init(|| {
                let mut d = format!("{method} {path} HTTP/1.{} ; {count} headers ; ", req.version.unwrap_or(9));
                for h in req.headers.iter().filter(|h| !h.name.is_empty()) {
                    let _ = write!(d, "[{}: {}] ", h.name, String::from_utf8_lossy(h.value));
                }
                d
            });
            if s.write_all(owner_response()).is_ok() {
                SERVED.fetch_add(1, Ordering::SeqCst);
            }
        } else {
            NON_OWNER.fetch_add(1, Ordering::SeqCst);
            note_odd(format!("non-owner {method} {path}"));
            let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
        let _ = s.flush();
    }

    // ---------------------------------------------------------------- window

    extern "system" fn wndproc(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        unsafe { DefWindowProcW(h, m, w, l) }
    }

    fn create_window() -> Result<HWND, String> {
        unsafe {
            let hinst = GetModuleHandleW(None).map_err(|e| format!("GetModuleHandleW: {e}"))?;
            let class = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                hInstance: HINSTANCE(hinst.0),
                lpszClassName: windows::core::w!("Wv2Probe"),
                ..Default::default()
            };
            let _ = RegisterClassW(&class);
            let hwnd = CreateWindowExW(
                Default::default(),
                windows::core::w!("Wv2Probe"),
                windows::core::w!("PiglorOS owner probe"),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                480,
                640,
                None,
                None,
                Some(HINSTANCE(hinst.0)),
                None,
            )
            .map_err(|e| format!("CreateWindowExW: {e}"))?;
            let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
            let fg_set = SetForegroundWindow(hwnd).as_bool();
            let fg = GetForegroundWindow() == hwnd;
            println!("PROBE window_created=true set_foreground_returned={fg_set} is_foreground={fg}");
            Ok(hwnd)
        }
    }

    fn pump_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            unsafe {
                let mut msg = MSG::default();
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            if done() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // ---------------------------------------------------------------- surface

    struct Surface {
        env: ICoreWebView2Environment,
        exit_token: i64,
        controller: Option<ICoreWebView2Controller>,
        webview: Option<ICoreWebView2>,
        browser_pid: u32,
        dcl: Rc<Cell<Option<(u64, Instant)>>>,
        nav_done: Rc<RefCell<Option<String>>>,
        process_failed: Rc<RefCell<Vec<String>>>,
        exited: Rc<RefCell<Option<(Instant, String, u32)>>>,
        udf: std::path::PathBuf,
        version: String,
        settings_ok: bool,
        settings: String,
    }

    fn wv_err(e: webview2_com::Error) -> String {
        format!("{e:?}")
    }

    fn take_str(p: PWSTR) -> String {
        take_pwstr(p)
    }

    fn open_surface(runtime: Option<&str>, udf_root: &std::path::Path, tag: &str) -> Result<Surface, String> {
        let udf = udf_root.join(tag);
        let _ = std::fs::remove_dir_all(&udf);
        std::fs::create_dir_all(&udf).map_err(|e| format!("mkdir udf: {e}"))?;
        let udf_h = HSTRING::from(udf.display().to_string());
        let rt_h = runtime.map(HSTRING::from);

        let options = CoreWebView2EnvironmentOptions::default();
        unsafe {
            options.set_additional_browser_arguments(String::new());
            options.set_are_browser_extensions_enabled(false);
            options.set_is_custom_crash_reporting_enabled(true);
            options.set_exclusive_user_data_folder_access(true);
        }
        let options: ICoreWebView2EnvironmentOptions = options.into();

        let env = {
            let (tx, rx) = mpsc::channel();
            let folder = rt_h.as_ref().map_or(PCWSTR::null(), |h| PCWSTR(h.as_ptr()));
            let udf_p = PCWSTR(udf_h.as_ptr());
            let opts = options.clone();
            CreateCoreWebView2EnvironmentCompletedHandler::wait_for_async_operation(
                Box::new(move |handler| unsafe {
                    CreateCoreWebView2EnvironmentWithOptions(folder, udf_p, &opts, &handler)
                        .map_err(webview2_com::Error::WindowsError)
                }),
                Box::new(move |hr, env| {
                    hr?;
                    tx.send(env.ok_or_else(|| windows::core::Error::from(E_POINTER)))
                        .expect("send env");
                    Ok(())
                }),
            )
            .map_err(|e| format!("env-create: {}", wv_err(e)))?;
            rx.recv()
                .map_err(|e| format!("env recv: {e}"))?
                .map_err(|e| format!("env result: {e}"))?
        };
        let version = unsafe {
            let mut p = PWSTR::null();
            env.BrowserVersionString(&mut p).map_err(|e| format!("BrowserVersionString: {e}"))?;
            take_str(p)
        };

        let exited: Rc<RefCell<Option<(Instant, String, u32)>>> = Rc::new(RefCell::new(None));
        let env5: ICoreWebView2Environment5 = env.cast().map_err(|e| format!("env5: {e}"))?;
        let mut exit_token = 0i64;
        {
            let ex = exited.clone();
            unsafe {
                env5.add_BrowserProcessExited(
                    &BrowserProcessExitedEventHandler::create(Box::new(move |_e, args| {
                        let mut kind = COREWEBVIEW2_BROWSER_PROCESS_EXIT_KIND::default();
                        let mut pid = 0u32;
                        if let Some(a) = args {
                            a.BrowserProcessExitKind(&mut kind)?;
                            a.BrowserProcessId(&mut pid)?;
                        }
                        *ex.borrow_mut() = Some((Instant::now(), format!("{}", kind.0), pid));
                        Ok(())
                    })),
                    &mut exit_token,
                )
                .map_err(|e| format!("add_BrowserProcessExited: {e}"))?;
            }
        }

        let hwnd = window();
        let controller = {
            let (tx, rx) = mpsc::channel();
            let e2 = env.clone();
            CreateCoreWebView2ControllerCompletedHandler::wait_for_async_operation(
                Box::new(move |handler| unsafe {
                    e2.CreateCoreWebView2Controller(hwnd, &handler)
                        .map_err(webview2_com::Error::WindowsError)
                }),
                Box::new(move |hr, c| {
                    hr?;
                    tx.send(c.ok_or_else(|| windows::core::Error::from(E_POINTER)))
                        .expect("send controller");
                    Ok(())
                }),
            )
            .map_err(|e| format!("controller-create: {}", wv_err(e)))?;
            rx.recv()
                .map_err(|e| format!("controller recv: {e}"))?
                .map_err(|e| format!("controller result: {e}"))?
        };
        let webview = unsafe { controller.CoreWebView2() }.map_err(|e| format!("CoreWebView2: {e}"))?;
        let mut browser_pid = 0u32;
        unsafe {
            let _ = webview.BrowserProcessId(&mut browser_pid);
            let mut rect = RECT::default();
            let _ = GetClientRect(hwnd, &mut rect);
            controller.SetBounds(rect).map_err(|e| format!("SetBounds: {e}"))?;
            controller.SetIsVisible(true).map_err(|e| format!("SetIsVisible: {e}"))?;
            let _ = controller.MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
        }

        let (settings_ok, settings) = apply_settings(&webview, &controller)?;

        let dcl: Rc<Cell<Option<(u64, Instant)>>> = Rc::new(Cell::new(None));
        let nav_done: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
        let process_failed: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        unsafe {
            let wv2: ICoreWebView2_2 = webview.cast().map_err(|e| format!("ICoreWebView2_2: {e}"))?;
            let d = dcl.clone();
            let mut t = 0i64;
            wv2.add_DOMContentLoaded(
                &DOMContentLoadedEventHandler::create(Box::new(move |_s, args| {
                    let mut id = 0u64;
                    if let Some(a) = args {
                        a.NavigationId(&mut id)?;
                    }
                    d.set(Some((id, Instant::now())));
                    Ok(())
                })),
                &mut t,
            )
            .map_err(|e| format!("add_DOMContentLoaded: {e}"))?;
            let nd = nav_done.clone();
            webview
                .add_NavigationCompleted(
                    &NavigationCompletedEventHandler::create(Box::new(move |_s, args| {
                        let mut ok = BOOL::default();
                        let mut st = COREWEBVIEW2_WEB_ERROR_STATUS::default();
                        if let Some(a) = args {
                            a.IsSuccess(&mut ok)?;
                            a.WebErrorStatus(&mut st)?;
                        }
                        *nd.borrow_mut() = Some(format!("success={} status={}", ok.as_bool(), st.0));
                        Ok(())
                    })),
                    &mut t,
                )
                .map_err(|e| format!("add_NavigationCompleted: {e}"))?;
            let pf = process_failed.clone();
            webview
                .add_ProcessFailed(
                    &ProcessFailedEventHandler::create(Box::new(move |_s, args| {
                        let mut k = COREWEBVIEW2_PROCESS_FAILED_KIND::default();
                        if let Some(a) = args {
                            a.ProcessFailedKind(&mut k)?;
                        }
                        pf.borrow_mut().push(format!("kind={}", k.0));
                        Ok(())
                    })),
                    &mut t,
                )
                .map_err(|e| format!("add_ProcessFailed: {e}"))?;
        }

        Ok(Surface {
            env,
            exit_token,
            controller: Some(controller),
            webview: Some(webview),
            browser_pid,
            dcl,
            nav_done,
            process_failed,
            exited,
            udf,
            version,
            settings_ok,
            settings,
        })
    }

    macro_rules! set_read {
        ($obj:expr, $set:ident, $get:ident, $val:expr, $ok:ident, $out:ident) => {{
            $obj.$set($val).map_err(|e| format!("{}: {e}", stringify!($set)))?;
            let mut b = BOOL::default();
            $obj.$get(&mut b).map_err(|e| format!("{}: {e}", stringify!($get)))?;
            let _ = write!($out, "{}={} ", stringify!($get), b.as_bool());
            if b.as_bool() != $val {
                $ok = false;
            }
        }};
    }

    fn apply_settings(webview: &ICoreWebView2, controller: &ICoreWebView2Controller) -> Result<(bool, String), String> {
        let mut ok = true;
        let mut out = String::new();
        unsafe {
            let s: ICoreWebView2Settings = webview.Settings().map_err(|e| format!("Settings: {e}"))?;
            set_read!(s, SetIsScriptEnabled, IsScriptEnabled, true, ok, out);
            set_read!(s, SetIsWebMessageEnabled, IsWebMessageEnabled, false, ok, out);
            set_read!(s, SetAreDefaultScriptDialogsEnabled, AreDefaultScriptDialogsEnabled, false, ok, out);
            set_read!(s, SetIsStatusBarEnabled, IsStatusBarEnabled, false, ok, out);
            set_read!(s, SetAreDevToolsEnabled, AreDevToolsEnabled, false, ok, out);
            set_read!(s, SetAreDefaultContextMenusEnabled, AreDefaultContextMenusEnabled, false, ok, out);
            set_read!(s, SetAreHostObjectsAllowed, AreHostObjectsAllowed, false, ok, out);
            set_read!(s, SetIsZoomControlEnabled, IsZoomControlEnabled, false, ok, out);
            set_read!(s, SetIsBuiltInErrorPageEnabled, IsBuiltInErrorPageEnabled, false, ok, out);
            let s3: ICoreWebView2Settings3 = s.cast().map_err(|e| format!("Settings3: {e}"))?;
            set_read!(s3, SetAreBrowserAcceleratorKeysEnabled, AreBrowserAcceleratorKeysEnabled, false, ok, out);
            let s4: ICoreWebView2Settings4 = s.cast().map_err(|e| format!("Settings4: {e}"))?;
            set_read!(s4, SetIsPasswordAutosaveEnabled, IsPasswordAutosaveEnabled, false, ok, out);
            set_read!(s4, SetIsGeneralAutofillEnabled, IsGeneralAutofillEnabled, false, ok, out);
            let s5: ICoreWebView2Settings5 = s.cast().map_err(|e| format!("Settings5: {e}"))?;
            set_read!(s5, SetIsPinchZoomEnabled, IsPinchZoomEnabled, false, ok, out);
            let s6: ICoreWebView2Settings6 = s.cast().map_err(|e| format!("Settings6: {e}"))?;
            set_read!(s6, SetIsSwipeNavigationEnabled, IsSwipeNavigationEnabled, false, ok, out);
            let s8: ICoreWebView2Settings8 = s.cast().map_err(|e| format!("Settings8: {e}"))?;
            set_read!(s8, SetIsReputationCheckingRequired, IsReputationCheckingRequired, false, ok, out);
            let c4: ICoreWebView2Controller4 = controller.cast().map_err(|e| format!("Controller4: {e}"))?;
            set_read!(c4, SetAllowExternalDrop, AllowExternalDrop, false, ok, out);
        }
        Ok((ok, out))
    }

    fn title(s: &Surface) -> String {
        let Some(wv) = s.webview.as_ref() else { return String::new() };
        unsafe {
            let mut p = PWSTR::null();
            if wv.DocumentTitle(&mut p).is_err() {
                return String::new();
            }
            take_str(p)
        }
    }

    fn navigate(s: &Surface) -> Result<(), String> {
        let url = HSTRING::from(OWNER_URL);
        unsafe {
            s.webview
                .as_ref()
                .ok_or("no webview")?
                .Navigate(PCWSTR(url.as_ptr()))
                .map_err(|e| format!("Navigate: {e}"))
        }
    }

    /// Close per §5.7: Controller::Close, drop controller/WebView, keep env and
    /// the BrowserProcessExited subscription, wait <= 10 s (5 s is the gate).
    fn close_surface(mut s: Surface) -> (Option<u128>, String, bool, bool) {
        if let Some(c) = s.controller.take() {
            unsafe {
                let _ = c.Close();
            }
        }
        s.webview = None;
        let t_close = Instant::now();
        let ex = s.exited.clone();
        pump_until(Duration::from_secs(10), || ex.borrow().is_some());
        let got = s.exited.borrow().clone();
        let (lat, kind, pid_match) = match got {
            Some((t, k, pid)) => (Some(t.duration_since(t_close).as_millis()), k, pid == s.browser_pid),
            None => (None, "none".into(), false),
        };
        unsafe {
            if let Ok(e5) = s.env.cast::<ICoreWebView2Environment5>() {
                let _ = e5.remove_BrowserProcessExited(s.exit_token);
            }
        }
        let udf = s.udf.clone();
        drop(s);
        let mut removed = false;
        for _ in 0..20 {
            if std::fs::remove_dir_all(&udf).is_ok() || !udf.exists() {
                removed = true;
                break;
            }
            pump_until(Duration::from_millis(100), || false);
        }
        (lat, kind, pid_match, removed)
    }

    thread_local! { static WINDOW: Cell<Option<isize>> = const { Cell::new(None) }; }

    fn set_window(h: HWND) {
        WINDOW.with(|w| w.set(Some(h.0 as isize)));
    }

    fn window() -> HWND {
        WINDOW.with(|w| HWND(w.get().expect("window") as *mut core::ffi::c_void))
    }

    // ---------------------------------------------------------------- buffers

    fn words(p: *mut u8, i: usize) -> &'static AtomicU32 {
        unsafe { AtomicU32::from_ptr((p as *mut u32).add(i)) }
    }

    fn write_header(p: *mut u8, role: u32, kind: u32, gen: u32, id: &[u8; 16], cap: u32, plen: u32, state: u32) {
        words(p, 0).store(0x3142_5750, Ordering::Relaxed);
        words(p, 1).store(1 | (64 << 16), Ordering::Relaxed);
        words(p, 2).store(role | (kind << 8), Ordering::Relaxed);
        words(p, 3).store(gen, Ordering::Relaxed);
        for k in 0..4 {
            let w = u32::from_le_bytes([id[4 * k], id[4 * k + 1], id[4 * k + 2], id[4 * k + 3]]);
            words(p, 4 + k).store(w, Ordering::Relaxed);
        }
        words(p, 8).store(cap, Ordering::Relaxed);
        words(p, 9).store(plen, Ordering::Relaxed);
        for k in 11..16 {
            words(p, k).store(0, Ordering::Relaxed);
        }
        words(p, 10).store(state, Ordering::SeqCst);
    }

    fn zero_fill(p: *mut u8, cap: usize) {
        for i in 0..cap / 8 {
            unsafe { AtomicU64::from_ptr((p as *mut u64).add(i)) }.store(0, Ordering::Relaxed);
        }
        fence(Ordering::SeqCst);
    }

    fn copy_out(p: *mut u8, dst: &mut [u64]) {
        for (i, d) in dst.iter_mut().enumerate() {
            *d = unsafe { AtomicU64::from_ptr((p as *mut u64).add(i)) }.load(Ordering::Relaxed);
        }
    }

    fn new_buffer(env: &ICoreWebView2Environment, cap: u64) -> Result<(ICoreWebView2SharedBuffer, *mut u8, bool), String> {
        unsafe {
            let e12: ICoreWebView2Environment12 = env.cast().map_err(|e| format!("env12: {e}"))?;
            let b = e12.CreateSharedBuffer(cap).map_err(|e| format!("CreateSharedBuffer: {e}"))?;
            let mut p: *mut u8 = std::ptr::null_mut();
            b.Buffer(&mut p).map_err(|e| format!("Buffer: {e}"))?;
            let mut sz = 0u64;
            b.Size(&mut sz).map_err(|e| format!("Size: {e}"))?;
            let aligned = (p as usize) % 64 == 0;
            if sz != cap || p.is_null() {
                return Err(format!("buffer size {sz} != {cap} or null"));
            }
            Ok((b, p, aligned))
        }
    }

    fn post(s: &Surface, b: &ICoreWebView2SharedBuffer, rw: bool, json: &str) -> Result<(), String> {
        let j = HSTRING::from(json);
        unsafe {
            let w17: ICoreWebView2_17 = s.webview.as_ref().ok_or("no webview")?.cast().map_err(|e| format!("ICoreWebView2_17: {e}"))?;
            let access = if rw {
                COREWEBVIEW2_SHARED_BUFFER_ACCESS_READ_WRITE
            } else {
                COREWEBVIEW2_SHARED_BUFFER_ACCESS_READ_ONLY
            };
            w17.PostSharedBufferToScript(b, access, PCWSTR(j.as_ptr()))
                .map_err(|e| format!("PostSharedBufferToScript: {e}"))
        }
    }

    // ---------------------------------------------------------------- runs

    #[derive(Default)]
    struct Row {
        run: u32,
        ok: bool,
        error: String,
        version: String,
        ready_ms: Option<u128>,
        served_delta: u32,
        nav: String,
        posted: bool,
        reply_ready_ms: Option<u128>,
        ab_equal: bool,
        payload_ok: bool,
        released: bool,
        release_ms: Option<u128>,
        aligned: bool,
        exit_ms: Option<u128>,
        exit_kind: String,
        pid_match: bool,
        udf_removed: bool,
        title: String,
        process_failed: String,
        settings_ok: bool,
    }

    fn ceremony(runtime: Option<&str>, udf_root: &std::path::Path, run: u32, first: bool) -> Row {
        let mut row = Row { run, ..Default::default() };
        let mut id = [0u8; 16];
        if let Err(e) = getrandom::fill(&mut id) {
            row.error = format!("getrandom: {e}");
            return row;
        }
        let gen = run + 1;
        let s = match open_surface(runtime, udf_root, &format!("r{run:05}-{}", hex(&id[..4]))) {
            Ok(s) => s,
            Err(e) => {
                row.error = e;
                return row;
            }
        };
        row.version = s.version.clone();
        row.settings_ok = s.settings_ok;
        if first {
            println!("PROBE browser_version={}", s.version);
            println!("PROBE settings_readback ok={} {}", s.settings_ok, s.settings);
        }
        let served0 = SERVED.load(Ordering::SeqCst);
        let t0 = Instant::now();
        if let Err(e) = navigate(&s) {
            row.error = e;
            let r = close_surface(s);
            row.exit_ms = r.0;
            return row;
        }
        let d = s.dcl.clone();
        let got = pump_until(Duration::from_secs(15), || d.get().is_some());
        row.served_delta = SERVED.load(Ordering::SeqCst) - served0;
        row.nav = s.nav_done.borrow().clone().unwrap_or_default();
        if !got {
            row.error = "ReadinessTimeout(no DOMContentLoaded in 15 s)".into();
            row.title = title(&s);
            let r = close_surface(s);
            row.exit_ms = r.0;
            return row;
        }
        row.ready_ms = d.get().map(|(_, t)| t.duration_since(t0).as_millis());

        let res = (|| -> Result<(), String> {
            let (req, rp, a1) = new_buffer(&s.env, 4096)?;
            let (rep, pp, a2) = new_buffer(&s.env, 8192)?;
            row.aligned = a1 && a2;
            zero_fill(rp, 4096);
            zero_fill(pp, 8192);
            write_header(rp, 0, 1, gen, &id, 4096, 32, 2);
            write_header(pp, 1, 1, gen, &id, 8192, 0, 0);
            fence(Ordering::SeqCst);
            post(&s, &req, false, r#"{"role":"request"}"#)?;
            post(&s, &rep, true, r#"{"role":"reply"}"#)?;
            row.posted = true;
            let tp = Instant::now();
            let state = || words(pp, 10).load(Ordering::SeqCst);
            let ready = pump_until(Duration::from_secs(10), || {
                let v = state();
                v == 2 || v == 6
            });
            if !ready {
                row.title = title(&s);
                zero_fill(rp, 4096);
                zero_fill(pp, 8192);
                unsafe {
                    let _ = req.Close();
                    let _ = rep.Close();
                }
                return Err(format!("reply not READY in 10 s (lost event?) state={}", state()));
            }
            row.reply_ready_ms = Some(tp.elapsed().as_millis());
            if words(pp, 10)
                .compare_exchange(2, 3, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return Err("CAS READY->CONSUMING failed".into());
            }
            let mut a = vec![0u64; 8192 / 8];
            let mut b = vec![0u64; 8192 / 8];
            copy_out(pp, &mut a);
            let st1 = state();
            copy_out(pp, &mut b);
            let st2 = state();
            row.ab_equal = a == b && st1 == 3 && st2 == 3;
            let bytes: Vec<u8> = a.iter().flat_map(|w| w.to_le_bytes()).collect();
            let plen = u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]) as usize;
            row.payload_ok = plen == 96
                && (0..96).all(|k| bytes[64 + k] == ((gen as usize * 7 + k) & 255) as u8)
                && bytes[12..16] == gen.to_le_bytes()
                && bytes[16..32] == id;
            words(pp, 10).store(4, Ordering::SeqCst);
            let tr = Instant::now();
            row.released = pump_until(Duration::from_secs(2), || state() == 5);
            row.release_ms = Some(tr.elapsed().as_millis());
            zero_fill(rp, 4096);
            zero_fill(pp, 8192);
            unsafe {
                req.Close().map_err(|e| format!("req Close: {e}"))?;
                rep.Close().map_err(|e| format!("rep Close: {e}"))?;
            }
            Ok(())
        })();
        if let Err(e) = res {
            row.error = e;
        }
        if row.title.is_empty() {
            row.title = title(&s);
        }
        row.process_failed = s.process_failed.borrow().join(";");
        let (lat, kind, pidm, removed) = close_surface(s);
        row.exit_ms = lat;
        row.exit_kind = kind;
        row.pid_match = pidm;
        row.udf_removed = removed;
        row.ok = row.error.is_empty()
            && row.served_delta == 1
            && row.ab_equal
            && row.payload_ok
            && row.released
            && row.exit_ms.is_some_and(|m| m <= 5000);
        row
    }

    fn stress(runtime: Option<&str>, udf_root: &std::path::Path, n: u32) -> String {
        let s = match open_surface(runtime, udf_root, "stress") {
            Ok(s) => s,
            Err(e) => return format!("error={e}"),
        };
        if let Err(e) = navigate(&s) {
            return format!("error={e}");
        }
        let d = s.dcl.clone();
        if !pump_until(Duration::from_secs(15), || d.get().is_some()) {
            return "error=no DOMContentLoaded".into();
        }
        let (b, p, _) = match new_buffer(&s.env, 4096) {
            Ok(x) => x,
            Err(e) => return format!("error={e}"),
        };
        zero_fill(p, 4096);
        let base = p as usize;
        let host = std::thread::spawn(move || -> Result<(u64, u128), String> {
            let a = |i: usize| unsafe { AtomicI32::from_ptr((base as *mut i32).add(i)) };
            let t0 = Instant::now();
            let mut mism = 0u64;
            for i in 0..=n as usize {
                let want = (2 * i) as i32;
                let mut spins = 0u64;
                while a(0).load(Ordering::SeqCst) != want {
                    spins += 1;
                    if spins % (1 << 20) == 0 && t0.elapsed() > Duration::from_secs(900) {
                        return Err(format!("host timeout at {i}"));
                    }
                    std::hint::spin_loop();
                }
                if i > 0 {
                    let e = (((i - 1) as i32) ^ 0x5a5a_5a5a) ^ 0x0f0f_0f0f;
                    if a(4).load(Ordering::Relaxed) != e || a(5).load(Ordering::Relaxed) != e {
                        mism += 1;
                    }
                }
                if i == n as usize {
                    break;
                }
                let v = (i as i32) ^ 0x5a5a_5a5a;
                a(1).store(v, Ordering::Relaxed);
                a(2).store(v, Ordering::Relaxed);
                a(0).store(want + 1, Ordering::SeqCst);
            }
            Ok((mism, t0.elapsed().as_millis()))
        });
        let posted = post(&s, &b, true, &format!(r#"{{"role":"stress","n":{n}}}"#));
        let mut t = String::new();
        if posted.is_ok() {
            pump_until(Duration::from_secs(900), || {
                t = title(&s);
                t.starts_with("STRESS:") || t.starts_with("ERR:")
            });
        }
        let host_res = if posted.is_ok() && t.starts_with("STRESS:") {
            host.join().map_err(|_| "join".to_string()).and_then(|r| r)
        } else {
            Err("host thread abandoned".into())
        };
        unsafe {
            let _ = b.Close();
        }
        let out = format!("post={posted:?} page_title={t} host={host_res:?}");
        let _ = close_surface(s);
        out
    }

    pub fn main() -> i32 {
        let runtime = std::env::var("PROBE_RUNTIME").ok().filter(|s| s != "evergreen");
        let runs: u32 = std::env::var("PROBE_RUNS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
        let handoffs: u32 = std::env::var("PROBE_HANDOFFS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        let csv = std::env::var("PROBE_CSV").unwrap_or_else(|_| "probe.csv".into());
        let udf_root = std::path::PathBuf::from(
            std::env::var("PROBE_UDF_ROOT").unwrap_or_else(|_| std::env::temp_dir().join("wv2udf").display().to_string()),
        );
        println!("PROBE runtime={runtime:?} runs={runs} handoffs={handoffs} udf_root={}", udf_root.display());

        unsafe {
            let avail = {
                let mut p = PWSTR::null();
                let f = runtime.as_deref().map(HSTRING::from);
                let r = GetAvailableCoreWebView2BrowserVersionString(
                    f.as_ref().map_or(PCWSTR::null(), |h| PCWSTR(h.as_ptr())),
                    &mut p,
                );
                match r {
                    Ok(()) if !p.is_null() => take_str(p),
                    Ok(()) => "none".into(),
                    Err(e) => format!("error {e}"),
                }
            };
            println!("PROBE available_browser_version={avail}");
            let dpi = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            println!("PROBE dpi_awareness_v2={dpi:?}");
            if let Err(e) = CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok() {
                println!("PROBE coinit_error={e}");
                return 2;
            }
        }
        let mut rnd = [0u8; 32];
        println!("PROBE getrandom_fill={:?}", getrandom::fill(&mut rnd).map(|()| hex(&rnd[..4])));
        println!("PROBE csp=\"{}\"", csp());
        println!("PROBE owner_response_sha256={} len={}", hex(&sha256(owner_response())), owner_response().len());
        if let Err(e) = start_listener() {
            println!("PROBE listener_error={e}");
            return 3;
        }
        match create_window() {
            Ok(h) => set_window(h),
            Err(e) => {
                println!("PROBE window_error={e}");
                return 4;
            }
        }
        let _ = window();

        if handoffs > 0 {
            println!("PROBE G2_stress n={handoffs} {}", stress(runtime.as_deref(), &udf_root, handoffs));
        }

        let mut f = String::from("run,ok,error,version,ready_ms,served_delta,nav,posted,reply_ready_ms,ab_equal,payload_ok,released,release_ms,aligned,exit_ms,exit_kind,pid_match,udf_removed,settings_ok,process_failed,title\n");
        let mut ok = 0u32;
        let mut consecutive_fail = 0u32;
        let mut exits: Vec<u128> = Vec::new();
        let mut lost = 0u32;
        let mut ready_timeouts = 0u32;
        let mut not_served_once = 0u32;
        let t_all = Instant::now();
        for run in 0..runs {
            let r = ceremony(runtime.as_deref(), &udf_root, run, run == 0);
            if r.ok {
                ok += 1;
                consecutive_fail = 0;
            } else {
                consecutive_fail += 1;
                println!("PROBE run_fail run={} error={} served_delta={} nav={} title={} pf={}", r.run, r.error, r.served_delta, r.nav, r.title, r.process_failed);
            }
            if r.error.contains("lost event") {
                lost += 1;
            }
            if r.error.contains("ReadinessTimeout") {
                ready_timeouts += 1;
            }
            if r.served_delta != 1 {
                not_served_once += 1;
            }
            if let Some(m) = r.exit_ms {
                exits.push(m);
            }
            let o = |v: Option<u128>| v.map_or(String::new(), |x| x.to_string());
            let _ = writeln!(
                f,
                "{},{},\"{}\",{},{},{},\"{}\",{},{},{},{},{},{},{},{},{},{},{},{},\"{}\",\"{}\"",
                r.run, r.ok, r.error.replace('"', "'"), r.version, o(r.ready_ms), r.served_delta,
                r.nav, r.posted, o(r.reply_ready_ms), r.ab_equal, r.payload_ok, r.released,
                o(r.release_ms), r.aligned, o(r.exit_ms), r.exit_kind, r.pid_match, r.udf_removed,
                r.settings_ok, r.process_failed, r.title.replace('"', "'")
            );
            if (run + 1) % 50 == 0 {
                println!("PROBE progress run={} ok={} elapsed_s={}", run + 1, ok, t_all.elapsed().as_secs());
                let _ = std::fs::write(&csv, &f);
            }
            if consecutive_fail >= 5 && ok == 0 {
                println!("PROBE abort=five-consecutive-failures-with-no-success");
                break;
            }
        }
        let _ = std::fs::write(&csv, &f);
        exits.sort_unstable();
        let pct = |p: f64| -> String {
            if exits.is_empty() {
                return "-".into();
            }
            let i = ((exits.len() as f64 - 1.0) * p).round() as usize;
            exits[i].to_string()
        };
        let over5 = exits.iter().filter(|&&m| m > 5000).count();
        println!(
            "PROBE summary runs={runs} ok={ok} lost_events={lost} readiness_timeouts={ready_timeouts} not_served_exactly_once={not_served_once} exit_observed={} exit_over_5s={over5} exit_ms_p50={} exit_ms_p99={} exit_ms_max={} elapsed_s={}",
            exits.len(), pct(0.5), pct(0.99), exits.last().map_or("-".into(), |m| m.to_string()), t_all.elapsed().as_secs()
        );
        println!(
            "PROBE listener served={} conns_v4={} conns_v6={} max_active={} preconnect_closed_by_1s_timeout={} eof_without_bytes={} header_timeouts={} too_many_headers={} max_headers={} not_admitted={} non_owner_requests={}",
            SERVED.load(Ordering::SeqCst), CONNS_V4.load(Ordering::SeqCst), CONNS_V6.load(Ordering::SeqCst),
            MAX_ACTIVE.load(Ordering::SeqCst), PRECONNECT_TIMEOUT.load(Ordering::SeqCst), EOF_NO_BYTES.load(Ordering::SeqCst),
            HEADER_TIMEOUT.load(Ordering::SeqCst), TOO_MANY_HEADERS.load(Ordering::SeqCst), MAX_HEADERS.load(Ordering::SeqCst),
            BAD_ADMISSION.load(Ordering::SeqCst), NON_OWNER.load(Ordering::SeqCst)
        );
        println!("PROBE first_owner_request={}", FIRST_HEADERS.get().map_or("-", |s| s.as_str()));
        if let Ok(v) = ODD.lock() {
            for o in v.iter() {
                println!("PROBE odd {o}");
            }
        }
        0
    }
}
