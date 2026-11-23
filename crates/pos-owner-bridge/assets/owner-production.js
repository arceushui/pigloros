// Let the host observe RECEIVED and cancel before the browser opens native UI.
var STATE_POLL_MS = 20, CREDENTIAL_START_GRACE_MS = 3 * STATE_POLL_MS;

function callCredentialAfterGrace(method, options) {
  return new Promise(function (resolve, reject) {
    var signal = options.signal, timer = 0;
    function aborted() {
      clearTimeout(timer);
      if (signal) { signal.removeEventListener("abort", aborted); }
      reject(new DOMException("Credential operation aborted", "AbortError"));
    }
    if (signal && signal.aborted) { aborted(); return; }
    if (signal) { signal.addEventListener("abort", aborted, { once: true }); }
    timer = setTimeout(function () {
      if (signal) { signal.removeEventListener("abort", aborted); }
      if (signal && signal.aborted) {
        reject(new DOMException("Credential operation aborted", "AbortError"));
        return;
      }
      var call;
      try { call = navigator.credentials[method](options); }
      catch (error) { reject(error); return; }
      Promise.resolve(call).then(resolve, reject);
    }, CREDENTIAL_START_GRACE_MS);
  });
}

ownerProtocol({
  create: function (options) { return callCredentialAfterGrace("create", options); },
  get: function (options) { return callCredentialAfterGrace("get", options); }
}, function () { return window.chrome && window.chrome.webview; });
