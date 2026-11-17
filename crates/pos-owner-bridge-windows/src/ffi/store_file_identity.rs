#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]

use std::fs::File;
use std::os::windows::io::AsRawHandle;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    SetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL, SE_DACL_AUTO_INHERITED,
    SE_DACL_AUTO_INHERIT_REQ,
};
use windows::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};

use super::directory::{current_sid, LocalMemory};

fn descriptor_text(descriptor: &LocalMemory) -> Result<String, ()> {
    // Normalize automatic-inheritance bookkeeping on this allocated copy only;
    // keep DACL protection, every ACE flag and all permissions unchanged.
    // SAFETY: the Windows-allocated descriptor is writable and uniquely owned.
    unsafe {
        SetSecurityDescriptorControl(
            PSECURITY_DESCRIPTOR(descriptor.0 .0),
            SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ,
            SECURITY_DESCRIPTOR_CONTROL(0),
        )
    }
    .map_err(|_| ())?;
    let mut output = PWSTR::null();
    // SAFETY: the descriptor is live; the initialized output receives a newly
    // allocated NUL-terminated string, which is freed after the copy.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(descriptor.0 .0),
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut output,
            None,
        )
    }
    .map_err(|_| ())?;
    let _allocation = LocalMemory(HLOCAL(output.0.cast()));
    // SAFETY: the successful conversion returned an allocated terminated string
    // that remains live until this Rust-owned copy has been constructed.
    unsafe { output.to_string() }.map_err(|_| ())
}

fn expected(sid: &str, protected: bool, inherited: bool) -> Result<String, ()> {
    let protection = if protected { "P" } else { "" };
    let inheritance = if inherited { "ID" } else { "" };
    let text: Vec<u16> = format!("O:{sid}D:{protection}(A;{inheritance};FA;;;{sid})")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut output = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the SID-derived terminated SDDL and initialized output remain
    // live during the call; the successful allocation has exactly one owner.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &raw mut output,
            None,
        )
    }
    .map_err(|_| ())?;
    descriptor_text(&LocalMemory(HLOCAL(output.0)))
}

impl crate::Native {
    pub(crate) fn require_private_file(file: &File) -> Result<(), ()> {
        private_file_check(file).map_err(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn diagnose_private_file(file: &File) -> Result<(), String> {
        match private_file_check(file) {
            Ok(()) => Ok(()),
            Err("file owner or DACL mismatch") => {
                let (actual, sid) = observe_file_descriptor(file).map_err(str::to_owned)?;
                let mut variants = Vec::new();
                for protected in [false, true] {
                    for inherited in [false, true] {
                        variants.push(redact_sids(
                            &expected(&sid, protected, inherited)
                                .map_err(|()| "expected file descriptor formatting")?,
                            &sid,
                        ));
                    }
                }
                Err(format!(
                    "file owner or DACL mismatch: actual={} expected={variants:?}",
                    redact_sids(&actual, &sid)
                ))
            }
            Err(error) => Err(error.to_owned()),
        }
    }

    pub(crate) fn file_link_count(file: &File) -> Result<u32, ()> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the borrowed File keeps its handle live, and the initialized
        // output is uniquely writable for the duration of this synchronous query.
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information) }
            .map_err(|_| ())?;
        Ok(information.nNumberOfLinks)
    }
}

fn observe_file_descriptor(file: &File) -> Result<(String, String), &'static str> {
    let mut output = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the borrowed File keeps its handle live throughout this query;
    // output is uniquely writable and its successful allocation is freed once.
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&raw mut output),
        )
    }
    .ok()
    .map_err(|_| "file security query")?;
    let actual = descriptor_text(&LocalMemory(HLOCAL(output.0)))
        .map_err(|()| "file descriptor formatting")?;
    let sid = current_sid().map_err(|()| "current SID query")?;
    Ok((actual, sid))
}

fn private_file_check(file: &File) -> Result<(), &'static str> {
    let (actual, sid) = observe_file_descriptor(file)?;
    for protected in [false, true] {
        for inherited in [false, true] {
            if actual
                == expected(&sid, protected, inherited)
                    .map_err(|()| "expected file descriptor formatting")?
            {
                return Ok(());
            }
        }
    }
    Err("file owner or DACL mismatch")
}

#[cfg(test)]
fn redact_sids(text: &str, current_sid: &str) -> String {
    let mut remaining = text;
    let mut result = String::new();
    while let Some(start) = remaining.find("S-") {
        result.push_str(&remaining[..start]);
        let sid = &remaining[start + 2..];
        let end = sid
            .find(|character: char| !character.is_ascii_digit() && character != '-')
            .unwrap_or(sid.len());
        let full_sid = &remaining[start..start + 2 + end];
        result.push_str(if full_sid == current_sid {
            "<CURRENT>"
        } else {
            "<OTHER>"
        });
        remaining = &sid[end..];
    }
    result.push_str(remaining);
    result
}

#[cfg(test)]
mod tests {
    use super::redact_sids;

    #[test]
    fn diagnostic_redaction_preserves_context_without_exposing_sids() {
        let current = "S-1-5-21-123";
        let cases = [
            ("owner=S-1-5-21-123", "owner=<CURRENT>"),
            ("owner=S-1-5-21-456", "owner=<OTHER>"),
            (
                "O:S-1-5-21-123 D:(A;;FA;;;S-1-5-21-456)",
                "O:<CURRENT> D:(A;;FA;;;<OTHER>)",
            ),
            ("no identities here", "no identities here"),
            ("[S-1-5-21-123], S-1-5-21-456!", "[<CURRENT>], <OTHER>!"),
            ("end:S-1-5-21-456", "end:<OTHER>"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_sids(input, current), expected, "{input}");
        }
    }
}
