#![cfg(windows)]

use std::io;
use std::net::TcpListener;
use std::os::windows::io::{FromRawSocket, OwnedSocket, RawSocket};
use std::sync::OnceLock;

use windows::Win32::Networking::WinSock::{
    bind, listen, setsockopt, WSAGetLastError, WSASocketW, WSAStartup, ADDRESS_FAMILY, AF_INET,
    AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, IPPROTO_IPV6, IPPROTO_TCP, IPV6_V6ONLY,
    SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET, SOCK_STREAM, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
    WSADATA, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
};

// The socket factory serves process-lifetime listeners. Keep exactly one WSA
// initialization for that lifetime; cleaning it while std-owned listeners still
// exist could invalidate unrelated live sockets. Windows reclaims it on exit.
static STARTED: OnceLock<Result<(), i32>> = OnceLock::new();

fn initialize() -> io::Result<()> {
    let initialized = STARTED.get_or_init(|| {
        let mut data = WSADATA::default();
        // SAFETY: request Winsock2.2 with a writable initialized WSADATA whose
        // lifetime spans the call. OnceLock serializes the single initialization.
        let code = unsafe { WSAStartup(0x0202, &raw mut data) };
        if code == 0 {
            Ok(())
        } else {
            Err(code)
        }
    });
    initialized.map_err(io::Error::from_raw_os_error)
}

struct NativeSocket {
    raw: SOCKET,
    owned: OwnedSocket,
}

fn open(family: ADDRESS_FAMILY) -> io::Result<NativeSocket> {
    initialize()?;
    // SAFETY: fixed TCP stream parameters and a supported family; no protocol
    // info pointer, no handle inheritance and no retained caller memory.
    let raw = unsafe {
        WSASocketW(
            i32::from(family.0),
            SOCK_STREAM.0,
            IPPROTO_TCP.0,
            None,
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    }
    .map_err(|error| io::Error::from_raw_os_error(error.code().0 & 0xffff))?;
    // SAFETY: WSASocketW returned a new owned socket. Ownership transfers once
    // to OwnedSocket; all error paths then close it through standard-library RAII.
    let owned = unsafe { OwnedSocket::from_raw_socket(raw.0 as RawSocket) };
    Ok(NativeSocket { raw, owned })
}

fn failed() -> io::Error {
    // SAFETY: reads only this thread's Winsock error immediately after failure.
    let error = unsafe { WSAGetLastError() };
    io::Error::from_raw_os_error(error.0)
}

fn set_option(socket: &NativeSocket, level: i32, option: i32) -> io::Result<()> {
    // SAFETY: the owned socket stays live and the initialized four-byte BOOL
    // slice is borrowed only for this synchronous setsockopt call.
    let status = unsafe { setsockopt(socket.raw, level, option, Some(&1_i32.to_ne_bytes())) };
    if status == 0 {
        Ok(())
    } else {
        Err(failed())
    }
}

fn listening(socket: NativeSocket) -> io::Result<TcpListener> {
    // SAFETY: a live, exclusively bound TCP socket; the fixed backlog is four.
    let status = unsafe { listen(socket.raw, 4) };
    if status == 0 {
        Ok(TcpListener::from(socket.owned))
    } else {
        Err(failed())
    }
}

pub(super) fn bind_v4(port: u16) -> io::Result<TcpListener> {
    let socket = open(AF_INET)?;
    set_option(&socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE)?;
    bind_v4_socket(socket, port)
}

fn bind_v4_socket(socket: NativeSocket, port: u16) -> io::Result<TcpListener> {
    let address = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
        },
        ..Default::default()
    };
    // SAFETY: the initialized repr(C) SOCKADDR_IN is sixteen bytes and outlives
    // the synchronous call; the socket is live and no pointer is retained.
    let status = unsafe {
        bind(
            socket.raw,
            std::ptr::from_ref(&address).cast::<SOCKADDR>(),
            16,
        )
    };
    if status == 0 {
        listening(socket)
    } else {
        Err(failed())
    }
}

pub(super) fn bind_v6(port: u16) -> io::Result<TcpListener> {
    let socket = open(AF_INET6)?;
    set_option(&socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE)?;
    set_option(&socket, IPPROTO_IPV6.0, IPV6_V6ONLY)?;
    let address = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: port.to_be(),
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            },
        },
        ..Default::default()
    };
    // SAFETY: the initialized repr(C) SOCKADDR_IN6 is twenty-eight bytes and
    // outlives the call; scope and flow are zero for the loopback address.
    let status = unsafe {
        bind(
            socket.raw,
            std::ptr::from_ref(&address).cast::<SOCKADDR>(),
            28,
        )
    };
    if status == 0 {
        listening(socket)
    } else {
        Err(failed())
    }
}

#[cfg(test)]
pub(super) fn competing_reuse(port: u16) -> io::Result<TcpListener> {
    use windows::Win32::Networking::WinSock::SO_REUSEADDR;
    let socket = open(AF_INET)?;
    set_option(&socket, SOL_SOCKET, SO_REUSEADDR)?;
    bind_v4_socket(socket, port)
}
