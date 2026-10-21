//! Atomic close-on-exec receive path for the one mountfsd connection.
//!
//! zlink's own Unix stream receives `SCM_RIGHTS` without `MSG_CMSG_CLOEXEC`
//! and drops the returned message flags. This socket replaces it: every
//! `recvmsg` requests `MSG_CMSG_CLOEXEC`, rejects ancillary truncation and any
//! non-descriptor control message, verifies `FD_CLOEXEC` on each received
//! descriptor, and accepts descriptors in at most one read. It also bounds
//! the reply to one NUL-terminated message and captures those exact bytes for
//! the closed reply parser. Rejected reads drop their `OwnedFd`s at once;
//! descriptors already handed to zlink are dropped with the connection.

use std::{
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use rustix::{
    io::{fcntl_getfd, FdFlags},
    net::{
        recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
    },
};
use tokio::{
    io::Interest,
    net::{
        unix::{OwnedReadHalf, OwnedWriteHalf},
        UnixStream,
    },
};
use zlink::connection::{
    socket::{ReadHalf, ReadResult, Socket, WriteHalf},
    PassedCredentials,
};

use super::ImageActivationError;

/// Largest accepted reply message, excluding its NUL terminator.
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// A Tokio Unix stream whose read half seals descriptors at receipt.
#[derive(Debug)]
pub(super) struct SealedUnixSocket(UnixStream);

impl SealedUnixSocket {
    pub(super) const fn new(stream: UnixStream) -> Self {
        Self(stream)
    }
}

impl Socket for SealedUnixSocket {
    type ReadHalf = SealedReadHalf;
    type WriteHalf = SealedWriteHalf;

    const CAN_TRANSFER_FDS: bool = true;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        let (read, write) = self.0.into_split();
        (
            SealedReadHalf {
                stream: read,
                frame: Frame::default(),
            },
            SealedWriteHalf(write),
        )
    }
}

/// The read half: one bounded reply frame and its sealed descriptors.
#[derive(Debug)]
pub(super) struct SealedReadHalf {
    stream: OwnedReadHalf,
    frame: Frame,
}

impl SealedReadHalf {
    /// The exact reply bytes, or why no complete reply was accepted.
    pub(super) fn frame(&self) -> Result<&[u8], ImageActivationError> {
        match self.frame.state {
            FrameState::Complete => Ok(&self.frame.message),
            FrameState::Defective => Err(ImageActivationError::MalformedReply),
            FrameState::Open => Err(ImageActivationError::Transport),
        }
    }
}

impl ReadHalf for SealedReadHalf {
    async fn read(&mut self, buf: &mut [u8]) -> zlink::Result<ReadResult> {
        let Self { stream, frame } = self;
        let socket: &UnixStream = stream.as_ref();
        socket
            .async_io(Interest::READABLE, || receive(socket, buf, frame))
            .await
            .map_err(zlink::Error::from)
    }
}

/// The write half: each zlink message leaves in one `sendmsg`.
#[derive(Debug)]
pub(super) struct SealedWriteHalf(OwnedWriteHalf);

impl WriteHalf for SealedWriteHalf {
    fn write(
        &mut self,
        buf: &[u8],
        fds: &[impl AsFd],
        _credentials: Option<&PassedCredentials>,
    ) -> impl Future<Output = zlink::Result<()>> {
        // Borrow the descriptors up front so the future holds only Send data.
        let descriptors: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
        let socket: &UnixStream = self.0.as_ref();
        async move {
            socket
                .async_io(Interest::WRITABLE, || send(socket, buf, &descriptors))
                .await
                .and_then(|sent| whole_message(sent, buf.len()))
                .map_err(zlink::Error::from)
        }
    }
}

#[derive(Debug, Default)]
struct Frame {
    message: Vec<u8>,
    descriptors_received: bool,
    state: FrameState,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FrameState {
    #[default]
    Open,
    Complete,
    Defective,
}

impl Frame {
    /// Accept one `recvmsg` result into the frame, or mark the frame defective.
    fn accept(
        &mut self,
        bytes: &[u8],
        flags: ReturnFlags,
        unexpected_control: bool,
        descriptors: Vec<OwnedFd>,
    ) -> io::Result<ReadResult> {
        let terminator = bytes.iter().position(|byte| *byte == 0);
        let body = terminator.map_or(bytes, |end| &bytes[..end]);
        let defective = flags.contains(ReturnFlags::CTRUNC)
            || unexpected_control
            || (self.descriptors_received && !descriptors.is_empty())
            || !descriptors.iter().all(is_sealed)
            || terminator.is_some_and(|end| end + 1 != bytes.len())
            || self.message.len() + body.len() > MAX_REPLY_BYTES;
        if defective {
            self.state = FrameState::Defective;
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.message.extend_from_slice(body);
        self.descriptors_received = self.descriptors_received || !descriptors.is_empty();
        if terminator.is_some() {
            self.state = FrameState::Complete;
        }
        Ok(ReadResult::new(bytes.len()).set_fds(descriptors))
    }
}

fn receive(socket: &UnixStream, buffer: &mut [u8], frame: &mut Frame) -> io::Result<ReadResult> {
    // Space for one credentials message plus a small descriptor batch, so an
    // unexpected credentials message is decoded rather than only truncated.
    // Batches beyond about ten descriptors set MSG_CTRUNC; any received count
    // other than one is rejected by the reply parser.
    let mut space =
        [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1), ScmCredentials(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut segments = [IoSliceMut::new(buffer)];
    recvmsg(socket, &mut segments, &mut control, RecvFlags::CMSG_CLOEXEC)
        .map_err(io::Error::from)
        .and_then(|received| {
            let (descriptors, unexpected_control) = drain(&mut control);
            frame.accept(
                &buffer[..received.bytes],
                received.flags,
                unexpected_control,
                descriptors,
            )
        })
}

/// Take every received descriptor and report any other control message.
fn drain(control: &mut RecvAncillaryBuffer<'_>) -> (Vec<OwnedFd>, bool) {
    let mut descriptors = Vec::new();
    let mut unexpected = false;
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            descriptors.extend(received);
        } else {
            unexpected = true;
        }
    }
    (descriptors, unexpected)
}

fn is_sealed(descriptor: &OwnedFd) -> bool {
    fcntl_getfd(descriptor).is_ok_and(|flags| flags.contains(FdFlags::CLOEXEC))
}

fn send(socket: &UnixStream, message: &[u8], descriptors: &[BorrowedFd<'_>]) -> io::Result<usize> {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if control.push(SendAncillaryMessage::ScmRights(descriptors)) {
        sendmsg(
            socket,
            &[IoSlice::new(message)],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .map_err(io::Error::from)
    } else {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

/// One message per `sendmsg`: a short write is a transport failure.
fn whole_message(sent: usize, expected: usize) -> io::Result<()> {
    if sent == expected {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::WriteZero))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{error::Error, fs::File, os::unix::net::UnixStream as StdUnixStream};

    use rustix::io::dup;

    use super::*;

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    fn sealed_file() -> Result<OwnedFd, Box<dyn Error + Send + Sync>> {
        Ok(OwnedFd::from(tempfile::tempfile()?))
    }

    fn unsealed_file() -> Result<OwnedFd, Box<dyn Error + Send + Sync>> {
        let file = File::from(sealed_file()?);
        Ok(dup(&file)?)
    }

    #[test]
    fn sealing_check_reads_the_descriptor_flag() -> TestResult {
        assert!(is_sealed(&sealed_file()?));
        assert!(!is_sealed(&unsealed_file()?));
        Ok(())
    }

    #[test]
    fn an_unsealed_descriptor_makes_the_frame_defective() -> TestResult {
        let mut frame = Frame::default();
        let read = frame.accept(b"{}\0", ReturnFlags::empty(), false, vec![unsealed_file()?]);
        assert_eq!(
            read.err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        assert_eq!(frame.state, FrameState::Defective);
        Ok(())
    }

    #[test]
    fn ancillary_truncation_makes_the_frame_defective() -> TestResult {
        let mut frame = Frame::default();
        let read = frame.accept(b"{}\0", ReturnFlags::CTRUNC, false, vec![sealed_file()?]);
        assert!(read.is_err());
        assert_eq!(frame.state, FrameState::Defective);
        Ok(())
    }

    #[test]
    fn a_message_of_exactly_the_bound_is_accepted() -> TestResult {
        let mut frame = Frame::default();
        let mut message = vec![b' '; MAX_REPLY_BYTES];
        message.push(0);
        let read = frame.accept(&message, ReturnFlags::empty(), false, vec![sealed_file()?])?;
        assert_eq!(read.bytes_read(), MAX_REPLY_BYTES + 1);
        assert_eq!(read.fds().len(), 1);
        assert_eq!(frame.state, FrameState::Complete);
        assert_eq!(frame.message.len(), MAX_REPLY_BYTES);
        Ok(())
    }

    #[test]
    fn one_byte_over_the_bound_is_defective() {
        let mut frame = Frame::default();
        let body = vec![b' '; MAX_REPLY_BYTES];
        assert!(frame
            .accept(&body, ReturnFlags::empty(), false, Vec::new())
            .is_ok());
        assert_eq!(frame.state, FrameState::Open);
        assert!(frame
            .accept(b" \0", ReturnFlags::empty(), false, Vec::new())
            .is_err());
        assert_eq!(frame.state, FrameState::Defective);
    }

    #[test]
    fn a_short_write_is_a_transport_failure() {
        assert!(whole_message(7, 7).is_ok());
        assert_eq!(
            whole_message(6, 7).err().map(|error| error.kind()),
            Some(io::ErrorKind::WriteZero)
        );
    }

    #[tokio::test]
    async fn sending_more_descriptors_than_the_control_space_holds_is_refused() -> TestResult {
        let (local, peer) = StdUnixStream::pair()?;
        local.set_nonblocking(true)?;
        peer.set_nonblocking(true)?;
        let socket = UnixStream::from_std(local)?;
        // Five descriptors exceed the one-descriptor space even when the stack
        // buffer happens to be fully aligned.
        let files = (0..5)
            .map(|_| sealed_file())
            .collect::<Result<Vec<_>, _>>()?;
        let borrowed: Vec<BorrowedFd<'_>> = files.iter().map(AsFd::as_fd).collect();
        assert_eq!(
            send(&socket, b"x", &borrowed)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            std::io::Read::read(&mut &peer, &mut byte)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        Ok(())
    }
}
