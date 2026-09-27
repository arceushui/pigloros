//! ADR-087's dependency proof: one generated call transfers descriptors both ways.
//!
//! The peer supplies a regular-file fixture in place of a detached mount. This
//! proves transport identity, not image admission, mount activation, or cleanup.

use std::{error::Error, fs::File, io::Write, os::fd::OwnedFd, time::Duration};

use rustix::fs::{fcntl_getfd, fcntl_setfd, fstat, FdFlags};
use serde_json::{json, Value};
use tokio::net::UnixStream;
use zlink::{tokio::unix::Stream, Connection, Reply};

#[zlink::proxy("io.systemd.MountFileSystem")]
trait MountImageProxy {
    #[zlink(return_fds)]
    async fn mount_image(
        &mut self,
        #[zlink(rename = "imageFileDescriptor")] image_file_descriptor: u32,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<(Result<Value, Value>, Vec<OwnedFd>)>;
}

#[tokio::test]
async fn generated_mount_image_call_transfers_both_descriptor_directions(
) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(5), descriptor_round_trip()).await?
}

async fn descriptor_round_trip() -> Result<(), Box<dyn Error>> {
    let mut image = tempfile::tempfile()?;
    image.write_all(b"held image descriptor")?;
    let mut root = tempfile::tempfile()?;
    root.write_all(b"quarantined reply descriptor")?;
    let expected_image = fstat(&image)?;
    let expected_root = fstat(&root)?;
    let (client_socket, peer_socket) = UnixStream::pair()?;
    let mut client = Connection::new(Stream::try_from(client_socket)?);
    let mut peer = Connection::new(Stream::try_from(peer_socket)?);

    let send = async {
        client
            .mount_image(0, vec![OwnedFd::from(image.try_clone()?)])
            .await
            .map_err(Box::<dyn Error>::from)
    };
    let receive = async {
        let (call, mut image_descriptors) = peer.receive_call::<Value>().await?;
        assert_eq!(
            call.method(),
            &json!({
                "method": "io.systemd.MountFileSystem.MountImage",
                "parameters": {"imageFileDescriptor": 0}
            })
        );
        assert!(!call.oneway());
        assert!(!call.more());
        assert!(!call.upgrade());
        assert_eq!(image_descriptors.len(), 1);
        let received_image = image_descriptors.pop().ok_or("missing image descriptor")?;
        let observed_image = fstat(&received_image)?;
        assert_eq!(observed_image.st_dev, expected_image.st_dev);
        assert_eq!(observed_image.st_ino, expected_image.st_ino);
        assert_eq!(observed_image.st_size, expected_image.st_size);

        peer.send_reply(
            &Reply::new(Some(json!({
                "partitions": [{"designator": "root", "mountFileDescriptor": 0}]
            }))),
            vec![OwnedFd::from(root)],
        )
        .await?;
        Ok::<(), Box<dyn Error>>(())
    };
    let (reply, ()) = tokio::try_join!(send, receive)?;
    let (parameters, mut root_descriptors) = reply;
    assert_eq!(
        parameters.map_err(|_| "unexpected peer error")?,
        json!({"partitions": [{"designator": "root", "mountFileDescriptor": 0}]})
    );
    assert_eq!(root_descriptors.len(), 1);
    let received_root = root_descriptors.pop().ok_or("missing root descriptor")?;
    fcntl_setfd(&received_root, FdFlags::CLOEXEC)?;
    assert!(fcntl_getfd(&received_root)?.contains(FdFlags::CLOEXEC));
    let observed_root = fstat(&received_root)?;
    assert_eq!(observed_root.st_dev, expected_root.st_dev);
    assert_eq!(observed_root.st_ino, expected_root.st_ino);
    assert_eq!(observed_root.st_size, expected_root.st_size);
    // The caller still holds the same image after the transport consumed its duplicate.
    assert_eq!(fstat(&image)?.st_ino, expected_image.st_ino);
    let received_file = File::from(received_root);
    assert_eq!(received_file.metadata()?.len(), 28);
    Ok(())
}
