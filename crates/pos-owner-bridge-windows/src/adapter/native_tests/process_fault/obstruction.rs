#![cfg(windows)]
#![forbid(unsafe_code)]

use crate::{
    BoolProperty, BufferSlot, EnvironmentOptions, EnvironmentSnapshot, EventSink, Failure,
    NativeError, NativeFactory, NativeOperations, NativePulse, NativeResult, NativeText, Operation,
    StaPump, WindowSnapshot,
};
use pos_owner_bridge::ReplyImage;
use pos_owner_bridge_codec::CeremonyKind;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[cfg(test)]
mod tests;

pub(super) struct ObstructionFactory<F> {
    inner: F,
    expected: PathBuf,
}

impl<F> ObstructionFactory<F> {
    pub(super) const fn new(inner: F, expected: PathBuf) -> Self {
        Self { inner, expected }
    }
}

impl<F: NativeFactory> StaPump for ObstructionFactory<F> {
    fn next(&self) -> NativeResult<NativePulse> {
        self.inner.next()
    }
    fn stop(&mut self) -> NativeResult<()> {
        self.inner.stop()
    }
}

impl<F: NativeFactory> NativeFactory for ObstructionFactory<F> {
    fn session(&self) -> NativeResult<Box<dyn NativeOperations>> {
        Ok(Box::new(ObstructionSession {
            inner: self.inner.session()?,
            expected: self.expected.clone(),
        }))
    }
}

struct ObstructionSession {
    inner: Box<dyn NativeOperations>,
    expected: PathBuf,
}

impl NativeOperations for ObstructionSession {
    fn environment_creation_completion(&self) -> Option<bool> {
        self.inner.environment_creation_completion()
    }
    fn create_window(
        &mut self,
        owner: Option<u64>,
        logical_width: u32,
        logical_height: u32,
    ) -> NativeResult<()> {
        self.inner
            .create_window(owner, logical_width, logical_height)
    }
    fn window(&self) -> NativeResult<WindowSnapshot> {
        self.inner.window()
    }
    fn resize_window(&self, logical_width: u32, logical_height: u32, dpi: u32) -> NativeResult<()> {
        self.inner.resize_window(logical_width, logical_height, dpi)
    }
    fn show_window(&self) -> NativeResult<()> {
        self.inner.show_window()
    }
    fn fit_controller(&self) -> NativeResult<()> {
        self.inner.fit_controller()
    }
    fn focus_controller(&self) -> NativeResult<()> {
        self.inner.focus_controller()
    }
    fn create_environment(
        &mut self,
        runtime: &Path,
        folder: &Path,
        options: EnvironmentOptions,
        sink: Rc<dyn EventSink>,
    ) -> NativeResult<()> {
        let invalid = || NativeError {
            operation: Operation::Environment,
            failure: Failure::InvalidAction,
        };
        if folder != self.expected.as_path() || !folder.is_absolute() {
            return Err(invalid());
        }
        let metadata = std::fs::symlink_metadata(folder).map_err(|_| invalid())?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
        let target = folder.join("EBWebView");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|_| invalid())?;
        let file_metadata = file.metadata().map_err(|_| invalid())?;
        if !file_metadata.is_file()
            || file_metadata.len() != 0
            || file_metadata.file_attributes() & 0x400 != 0
        {
            return Err(invalid());
        }
        drop(file);
        self.inner
            .create_environment(runtime, folder, options, sink)
    }
    fn environment_completion(&mut self) -> Option<NativeResult<()>> {
        self.inner.environment_completion()
    }
    fn environment(&self) -> NativeResult<EnvironmentSnapshot> {
        self.inner.environment()
    }
    fn create_controller(&mut self) -> NativeResult<()> {
        self.inner.create_controller()
    }
    fn controller_completion(&mut self) -> Option<NativeResult<()>> {
        self.inner.controller_completion()
    }
    fn has_controller(&self) -> NativeResult<bool> {
        self.inner.has_controller()
    }
    fn browser_pid(&self) -> NativeResult<u32> {
        self.inner.browser_pid()
    }
    fn require_shared_interfaces(&mut self) -> NativeResult<()> {
        self.inner.require_shared_interfaces()
    }
    fn subscribe_view(&mut self, sink: Rc<dyn EventSink>) -> NativeResult<()> {
        self.inner.subscribe_view(sink)
    }
    fn set_bool(&self, property: BoolProperty, value: bool) -> NativeResult<()> {
        self.inner.set_bool(property, value)
    }
    fn get_bool(&self, property: BoolProperty) -> NativeResult<bool> {
        self.inner.get_bool(property)
    }
    fn navigate_owner(&self) -> NativeResult<()> {
        self.inner.navigate_owner()
    }
    fn source(&self) -> NativeResult<NativeText> {
        self.inner.source()
    }
    fn create_buffers(
        &mut self,
        kind: CeremonyKind,
        request: &[u8],
        reply_header: &[u8; 64],
    ) -> NativeResult<()> {
        self.inner.create_buffers(kind, request, reply_header)
    }
    fn post(&self, slot: BufferSlot) -> NativeResult<()> {
        self.inner.post(slot)
    }
    fn load_state(&self) -> NativeResult<u32> {
        self.inner.load_state()
    }
    fn compare_exchange(&self, current: u32, new: u32) -> NativeResult<bool> {
        self.inner.compare_exchange(current, new)
    }
    fn copy_reply(&self, out: &mut ReplyImage) -> NativeResult<()> {
        self.inner.copy_reply(out)
    }
    fn close_buffers(&mut self) -> NativeResult<()> {
        self.inner.close_buffers()
    }
    fn buffer_close_uncertain(&self) -> bool {
        self.inner.buffer_close_uncertain()
    }
    fn unsubscribe_view(&mut self) -> NativeResult<()> {
        self.inner.unsubscribe_view()
    }
    fn close_controller(&mut self) -> NativeResult<()> {
        self.inner.close_controller()
    }
    fn unsubscribe_exit(&mut self) -> NativeResult<()> {
        self.inner.unsubscribe_exit()
    }
    fn drop_environment(&mut self) -> NativeResult<()> {
        self.inner.drop_environment()
    }
    fn destroy_window(&mut self) -> NativeResult<()> {
        self.inner.destroy_window()
    }
    fn pending(&self) -> bool {
        self.inner.pending()
    }
}
