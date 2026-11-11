#![cfg(windows)]

use std::cell::Cell;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

use crate::{Failure, NativeError, NativeResult, Operation};
use pos_owner_bridge::ReplyImage;
use pos_owner_bridge_codec::{
    CeremonyKind, ControlRole, CREATE_REPLY_BUFFER_CAPACITY, GET_REPLY_BUFFER_CAPACITY,
    REQUEST_BUFFER_CAPACITY,
};
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2Environment12, ICoreWebView2SharedBuffer, ICoreWebView2_17,
    COREWEBVIEW2_SHARED_BUFFER_ACCESS_READ_ONLY, COREWEBVIEW2_SHARED_BUFFER_ACCESS_READ_WRITE,
};
use windows::core::w;

type Result<T> = NativeResult<T>;
const STATE_CHUNK: usize = 5;

struct Mapping {
    object: ICoreWebView2SharedBuffer,
    base: Option<NonNull<u8>>,
    capacity: usize,
    role: ControlRole,
    close_uncertain: Rc<Cell<bool>>,
}

impl Mapping {
    fn new(
        environment: &ICoreWebView2Environment12,
        capacity: u32,
        role: ControlRole,
        close_uncertain: Rc<Cell<bool>>,
    ) -> Result<Self> {
        // SAFETY: live STA environment and a fixed codec-validated capacity;
        // the returned COM interface uniquely owns this new shared buffer.
        let object = unsafe { environment.CreateSharedBuffer(u64::from(capacity)) }
            .map_err(|_| unavailable())?;
        let observed = observe_mapping(&object, capacity);
        match observed {
            Ok(base) => Ok(Self {
                object,
                base: Some(base),
                capacity: capacity as usize,
                role,
                close_uncertain,
            }),
            Err(error) => {
                // No secret has been written before size/alignment admission.
                if close_object(&object).is_err() {
                    close_uncertain.set(true);
                }
                Err(error)
            }
        }
    }

    fn word64(&self, index: usize) -> Result<&AtomicU64> {
        if index >= self.capacity / 8 || index == STATE_CHUNK {
            return Err(unavailable());
        }
        let base = self.base.ok_or_else(unavailable)?;
        let pointer = base.cast::<u64>().as_ptr().wrapping_add(index);
        // SAFETY: the admitted live COM mapping is 64-byte aligned; the checked
        // eight-byte range is in-bounds and excludes the two 32-bit control
        // words. This borrow cannot outlive self or a mutable close operation.
        Ok(unsafe { AtomicU64::from_ptr(pointer) })
    }

    fn state(&self) -> Result<&AtomicU32> {
        let base = self.base.ok_or_else(unavailable)?;
        // SAFETY: all fixed capacities contain the aligned 32-bit state at40;
        // the live COM mapping outlives this borrow. No 64-bit access overlaps it.
        Ok(unsafe { AtomicU32::from_ptr(base.cast::<u32>().as_ptr().wrapping_add(10)) })
    }

    fn flags(&self) -> Result<&AtomicU32> {
        let base = self.base.ok_or_else(unavailable)?;
        // SAFETY: the aligned zero-flags word at44 is inside every admitted
        // mapping and disjoint from state. No 64-bit access spans either word.
        Ok(unsafe { AtomicU32::from_ptr(base.cast::<u32>().as_ptr().wrapping_add(11)) })
    }

    fn initialize(&self, bytes: &[u8]) -> Result<()> {
        if !valid_aligned_offset(self.capacity, bytes.len()) {
            return Err(unavailable());
        }
        for (index, chunk) in bytes.chunks_exact(8).enumerate() {
            if index == STATE_CHUNK {
                let mut state = [0; 4];
                let mut flags = [0; 4];
                state.copy_from_slice(&chunk[..4]);
                flags.copy_from_slice(&chunk[4..]);
                self.state()?
                    .store(u32::from_le_bytes(state), Ordering::SeqCst);
                self.flags()?
                    .store(u32::from_le_bytes(flags), Ordering::Relaxed);
            } else {
                let mut word = [0; 8];
                word.copy_from_slice(chunk);
                self.word64(index)?
                    .store(u64::from_le_bytes(word), Ordering::Relaxed);
            }
        }
        fence(Ordering::SeqCst);
        Ok(())
    }

    fn zero_from(&self, start: usize) -> Result<()> {
        if !valid_aligned_offset(self.capacity, start) {
            return Err(unavailable());
        }
        for index in start / 8..self.capacity / 8 {
            if index == STATE_CHUNK {
                self.state()?.store(0, Ordering::SeqCst);
                self.flags()?.store(0, Ordering::Relaxed);
            } else {
                self.word64(index)?.store(0, Ordering::Relaxed);
            }
        }
        fence(Ordering::SeqCst);
        Ok(())
    }

    fn copy_to(&self, out: &mut [u8]) -> Result<()> {
        if out.len() != self.capacity {
            return Err(unavailable());
        }
        for (index, chunk) in out.chunks_exact_mut(8).enumerate() {
            if index == STATE_CHUNK {
                // The explicit 32-bit state rule overrides ordinary eight-byte
                // copies. It prevents mixed-width overlap with live state CAS.
                chunk[..4].copy_from_slice(&self.state()?.load(Ordering::SeqCst).to_le_bytes());
                chunk[4..].copy_from_slice(&self.flags()?.load(Ordering::Relaxed).to_le_bytes());
            } else {
                chunk.copy_from_slice(&self.word64(index)?.load(Ordering::Relaxed).to_le_bytes());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn all_zero_from(&self, start: usize) -> Result<bool> {
        // The private close path supplies only its fixed 0/64 offset after
        // mapping capacity/alignment admission; no caller-selected range enters.
        let mut zero = true;
        for index in start / 8..self.capacity / 8 {
            if index == STATE_CHUNK {
                zero &= self.state()?.load(Ordering::SeqCst) == 0;
                zero &= self.flags()?.load(Ordering::SeqCst) == 0;
            } else {
                zero &= self.word64(index)?.load(Ordering::SeqCst) == 0;
            }
        }
        Ok(zero)
    }

    #[cfg(test)]
    fn header_words(&self) -> Result<[u64; 8]> {
        let mut words = [0; 8];
        for (index, word) in words.iter_mut().enumerate() {
            *word = if index == STATE_CHUNK {
                u64::from(self.state()?.load(Ordering::SeqCst))
                    | (u64::from(self.flags()?.load(Ordering::SeqCst)) << 32)
            } else {
                self.word64(index)?.load(Ordering::SeqCst)
            };
        }
        Ok(words)
    }

    fn close(&mut self) -> Result<()> {
        if self.base.is_none() {
            return Ok(());
        }
        // Reply headers are never reset during retirement/terminal cleanup.
        let start = if self.role == ControlRole::Request {
            0
        } else {
            64
        };
        #[cfg(test)]
        let witness = zero_witness::before(self, start);
        let zeroed = self.zero_from(start);
        #[cfg(test)]
        zero_witness::after(self, start, witness, zeroed.is_ok());
        // Even a failed Close makes pointer validity uncertain. Retain the COM
        // owner/error latch but never access this pointer again.
        self.base = None;
        let closed = close_object(&self.object);
        if closed.is_err() || zeroed.is_err() {
            self.close_uncertain.set(true);
        }
        zeroed.and(closed)
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // The normal driver path checks close explicitly after the release
        // window. Constructor failure and unexpected owner destruction still
        // wipe a mapping; any native failure stays in the shared error latch.
        let _closed = self.close();
    }
}

fn observe_mapping(object: &ICoreWebView2SharedBuffer, capacity: u32) -> Result<NonNull<u8>> {
    let mut size = 0_u64;
    // SAFETY: live owned STA buffer and initialized distinct writable output.
    unsafe { object.Size(&raw mut size) }.map_err(|_| unavailable())?;
    let mut pointer = std::ptr::null_mut();
    // SAFETY: the live buffer owns the mapping; initialized output receives a
    // borrowed pointer used only while that interface is held and not closed.
    unsafe { object.Buffer(&raw mut pointer) }.map_err(|_| unavailable())?;
    if size != u64::from(capacity) || capacity < 64 || !capacity.is_multiple_of(8) {
        return Err(unavailable());
    }
    NonNull::new(pointer)
        .filter(|pointer| (pointer.as_ptr() as usize).is_multiple_of(64))
        .ok_or_else(unavailable)
}

fn close_object(object: &ICoreWebView2SharedBuffer) -> Result<()> {
    // SAFETY: a live owned STA interface; all atomic borrows ended before this
    // call and no pointer access is attempted after it, including on error.
    unsafe { object.Close() }.map_err(|_| unavailable())
}

pub(super) struct Pair {
    request: Mapping,
    reply: Mapping,
}

impl Pair {
    pub(super) fn new(
        environment: &ICoreWebView2Environment12,
        kind: CeremonyKind,
        request: &[u8],
        reply_header: &[u8; 64],
        close_uncertain: Rc<Cell<bool>>,
    ) -> Result<Self> {
        if request.len() != REQUEST_BUFFER_CAPACITY as usize {
            return Err(unavailable());
        }
        let reply_capacity = match kind {
            CeremonyKind::Create => CREATE_REPLY_BUFFER_CAPACITY,
            CeremonyKind::Get => GET_REPLY_BUFFER_CAPACITY,
        };
        let request_mapping = Mapping::new(
            environment,
            REQUEST_BUFFER_CAPACITY,
            ControlRole::Request,
            Rc::clone(&close_uncertain),
        )?;
        let reply_mapping = Mapping::new(
            environment,
            reply_capacity,
            ControlRole::Reply,
            close_uncertain,
        )?;
        let pair = Self {
            request: request_mapping,
            reply: reply_mapping,
        };
        // Both allocations are admitted before writing any request secret.
        // Any later failure drops both owners and wipes both mappings.
        pair.reply.zero_from(0)?;
        pair.reply.initialize(reply_header)?;
        pair.request.initialize(request)?;
        Ok(pair)
    }

    pub(super) fn post_request(&self, view: &ICoreWebView2_17) -> Result<()> {
        // SAFETY: live main-frame interface and admitted mapping, constant JSON;
        // pointer/COM owners remain on this STA. Request access is read-only.
        unsafe {
            view.PostSharedBufferToScript(
                &self.request.object,
                COREWEBVIEW2_SHARED_BUFFER_ACCESS_READ_ONLY,
                w!("{\"role\":\"request\"}"),
            )
        }
        .map_err(|_| unavailable())
    }

    pub(super) fn post_reply(&self, view: &ICoreWebView2_17) -> Result<()> {
        // SAFETY: live main-frame interface and admitted mapping, constant JSON;
        // this is the reply buffer's sole allowed read/write exposure.
        unsafe {
            view.PostSharedBufferToScript(
                &self.reply.object,
                COREWEBVIEW2_SHARED_BUFFER_ACCESS_READ_WRITE,
                w!("{\"role\":\"reply\"}"),
            )
        }
        .map_err(|_| unavailable())
    }

    pub(super) fn load_state(&self) -> Result<u32> {
        self.reply.state().map(|state| state.load(Ordering::SeqCst))
    }

    pub(super) fn compare_exchange(&self, current: u32, next: u32) -> Result<bool> {
        self.reply.state().map(|state| {
            state
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        })
    }

    pub(super) fn copy_reply(&self, out: &mut ReplyImage) -> Result<()> {
        self.reply.copy_to(out.as_mut_bytes())
    }

    pub(super) fn close(&mut self) -> Result<()> {
        // Always attempt both zero/close operations, even when the first fails.
        let request = self.request.close();
        let reply = self.reply.close();
        request.and(reply)
    }
}

const fn unavailable() -> NativeError {
    NativeError {
        operation: Operation::Buffers,
        failure: Failure::CallFailed,
    }
}

#[cfg(test)]
mod zero_witness {
    use super::Mapping;
    use crate::{BufferSlot, NativeZeroObservation};
    use pos_owner_bridge_codec::ControlRole;
    use std::cell::RefCell;

    std::thread_local! {
        static OBSERVATIONS: RefCell<Option<Vec<NativeZeroObservation>>> = const { RefCell::new(None) };
    }

    pub(super) struct Before {
        before_nonzero: Option<bool>,
        header: Option<[u64; 8]>,
    }

    pub(super) fn before(mapping: &Mapping, start: usize) -> Option<Before> {
        if !OBSERVATIONS.with(|observations| observations.borrow().is_some()) {
            return None;
        }
        Some(Before {
            before_nonzero: mapping.all_zero_from(start).ok().map(|zero| !zero),
            header: if mapping.role == ControlRole::Reply {
                mapping.header_words().ok()
            } else {
                None
            },
        })
    }

    pub(super) fn after(
        mapping: &Mapping,
        start: usize,
        before: Option<Before>,
        zero_succeeded: bool,
    ) {
        let Some(before) = before else {
            return;
        };
        let zeroed = if zero_succeeded {
            mapping.all_zero_from(start).ok()
        } else {
            None
        };
        let header_present = before.header.map(|old| old.iter().any(|word| *word != 0));
        let header_unchanged = before
            .header
            .and_then(|old| mapping.header_words().ok().map(|new| old == new));
        let slot = if mapping.role == ControlRole::Request {
            BufferSlot::Request
        } else {
            BufferSlot::Reply
        };
        OBSERVATIONS.with(|observations| {
            if let Some(observations) = observations.borrow_mut().as_mut() {
                observations.push(NativeZeroObservation {
                    slot,
                    before_nonzero: before.before_nonzero,
                    zeroed,
                    header_present,
                    header_unchanged,
                });
            }
        });
    }

    impl crate::Native {
        pub(crate) fn arm_native_zero_observations() {
            OBSERVATIONS.with(|observations| *observations.borrow_mut() = Some(Vec::new()));
        }

        pub(crate) fn take_native_zero_observations() -> Vec<NativeZeroObservation> {
            OBSERVATIONS.with(|observations| observations.borrow_mut().take().unwrap_or_default())
        }
    }
}

const fn valid_aligned_offset(capacity: usize, offset: usize) -> bool {
    offset <= capacity && offset.is_multiple_of(8)
}

#[cfg(test)]
mod tests {
    #[test]
    fn aligned_offsets_include_end_but_reject_unaligned_and_out_of_bounds() {
        for offset in [0, 8, 56, 64] {
            assert!(super::valid_aligned_offset(64, offset));
        }
        for offset in [1, 63, 65, 72, usize::MAX] {
            assert!(!super::valid_aligned_offset(64, offset));
        }
    }
}
