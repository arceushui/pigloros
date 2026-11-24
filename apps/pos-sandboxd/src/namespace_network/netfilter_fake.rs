//! A fake nftables kernel behind a [`NetlinkTransport`], for the tests of the
//! generation-bracketed reads (ADR-069 R14 §3.2 steps 4 and 5).
//!
//! It answers `NFT_MSG_GETGEN` with the next scripted generation and every
//! table, chain and rule dump with the messages it holds, so the sequence
//! numbers always agree with the requests, however often a read is retried.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use netlink_packet_core::{
    DoneMessage, NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    NetlinkSerializable, NLM_F_DUMP_INTR, NLM_F_MULTIPART,
};
use netlink_packet_netfilter::nftables::{GenAttribute, GenMessage, NfTablesMessage, TableMessage};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
};
use rustix::io::Errno;

use super::netlink::{NetlinkError, NetlinkSession, NetlinkTransport};

/// What the fake kernel holds, and what it will answer.
#[derive(Default)]
pub(super) struct Kernel {
    /// The answers to `NFT_MSG_GETGEN`, in order; none left, and the reply
    /// never arrives.
    pub(super) generations: VecDeque<u32>,
    pub(super) tables: Vec<NetfilterMessage>,
    pub(super) chains: Vec<NetfilterMessage>,
    pub(super) rules: Vec<NetfilterMessage>,
    /// How many of the next dumps end flagged as interrupted.
    pub(super) interrupted: usize,
    /// How many sessions were opened.
    pub(super) opened: usize,
    /// What the generation replies get wrong, if anything.
    pub(super) fault: Fault,
}

/// How a fake kernel mis-answers `NFT_MSG_GETGEN`.
#[derive(Clone, Copy, Default)]
pub(super) enum Fault {
    #[default]
    None,
    /// The reply carries no `NFTA_GEN_ID`.
    NoId,
    /// The reply is a table, not a generation.
    NotAGeneration,
}

/// A shared fake kernel.
pub(super) type Shared = Rc<RefCell<Kernel>>;

/// A kernel that answers `generations` in order and holds no ruleset.
pub(super) fn kernel(generations: &[u32]) -> Shared {
    Rc::new(RefCell::new(Kernel {
        generations: generations.iter().copied().collect(),
        ..Kernel::default()
    }))
}

/// A session over a new connection to `kernel`.
pub(super) fn session(kernel: &Shared) -> NetlinkSession<Wire> {
    kernel.borrow_mut().opened += 1;
    NetlinkSession::new(Wire {
        kernel: Rc::clone(kernel),
        replies: RefCell::new(VecDeque::new()),
    })
}

/// One connection to the fake kernel.
pub(super) struct Wire {
    kernel: Shared,
    replies: RefCell<VecDeque<Vec<u8>>>,
}

impl NetlinkTransport for Wire {
    fn send(&self, datagram: &[u8]) -> Result<(), NetlinkError> {
        let request = NetlinkMessage::<NetfilterMessage>::deserialize(datagram)
            .map_err(|_| NetlinkError::Decode)?;
        let sequence = request.header.sequence_number;
        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(kind),
            ..
        }) = request.payload
        else {
            return Err(NetlinkError::Unexpected);
        };
        let answered = self.kernel.borrow_mut().answer(sequence, &kind);
        self.replies.borrow_mut().extend(answered);
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, NetlinkError> {
        self.replies
            .borrow_mut()
            .pop_front()
            .ok_or(NetlinkError::Io(Errno::TIMEDOUT))
    }
}

/// `payload` as one reply datagram to request `sequence`.
fn datagram<I: NetlinkSerializable + NetlinkDeserializable>(
    sequence: u32,
    flags: u16,
    payload: NetlinkPayload<I>,
) -> Vec<u8> {
    let mut header = NetlinkHeader::default();
    header.sequence_number = sequence;
    header.flags = flags;
    let mut message = NetlinkMessage::new(header, payload);
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

impl Kernel {
    /// The datagrams the kernel answers `request` with.
    fn answer(&mut self, sequence: u32, request: &NfTablesMessage) -> Vec<Vec<u8>> {
        match request {
            NfTablesMessage::GetGen(_) => self.generation(sequence),
            NfTablesMessage::GetTable(_) => self.dump(sequence, self.tables.clone()),
            NfTablesMessage::GetChain(_) => self.dump(sequence, self.chains.clone()),
            _ => self.dump(sequence, self.rules.clone()),
        }
    }

    fn generation(&mut self, sequence: u32) -> Vec<Vec<u8>> {
        self.generations
            .pop_front()
            .map(|id| {
                let report = match self.fault {
                    Fault::None => NfTablesMessage::NewGen(GenMessage {
                        attributes: vec![GenAttribute::Id(id)],
                    }),
                    Fault::NoId => NfTablesMessage::NewGen(GenMessage {
                        attributes: Vec::new(),
                    }),
                    Fault::NotAGeneration => NfTablesMessage::NewTable(TableMessage {
                        attributes: Vec::new(),
                    }),
                };
                let reply = NetfilterMessage::new(
                    NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, 0),
                    report,
                );
                datagram(sequence, 0, NetlinkPayload::InnerMessage(reply))
            })
            .into_iter()
            .collect()
    }

    /// `items` as one dump, flagged as interrupted while the script says so.
    fn dump(&mut self, sequence: u32, items: Vec<NetfilterMessage>) -> Vec<Vec<u8>> {
        let flag = if self.interrupted > 0 {
            self.interrupted -= 1;
            NLM_F_DUMP_INTR
        } else {
            0
        };
        let mut replies: Vec<Vec<u8>> = items
            .into_iter()
            .map(|item| {
                datagram(
                    sequence,
                    NLM_F_MULTIPART,
                    NetlinkPayload::InnerMessage(item),
                )
            })
            .collect();
        replies.push(datagram::<NetfilterMessage>(
            sequence,
            NLM_F_MULTIPART | flag,
            NetlinkPayload::Done(DoneMessage::default()),
        ));
        replies
    }
}
