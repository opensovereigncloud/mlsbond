//! The mlsbond server: the Delivery Service of every VNI group. It orders and relays what the
//! clients send, names one committer per group and hands it what is pending, and carries out the
//! rekey policy. It holds no secrets and keeps everything in memory only.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures::Stream;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{info, warn};

use crate::prefix::HostPrefix;
use crate::proto::admin_server::Admin;
use crate::proto::delivery_server::Delivery;
use crate::proto::{self, client_message, entry, server_message};

pub use crate::proto::admin_server::AdminServer;
pub use crate::proto::delivery_server::DeliveryServer;

#[derive(Clone, Debug)]
pub struct Config {
    /// How long a member's stream may be gone before the member is removed from its groups.
    pub removal_grace: Duration,
    /// How long pending changes are collected before the committer is asked for a commit.
    pub commit_delay: Duration,
}

type Tx = mpsc::UnboundedSender<Result<proto::ServerMessage, Status>>;

enum Event {
    Connected { conn: u64, hello: proto::Hello, tx: Tx },
    Message { conn: u64, msg: client_message::Message },
    Disconnected { conn: u64 },
    Admin(AdminRequest),
}

enum AdminRequest {
    GetPolicy(oneshot::Sender<proto::GetPolicyResponse>),
    SetPolicy(proto::RekeyPolicy, oneshot::Sender<()>),
    SetVniPolicy(u32, proto::RekeyPolicy, oneshot::Sender<()>),
    ClearVniPolicy(u32, oneshot::Sender<()>),
    Rekey(u32, oneshot::Sender<Result<(), Status>>),
    ListGroups(oneshot::Sender<proto::ListGroupsResponse>),
}

/// Starts the server's state machine and returns the two gRPC services.
pub fn start(config: Config) -> (DeliveryServer<DeliveryService>, AdminServer<AdminService>) {
    let (events, rx) = mpsc::unbounded_channel();
    let boot_id = format!("{:016x}", rand::random::<u64>());
    info!("mlsbond server starting, boot ID {boot_id}");
    tokio::spawn(State::new(config, boot_id).run(rx));
    (
        DeliveryServer::new(DeliveryService { events: events.clone(), next_conn: Arc::new(AtomicU64::new(1)) }),
        AdminServer::new(AdminService { events }),
    )
}

// ------------------------------------------------------------------------------------------------
// gRPC services
// ------------------------------------------------------------------------------------------------

pub struct DeliveryService {
    events: mpsc::UnboundedSender<Event>,
    next_conn: Arc<AtomicU64>,
}

#[tonic::async_trait]
impl Delivery for DeliveryService {
    type StreamStream = Pin<Box<dyn Stream<Item = Result<proto::ServerMessage, Status>> + Send>>;

    async fn stream(&self, request: Request<Streaming<proto::ClientMessage>>) -> Result<Response<Self::StreamStream>, Status> {
        let mut inbound = request.into_inner();
        let hello = match inbound.message().await?.and_then(|m| m.message) {
            Some(client_message::Message::Hello(hello)) => hello,
            _ => return Err(Status::invalid_argument("the stream must start with Hello")),
        };
        if hello.host_prefix.parse::<HostPrefix>().is_err() {
            return Err(Status::invalid_argument("host prefix must be an IPv6 /64"));
        }
        let conn = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        let events = self.events.clone();
        events.send(Event::Connected { conn, hello, tx }).map_err(|_| Status::unavailable("shutting down"))?;
        tokio::spawn(async move {
            while let Ok(Some(m)) = inbound.message().await {
                if let Some(msg) = m.message {
                    let _ = events.send(Event::Message { conn, msg });
                }
            }
            let _ = events.send(Event::Disconnected { conn });
        });
        Ok(Response::new(Box::pin(UnboundedReceiverStream::new(rx))))
    }
}

pub struct AdminService {
    events: mpsc::UnboundedSender<Event>,
}

impl AdminService {
    async fn ask<T>(&self, req: impl FnOnce(oneshot::Sender<T>) -> AdminRequest) -> Result<T, Status> {
        let (tx, rx) = oneshot::channel();
        self.events.send(Event::Admin(req(tx))).map_err(|_| Status::unavailable("shutting down"))?;
        rx.await.map_err(|_| Status::unavailable("shutting down"))
    }
}

fn check_vni(vni: u32) -> Result<(), Status> {
    if vni == 0 || vni >= 1 << 24 {
        return Err(Status::invalid_argument(format!("vni must be between 1 and {}", (1 << 24) - 1)));
    }
    Ok(())
}

#[tonic::async_trait]
impl Admin for AdminService {
    async fn get_policy(&self, _: Request<proto::GetPolicyRequest>) -> Result<Response<proto::GetPolicyResponse>, Status> {
        Ok(Response::new(self.ask(AdminRequest::GetPolicy).await?))
    }

    async fn set_policy(&self, req: Request<proto::SetPolicyRequest>) -> Result<Response<proto::SetPolicyResponse>, Status> {
        let policy = req.into_inner().policy.unwrap_or_default();
        self.ask(|tx| AdminRequest::SetPolicy(policy, tx)).await?;
        Ok(Response::new(proto::SetPolicyResponse {}))
    }

    async fn set_vni_policy(&self, req: Request<proto::SetVniPolicyRequest>) -> Result<Response<proto::SetVniPolicyResponse>, Status> {
        let req = req.into_inner();
        check_vni(req.vni)?;
        let policy = req.policy.unwrap_or_default();
        self.ask(|tx| AdminRequest::SetVniPolicy(req.vni, policy, tx)).await?;
        Ok(Response::new(proto::SetVniPolicyResponse {}))
    }

    async fn clear_vni_policy(&self, req: Request<proto::ClearVniPolicyRequest>) -> Result<Response<proto::ClearVniPolicyResponse>, Status> {
        let vni = req.into_inner().vni;
        check_vni(vni)?;
        self.ask(|tx| AdminRequest::ClearVniPolicy(vni, tx)).await?;
        Ok(Response::new(proto::ClearVniPolicyResponse {}))
    }

    async fn rekey(&self, req: Request<proto::RekeyRequest>) -> Result<Response<proto::RekeyResponse>, Status> {
        let vni = req.into_inner().vni;
        check_vni(vni)?;
        self.ask(|tx| AdminRequest::Rekey(vni, tx)).await??;
        Ok(Response::new(proto::RekeyResponse {}))
    }

    async fn list_groups(&self, _: Request<proto::ListGroupsRequest>) -> Result<Response<proto::ListGroupsResponse>, Status> {
        Ok(Response::new(self.ask(AdminRequest::ListGroups).await?))
    }
}

// ------------------------------------------------------------------------------------------------
// State
// ------------------------------------------------------------------------------------------------

/// One mlsbond client process, by host prefix. A new process under the same host prefix (a new
/// instance) replaces the old one.
struct Client {
    name: String,
    instance: u64,
    conn: Option<(u64, Tx)>,
    key_packages: VecDeque<Vec<u8>>,
    /// per VNI, the last GroupMessage id accepted from this instance
    accepted: HashMap<u32, u64>,
}

/// A leaf of a VNI group: one instance of a host.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
struct Leaf {
    prefix: HostPrefix,
    instance: u64,
}

struct Member {
    leaf: Leaf,
    /// since when its instance has had no stream
    gone_since: Option<Instant>,
}

enum LogKind {
    Commit { work: u64, committer: HostPrefix, commit: Vec<u8>, welcome: Vec<u8>, added: Vec<Leaf> },
    Message { sender: HostPrefix, message: proto::GroupMessage },
}

struct LogEntry {
    seq: u64,
    kind: LogKind,
}

/// Work handed to a committer, waiting for its commit.
struct Work {
    id: u64,
    committer: Leaf,
    epoch: u64,
    adds: Vec<(Leaf, Vec<u8>)>,
    removes: Vec<Leaf>,
    scope: proto::Scope,
    reset: Option<HostPrefix>,
}

struct Group {
    vni: u32,
    /// the client asked to create the group, until it has
    creator: Option<Leaf>,
    /// oldest first
    members: Vec<Member>,
    committer: Option<HostPrefix>,
    epoch: u64,
    next_seq: u64,
    log: VecDeque<LogEntry>,
    acks: HashMap<HostPrefix, u64>,
    pending_adds: Vec<Leaf>,
    pending_removes: BTreeSet<Leaf>,
    rekey_all: bool,
    /// hosts whose dataplane was reset, to rekey one per commit
    resets: VecDeque<HostPrefix>,
    /// the reset host asked to propose an update of its leaf, in which epoch
    asked: Option<(HostPrefix, u64)>,
    /// its proposal, relayed in this epoch
    proposal: Option<(HostPrefix, u64)>,
    work: Option<Work>,
    dispatch_at: Option<Instant>,
    last_rekey: Instant,
}

impl Group {
    fn new(vni: u32, creator: Leaf) -> Group {
        Group {
            vni,
            creator: Some(creator),
            members: Vec::new(),
            committer: None,
            epoch: 0,
            next_seq: 1,
            log: VecDeque::new(),
            acks: HashMap::new(),
            pending_adds: Vec::new(),
            pending_removes: BTreeSet::new(),
            rekey_all: false,
            resets: VecDeque::new(),
            asked: None,
            proposal: None,
            work: None,
            dispatch_at: None,
            last_rekey: Instant::now(),
        }
    }

    fn member(&self, prefix: HostPrefix) -> Option<&Member> {
        self.members.iter().find(|m| m.leaf.prefix == prefix)
    }

    fn is_member(&self, leaf: Leaf) -> bool {
        self.member(leaf.prefix).is_some_and(|m| m.leaf == leaf)
    }

    fn schedule(&mut self, delay: Duration) {
        let at = Instant::now() + delay;
        if self.dispatch_at.is_none_or(|t| t > at) {
            self.dispatch_at = Some(at);
        }
    }
}

struct State {
    config: Config,
    boot_id: String,
    clients: HashMap<HostPrefix, Client>,
    conns: HashMap<u64, Leaf>,
    groups: BTreeMap<u32, Group>,
    policy: proto::RekeyPolicy,
    vni_policies: BTreeMap<u32, proto::RekeyPolicy>,
    next_work: u64,
}

fn msg(m: server_message::Message) -> proto::ServerMessage {
    proto::ServerMessage { message: Some(m) }
}

impl State {
    fn new(config: Config, boot_id: String) -> State {
        State {
            config,
            boot_id,
            clients: HashMap::new(),
            conns: HashMap::new(),
            groups: BTreeMap::new(),
            policy: proto::RekeyPolicy::default(),
            vni_policies: BTreeMap::new(),
            next_work: 1,
        }
    }

    async fn run(mut self, mut events: mpsc::UnboundedReceiver<Event>) {
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! {
                ev = events.recv() => match ev {
                    Some(ev) => self.handle(ev),
                    None => return,
                },
                _ = tick.tick() => self.tick(),
            }
        }
    }

    fn handle(&mut self, ev: Event) {
        match ev {
            Event::Connected { conn, hello, tx } => self.connected(conn, hello, tx),
            Event::Message { conn, msg } => {
                if let Some(&leaf) = self.conns.get(&conn) {
                    self.message(leaf, msg);
                }
            }
            Event::Disconnected { conn } => {
                if let Some(leaf) = self.conns.remove(&conn) {
                    if let Some(c) = self.clients.get_mut(&leaf.prefix) {
                        if c.conn.as_ref().is_some_and(|(id, _)| *id == conn) {
                            info!("{} ({}) disconnected", leaf.prefix, c.name);
                            c.conn = None;
                        }
                    }
                }
            }
            Event::Admin(req) => self.admin(req),
        }
    }

    /// Whether the leaf's instance is the current one of its host and has a stream.
    fn alive(&self, leaf: Leaf) -> bool {
        self.clients.get(&leaf.prefix).is_some_and(|c| c.instance == leaf.instance && c.conn.is_some())
    }

    fn send(&self, leaf: Leaf, m: server_message::Message) {
        if let Some(c) = self.clients.get(&leaf.prefix) {
            if c.instance == leaf.instance {
                if let Some((_, tx)) = &c.conn {
                    let _ = tx.send(Ok(msg(m)));
                }
            }
        }
    }

    fn effective_policy(&self, vni: u32) -> proto::RekeyPolicy {
        self.vni_policies.get(&vni).copied().unwrap_or(self.policy)
    }

    fn connected(&mut self, conn: u64, hello: proto::Hello, tx: Tx) {
        let Ok(prefix) = hello.host_prefix.parse::<HostPrefix>() else { return };
        let leaf = Leaf { prefix, instance: hello.instance };
        match self.clients.get_mut(&prefix) {
            Some(c) if c.instance == hello.instance => {
                info!("{prefix} ({}) reconnected", hello.client_name);
                c.conn = Some((conn, tx));
                c.name = hello.client_name;
            }
            old => {
                if old.is_some() {
                    info!("{prefix} ({}) connected as a new instance, replacing the old one", hello.client_name);
                } else {
                    info!("{prefix} ({}) connected", hello.client_name);
                }
                self.clients.insert(
                    prefix,
                    Client {
                        name: hello.client_name,
                        instance: hello.instance,
                        conn: Some((conn, tx)),
                        key_packages: VecDeque::new(),
                        accepted: HashMap::new(),
                    },
                );
            }
        }
        self.conns.insert(conn, leaf);
        let key_packages = self.clients[&prefix].key_packages.len() as u32;
        self.send(leaf, server_message::Message::HelloAck(proto::HelloAck { boot_id: self.boot_id.clone(), key_packages }));
    }

    fn message(&mut self, leaf: Leaf, m: client_message::Message) {
        use client_message::Message as M;
        match m {
            M::Hello(_) => {}
            M::KeyPackages(kps) => {
                if let Some(c) = self.clients.get_mut(&leaf.prefix) {
                    c.key_packages.extend(kps.key_packages);
                }
                let delay = self.config.commit_delay;
                for g in self.groups.values_mut() {
                    if g.pending_adds.contains(&leaf) {
                        g.schedule(delay);
                    }
                }
            }
            M::Join(j) => self.join(leaf, j.vni),
            M::Resume(r) => self.resume(leaf, r.vni, r.last_seq),
            M::Leave(l) => self.leave(leaf, l.vni),
            M::GroupCreated(c) => self.group_created(leaf, c.vni),
            M::Commit(c) => self.commit(leaf, c),
            M::CommitFailed(f) => self.commit_failed(leaf, f),
            M::GroupMessage(gm) => self.group_message(leaf, gm),
            M::Ack(a) => {
                if let Some(g) = self.groups.get_mut(&a.vni) {
                    if g.is_member(leaf) {
                        let ack = g.acks.entry(leaf.prefix).or_default();
                        *ack = (*ack).max(a.seq);
                        trim_log(g);
                    }
                }
            }
            M::ResetRequest(_) => {
                let delay = self.config.commit_delay;
                for g in self.groups.values_mut() {
                    if g.is_member(leaf) && g.members.len() > 1 && !g.resets.contains(&leaf.prefix) {
                        info!("vni {}: dataplane reset of {}, rekeying its pairs", g.vni, leaf.prefix);
                        g.resets.push_back(leaf.prefix);
                        g.schedule(delay);
                    }
                }
            }
        }
    }

    fn join(&mut self, leaf: Leaf, vni: u32) {
        if check_vni(vni).is_err() {
            return;
        }
        let delay = self.config.commit_delay;
        let Some(g) = self.groups.get_mut(&vni) else {
            info!("vni {vni}: {} creates the VNI group", leaf.prefix);
            self.groups.insert(vni, Group::new(vni, leaf));
            self.send(leaf, server_message::Message::CreateGroup(proto::CreateGroup { vni }));
            return;
        };
        if g.creator == Some(leaf) {
            self.send(leaf, server_message::Message::CreateGroup(proto::CreateGroup { vni }));
            return;
        }
        if g.pending_adds.contains(&leaf) {
            return;
        }
        g.pending_adds.retain(|l| l.prefix != leaf.prefix);
        if let Some(m) = g.member(leaf.prefix) {
            // a restarted client, or one that lost its group: its old leaf goes in the same commit
            info!("vni {vni}: {} joins again, replacing its leaf", leaf.prefix);
            g.pending_removes.insert(m.leaf);
        } else {
            info!("vni {vni}: {} joins", leaf.prefix);
        }
        g.pending_adds.push(leaf);
        g.schedule(delay);
    }

    fn resume(&mut self, leaf: Leaf, vni: u32, last_seq: u64) {
        let resumable = self.groups.get(&vni).is_some_and(|g| {
            g.is_member(leaf) && !g.pending_removes.contains(&leaf) && g.log.front().is_none_or(|e| e.seq <= last_seq + 1) && last_seq < g.next_seq
        });
        if !resumable {
            info!("vni {vni}: {} cannot resume, rejoining", leaf.prefix);
            self.send(leaf, server_message::Message::Rejoin(proto::Rejoin { vni }));
            return;
        }
        let g = &self.groups[&vni];
        for e in g.log.iter().filter(|e| e.seq > last_seq) {
            if let Some(m) = entry_for(g, e, leaf) {
                self.send(leaf, m);
            }
        }
        // a committer coming back finds its work again, after what it missed
        if let Some(w) = g.work.as_ref().filter(|w| w.committer == leaf) {
            self.send(leaf, server_message::Message::CommitWork(self.work_message(g, w)));
        }
        let delay = self.config.commit_delay;
        let g = self.groups.get_mut(&vni).unwrap();
        // a reset host that was away may have missed the request to propose its update
        if g.asked.is_some_and(|(p, _)| p == leaf.prefix) && g.proposal.is_none() {
            g.asked = None;
            g.schedule(delay);
        }
        let ack = g.acks.entry(leaf.prefix).or_default();
        *ack = (*ack).max(last_seq);
    }

    fn leave(&mut self, leaf: Leaf, vni: u32) {
        let delay = self.config.commit_delay;
        let Some(g) = self.groups.get_mut(&vni) else { return };
        g.pending_adds.retain(|l| *l != leaf);
        if g.creator == Some(leaf) {
            g.creator = None;
        }
        if g.is_member(leaf) {
            info!("vni {vni}: {} leaves", leaf.prefix);
            g.pending_removes.insert(leaf);
            g.resets.retain(|p| *p != leaf.prefix);
        }
        g.schedule(delay);
    }

    fn group_created(&mut self, leaf: Leaf, vni: u32) {
        let delay = self.config.commit_delay;
        let Some(g) = self.groups.get_mut(&vni) else { return };
        if g.creator != Some(leaf) {
            return;
        }
        info!("vni {vni}: VNI group created by {}, its committer", leaf.prefix);
        g.creator = None;
        g.members = vec![Member { leaf, gone_since: None }];
        g.committer = Some(leaf.prefix);
        g.last_rekey = Instant::now();
        g.acks.insert(leaf.prefix, 0);
        g.schedule(delay);
    }

    fn group_message(&mut self, leaf: Leaf, gm: proto::GroupMessage) {
        let (vni, id) = (gm.vni, gm.id);

        let Some(c) = self.clients.get_mut(&leaf.prefix) else { return };
        if c.instance != leaf.instance {
            return;
        }
        let last = c.accepted.entry(vni).or_default();
        let duplicate = id <= *last;
        *last = (*last).max(id);
        let accepted = server_message::Message::Accepted(proto::Accepted { vni, id });
        if duplicate {
            self.send(leaf, accepted);
            return;
        }
        if let Some(g) = self.groups.get_mut(&vni).filter(|g| g.is_member(leaf)) {
            let relay = match gm.kind() {
                proto::GroupMessageKind::Application => true,
                // only the update a reset host was asked for, in the epoch it was asked for and
                // while no commit is under way, so that the next commit includes it
                proto::GroupMessageKind::Proposal => {
                    let wanted = g.asked == Some((leaf.prefix, gm.epoch)) && g.epoch == gm.epoch && g.work.is_none();
                    if wanted {
                        g.proposal = Some((leaf.prefix, gm.epoch));
                        g.schedule(Duration::ZERO);
                    }
                    wanted
                }
                proto::GroupMessageKind::Unspecified => false,
            };
            if relay {
                let seq = g.next_seq;
                g.next_seq += 1;
                g.log.push_back(LogEntry { seq, kind: LogKind::Message { sender: leaf.prefix, message: gm } });
                let g = &self.groups[&vni];
                let e = g.log.back().unwrap();
                for m in &g.members {
                    if let Some(sm) = entry_for(g, e, m.leaf) {
                        self.send(m.leaf, sm);
                    }
                }
            }
        }
        self.send(leaf, accepted);
    }

    fn commit(&mut self, leaf: Leaf, c: proto::Commit) {
        let delay = self.config.commit_delay;
        let Some(g) = self.groups.get_mut(&c.vni) else { return };
        let Some(w) = g.work.take_if(|w| w.id == c.work && w.committer == leaf) else {
            warn!("vni {}: ignoring a commit from {} for work {} not handed to it", c.vni, leaf.prefix, c.work);
            return;
        };
        let seq = g.next_seq;
        g.next_seq += 1;
        g.members.retain(|m| !w.removes.contains(&m.leaf));
        let added: Vec<Leaf> = w.adds.iter().map(|(l, _)| *l).collect();
        for l in &w.removes {
            g.acks.remove(&l.prefix);
            g.pending_removes.remove(l);
        }
        for &l in &added {
            g.members.push(Member { leaf: l, gone_since: None });
            g.acks.insert(l.prefix, seq);
        }
        g.pending_adds.retain(|l| !added.contains(l));
        g.epoch += 1;
        g.proposal = None;
        g.asked = None;
        let scope = w.scope.kind();
        if scope == proto::ScopeKind::ScopeAll {
            g.rekey_all = false;
            g.last_rekey = Instant::now();
        }
        if let Some(p) = w.reset {
            g.resets.retain(|r| *r != p);
        }
        let added_names: Vec<String> = added.iter().map(|l| l.prefix.to_string()).collect();
        let removed_names: Vec<String> = w.removes.iter().map(|l| l.prefix.to_string()).collect();
        info!(
            "vni {}: commit by {} to epoch {}: added [{}], removed [{}], rekey {}",
            g.vni,
            leaf.prefix,
            g.epoch,
            added_names.join(", "),
            removed_names.join(", "),
            match scope {
                proto::ScopeKind::ScopeNone => "none".to_string(),
                proto::ScopeKind::ScopeAll => "all pairs".to_string(),
                proto::ScopeKind::ScopeHost => format!("pairs of {}", w.scope.host_prefix),
            }
        );
        g.log.push_back(LogEntry {
            seq,
            kind: LogKind::Commit { work: w.id, committer: leaf.prefix, commit: c.commit, welcome: c.welcome, added: added.clone() },
        });
        if !g.pending_adds.is_empty() || !g.pending_removes.is_empty() || g.rekey_all || !g.resets.is_empty() {
            g.schedule(delay);
        }
        let g = &self.groups[&c.vni];
        let e = g.log.back().unwrap();
        let recipients: Vec<Leaf> = g.members.iter().map(|m| m.leaf).collect();
        for l in recipients {
            if let Some(m) = entry_for(g, e, l) {
                self.send(l, m);
            }
        }
        let mut used: HashMap<Leaf, u32> = HashMap::new();
        for l in added {
            *used.entry(l).or_default() += 1;
        }
        for (l, count) in used {
            self.send(l, server_message::Message::KeyPackagesUsed(proto::KeyPackagesUsed { count }));
        }
        let g = self.groups.get_mut(&c.vni).unwrap();
        trim_log(g);
    }

    fn commit_failed(&mut self, leaf: Leaf, f: proto::CommitFailed) {
        let Some(g) = self.groups.get_mut(&f.vni) else { return };
        let Some(w) = g.work.take_if(|w| w.id == f.work && w.committer == leaf) else { return };
        warn!("vni {}: {} could not commit: {}", f.vni, leaf.prefix, f.reason);
        let mut back = Vec::new();
        for (i, (l, kp)) in w.adds.into_iter().enumerate() {
            if f.bad_adds.contains(&(i as u32)) {
                // a key package the committer refused: the host has to upload another one
                self.send(l, server_message::Message::KeyPackagesUsed(proto::KeyPackagesUsed { count: 1 }));
            } else {
                back.push((l, kp));
            }
        }
        self.return_key_packages(back);
        let delay = self.config.removal_grace.max(Duration::from_secs(1));
        self.groups.get_mut(&f.vni).unwrap().schedule(delay);
    }

    fn return_key_packages(&mut self, kps: Vec<(Leaf, Vec<u8>)>) {
        for (l, kp) in kps.into_iter().rev() {
            if let Some(c) = self.clients.get_mut(&l.prefix).filter(|c| c.instance == l.instance) {
                c.key_packages.push_front(kp);
            }
        }
    }

    fn work_message(&self, g: &Group, w: &Work) -> proto::CommitWork {
        proto::CommitWork {
            vni: g.vni,
            work: w.id,
            epoch: w.epoch,
            adds: w.adds.iter().map(|(_, kp)| kp.clone()).collect(),
            removes: w.removes.iter().map(|l| l.prefix.to_string()).collect(),
            scope: Some(w.scope.clone()),
            include_proposals: w.reset.is_some() && g.proposal.is_some(),
            self_update: w.reset.is_some() && g.proposal.is_none(),
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        let vnis: Vec<u32> = self.groups.keys().copied().collect();
        for vni in vnis {
            self.tick_group(vni, now);
        }
    }

    fn tick_group(&mut self, vni: u32, now: Instant) {
        let grace = self.config.removal_grace;
        let delay = self.config.commit_delay;
        let policy = self.effective_policy(vni);
        let alive: Vec<bool> = self.groups[&vni].members.iter().map(|m| self.alive(m.leaf)).collect();
        let creator_alive = self.groups[&vni].creator.is_some_and(|l| self.alive(l));
        let g = self.groups.get_mut(&vni).unwrap();

        // members whose stream is gone for longer than the grace period are removed
        for (m, alive) in g.members.iter_mut().zip(alive) {
            if alive {
                m.gone_since = None;
            } else if m.gone_since.is_none() {
                m.gone_since = Some(now);
            } else if m.gone_since.is_some_and(|t| now - t >= grace) && !g.pending_removes.contains(&m.leaf) {
                info!("vni {vni}: {} is gone, removing it", m.leaf.prefix);
                g.pending_removes.insert(m.leaf);
                g.resets.retain(|p| *p != m.leaf.prefix);
                if g.dispatch_at.is_none() {
                    g.dispatch_at = Some(now + delay);
                }
            }
        }
        if g.creator.is_some() && !creator_alive {
            // whoever joined meanwhile creates the group instead
            g.creator = None;
            g.schedule(delay);
        }

        if policy.interval_seconds > 0
            && g.creator.is_none()
            && g.members.len() > 1
            && !g.rekey_all
            && now - g.last_rekey >= Duration::from_secs(policy.interval_seconds.into())
        {
            info!("vni {vni}: periodic rekey");
            g.rekey_all = true;
            g.schedule(Duration::ZERO);
        }

        if g.dispatch_at.is_some_and(|t| t <= now) {
            g.dispatch_at = None;
            self.dispatch(vni);
        }
    }

    /// Hands the committer what is pending, or recreates a group nobody can commit to any more.
    fn dispatch(&mut self, vni: u32) {
        let policy = self.effective_policy(vni);
        let g = &self.groups[&vni];
        if g.creator.is_some() {
            return;
        }
        let eligible: Vec<Leaf> = g.members.iter().map(|m| m.leaf).filter(|l| !g.pending_removes.contains(l) && self.alive(*l)).collect();

        // work of a committer that is being removed is abandoned
        if let Some(w) = &g.work {
            if eligible.contains(&w.committer) {
                return;
            }
            let g = self.groups.get_mut(&vni).unwrap();
            let w = g.work.take().unwrap();
            self.return_key_packages(w.adds);
        }
        let g = &self.groups[&vni];

        let Some(&committer) = eligible.first() else {
            // members gone for less than the grace period may still resume
            if g.members.iter().all(|m| g.pending_removes.contains(&m.leaf)) {
                self.recreate(vni);
            }
            return;
        };
        if g.members.len() == 1 && g.members[0].leaf == committer && g.pending_adds.is_empty() && g.pending_removes.is_empty() {
            // nothing to rekey in a group of one
            let g = self.groups.get_mut(&vni).unwrap();
            g.rekey_all = false;
            g.resets.clear();
            return;
        }

        // adds, each with the removal of an old leaf of its host
        let mut removes: BTreeSet<Leaf> = g.pending_removes.iter().copied().filter(|l| g.is_member(*l)).collect();
        let mut adds = Vec::new();
        for l in g.pending_adds.clone() {
            let Some(c) = self.clients.get_mut(&l.prefix).filter(|c| c.instance == l.instance) else { continue };
            let Some(kp) = c.key_packages.pop_front() else { continue };
            if let Some(m) = g.member(l.prefix) {
                removes.insert(m.leaf);
            }
            adds.push((l, kp));
        }
        let readded: BTreeSet<HostPrefix> = adds.iter().map(|(l, _)| l.prefix).collect();
        let removal = removes.iter().any(|l| !readded.contains(&l.prefix));

        let mut scope = proto::Scope::default();
        let mut reset = None;
        if let Some((p, e)) = g.proposal.filter(|(_, e)| *e == g.epoch) {
            let _ = e;
            reset = Some(p);
        } else if let Some(&p) = g.resets.front().filter(|p| **p == committer.prefix) {
            reset = Some(p);
        }
        if let Some(p) = reset {
            scope = proto::Scope { kind: proto::ScopeKind::ScopeHost.into(), host_prefix: p.to_string() };
        }
        if g.rekey_all || (removal && policy.rekey_on_removal) {
            scope = proto::Scope { kind: proto::ScopeKind::ScopeAll.into(), host_prefix: String::new() };
        }

        if adds.is_empty() && removes.is_empty() && scope.kind() == proto::ScopeKind::ScopeNone {
            // a reset host other than the committer first proposes an update of its leaf
            if let Some(&p) = g.resets.front() {
                if g.asked != Some((p, g.epoch)) {
                    if let Some(m) = g.member(p) {
                        let (leaf, epoch) = (m.leaf, g.epoch);
                        self.groups.get_mut(&vni).unwrap().asked = Some((p, epoch));
                        self.send(leaf, server_message::Message::ProposeUpdate(proto::ProposeUpdate { vni, epoch }));
                    }
                }
            }
            return;
        }

        let id = self.next_work;
        self.next_work += 1;
        let work = Work { id, committer, epoch: g.epoch, adds, removes: removes.into_iter().collect(), scope, reset };
        let g = self.groups.get_mut(&vni).unwrap();
        if g.committer != Some(committer.prefix) {
            info!("vni {vni}: {} is the committer now", committer.prefix);
            g.committer = Some(committer.prefix);
        }
        let m = self.work_message(&self.groups[&vni], &work);
        self.send(committer, server_message::Message::CommitWork(m));
        self.groups.get_mut(&vni).unwrap().work = Some(work);
    }

    /// Drops a group all of whose members are gone; whoever still wants to join starts it anew.
    fn recreate(&mut self, vni: u32) {
        let g = self.groups.remove(&vni).unwrap();
        info!("vni {vni}: all members gone, VNI group dropped");
        let mut waiting = g.pending_adds.into_iter().filter(|l| self.alive(*l));
        if let Some(creator) = waiting.next() {
            let mut ng = Group::new(vni, creator);
            ng.pending_adds = waiting.collect();
            self.groups.insert(vni, ng);
            info!("vni {vni}: {} creates the VNI group", creator.prefix);
            self.send(creator, server_message::Message::CreateGroup(proto::CreateGroup { vni }));
        }
    }

    fn admin(&mut self, req: AdminRequest) {
        match req {
            AdminRequest::GetPolicy(tx) => {
                let _ =
                    tx.send(proto::GetPolicyResponse { global: Some(self.policy), vnis: self.vni_policies.iter().map(|(k, v)| (*k, *v)).collect() });
            }
            AdminRequest::SetPolicy(p, tx) => {
                info!("rekey policy: every {}s, on removal {}", p.interval_seconds, p.rekey_on_removal);
                self.policy = p;
                let _ = tx.send(());
            }
            AdminRequest::SetVniPolicy(vni, p, tx) => {
                info!("vni {vni}: rekey policy every {}s, on removal {}", p.interval_seconds, p.rekey_on_removal);
                self.vni_policies.insert(vni, p);
                let _ = tx.send(());
            }
            AdminRequest::ClearVniPolicy(vni, tx) => {
                info!("vni {vni}: rekey policy back to the global one");
                self.vni_policies.remove(&vni);
                let _ = tx.send(());
            }
            AdminRequest::Rekey(vni, tx) => {
                let res = match self.groups.get_mut(&vni).filter(|g| g.creator.is_none()) {
                    Some(g) => {
                        info!("vni {vni}: rekey requested");
                        g.rekey_all = true;
                        g.schedule(Duration::ZERO);
                        Ok(())
                    }
                    None => Err(Status::not_found(format!("no VNI group {vni}"))),
                };
                let _ = tx.send(res);
            }
            AdminRequest::ListGroups(tx) => {
                let groups = self
                    .groups
                    .values()
                    .filter(|g| g.creator.is_none())
                    .map(|g| proto::GroupStatus {
                        vni: g.vni,
                        epoch: g.epoch,
                        committer: g.committer.map(|p| p.to_string()).unwrap_or_default(),
                        members: g
                            .members
                            .iter()
                            .map(|m| proto::GroupMember {
                                host_prefix: m.leaf.prefix.to_string(),
                                client_name: self.clients.get(&m.leaf.prefix).map(|c| c.name.clone()).unwrap_or_default(),
                                connected: self.alive(m.leaf),
                            })
                            .collect(),
                        policy: Some(self.effective_policy(g.vni)),
                    })
                    .collect();
                let _ = tx.send(proto::ListGroupsResponse { groups });
            }
        }
    }
}

/// What a log entry is to one leaf: the entry, its Welcome, or nothing.
fn entry_for(g: &Group, e: &LogEntry, leaf: Leaf) -> Option<server_message::Message> {
    let kind = match &e.kind {
        LogKind::Commit { added, welcome, .. } if added.contains(&leaf) => {
            return Some(server_message::Message::Welcomed(proto::Welcomed { vni: g.vni, seq: e.seq, welcome: welcome.clone() }));
        }
        LogKind::Commit { work, committer, commit, .. } => {
            entry::Kind::Commit(proto::CommitEntry { work: *work, committer: committer.to_string(), commit: commit.clone() })
        }
        LogKind::Message { sender, .. } if *sender == leaf.prefix => return None,
        LogKind::Message { message, .. } => entry::Kind::Message(message.clone()),
    };
    Some(server_message::Message::Entry(proto::Entry { vni: g.vni, seq: e.seq, kind: Some(kind) }))
}

/// Drops what every member has acknowledged.
fn trim_log(g: &mut Group) {
    let min = g.members.iter().map(|m| g.acks.get(&m.leaf.prefix).copied().unwrap_or(0)).min().unwrap_or(u64::MAX);
    while g.log.front().is_some_and(|e| e.seq <= min) {
        g.log.pop_front();
    }
}
