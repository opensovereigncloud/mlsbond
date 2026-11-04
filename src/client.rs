//! The mlsbond client: one per host, its member in every VNI group it subscribed to. It derives
//! the Security Associations of each pair of hosts and hands them to its orchestrator one step at
//! a time, paced by the peers' Ready and Switched. It never touches a dataplane and keeps
//! everything in memory only.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use futures::Stream;
use openmls::prelude::*;
use prost::Message as _;
use tls_codec::{Deserialize as _, Serialize as _};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::Endpoint;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, warn};

use crate::mls::{self, Identity, KeyMaterial};
use crate::prefix::HostPrefix;
use crate::proto::client_api_server::ClientApi;
use crate::proto::delivery_client::DeliveryClient;
use crate::proto::{self, client_message, entry, group_application, server_message, step, watch_request};

pub use crate::proto::client_api_server::ClientApiServer;

#[derive(Clone, Debug)]
pub struct Config {
    /// the mlsbond server, host:port or a URL
    pub server: String,
    /// key packages kept uploaded at the server
    pub key_packages: usize,
    /// how long pairs from before a (re)join wait for their peer to join too
    pub stale_pairs_after: Duration,
}

const BACKOFF_START: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const REPLAY_WINDOW: u32 = 64;

/// The identity of a Security Association, as dpservice uses it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
struct SaId {
    vni: u32,
    spi: u32,
    egress: bool,
    src: HostPrefix,
    dst: HostPrefix,
}

impl SaId {
    fn to_proto(self) -> proto::SecurityAssociationId {
        proto::SecurityAssociationId {
            vni: self.vni,
            spi: self.spi,
            direction: if self.egress { proto::Direction::Egress } else { proto::Direction::Ingress }.into(),
            src_underlay: self.src.underlay().octets().to_vec(),
            dst_underlay: self.dst.underlay().octets().to_vec(),
        }
    }

    fn from_proto(p: &proto::SecurityAssociationId) -> Option<SaId> {
        Some(SaId {
            vni: p.vni,
            spi: p.spi,
            egress: match p.direction() {
                proto::Direction::Egress => true,
                proto::Direction::Ingress => false,
                proto::Direction::Unspecified => return None,
            },
            src: HostPrefix::from_underlay_bytes(&p.src_underlay)?,
            dst: HostPrefix::from_underlay_bytes(&p.dst_underlay)?,
        })
    }
}

fn sa_proto(id: SaId, km: &KeyMaterial) -> proto::SecurityAssociation {
    proto::SecurityAssociation {
        id: Some(id.to_proto()),
        algorithm: proto::Algorithm::Aes256Gcm.into(),
        key: km.key.to_vec(),
        salt: km.salt.to_vec(),
        esn: true,
        replay_window: if id.egress { 0 } else { REPLAY_WINDOW },
    }
}

// ------------------------------------------------------------------------------------------------
// gRPC service
// ------------------------------------------------------------------------------------------------

type StepTx = mpsc::UnboundedSender<Result<proto::Step, Status>>;

enum Event {
    Init { name: String, prefix: HostPrefix, reply: oneshot::Sender<Result<(), Status>> },
    Subscribe { vni: u32, reply: oneshot::Sender<Result<(), Status>> },
    Unsubscribe { vni: u32, reply: oneshot::Sender<Result<(), Status>> },
    DataplaneReset { reply: oneshot::Sender<Result<(), Status>> },
    Status { reply: oneshot::Sender<proto::StatusResponse> },
    WatchOpened { watch: u64, inventory: Vec<proto::SecurityAssociationId>, tx: StepTx },
    Confirmed { watch: u64, step: u64, error: String },
    WatchClosed { watch: u64 },
    ServerConnecting { conn: u64, tx: mpsc::UnboundedSender<proto::ClientMessage> },
    FromServer { conn: u64, msg: server_message::Message },
    ServerDisconnected { conn: u64 },
}

/// Starts the client's state machine and returns its API service.
pub fn start(config: Config) -> ClientApiServer<ApiService> {
    let (events, rx) = mpsc::unbounded_channel();
    tokio::spawn(Core::new(config, events.clone()).run(rx));
    ClientApiServer::new(ApiService { events, next_watch: Arc::new(AtomicU64::new(1)) })
}

pub struct ApiService {
    events: mpsc::UnboundedSender<Event>,
    next_watch: Arc<AtomicU64>,
}

impl ApiService {
    async fn ask<T>(&self, ev: impl FnOnce(oneshot::Sender<T>) -> Event) -> Result<T, Status> {
        let (tx, rx) = oneshot::channel();
        self.events.send(ev(tx)).map_err(|_| Status::unavailable("shutting down"))?;
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
impl ClientApi for ApiService {
    async fn init(&self, req: Request<proto::InitRequest>) -> Result<Response<proto::InitResponse>, Status> {
        let req = req.into_inner();
        let prefix: HostPrefix = req.host_prefix.parse().map_err(Status::invalid_argument)?;
        self.ask(|reply| Event::Init { name: req.client_name, prefix, reply }).await??;
        Ok(Response::new(proto::InitResponse {}))
    }

    async fn subscribe(&self, req: Request<proto::SubscribeRequest>) -> Result<Response<proto::SubscribeResponse>, Status> {
        let vni = req.into_inner().vni;
        check_vni(vni)?;
        self.ask(|reply| Event::Subscribe { vni, reply }).await??;
        Ok(Response::new(proto::SubscribeResponse {}))
    }

    async fn unsubscribe(&self, req: Request<proto::UnsubscribeRequest>) -> Result<Response<proto::UnsubscribeResponse>, Status> {
        let vni = req.into_inner().vni;
        check_vni(vni)?;
        self.ask(|reply| Event::Unsubscribe { vni, reply }).await??;
        Ok(Response::new(proto::UnsubscribeResponse {}))
    }

    async fn dataplane_reset(&self, _: Request<proto::DataplaneResetRequest>) -> Result<Response<proto::DataplaneResetResponse>, Status> {
        self.ask(|reply| Event::DataplaneReset { reply }).await??;
        Ok(Response::new(proto::DataplaneResetResponse {}))
    }

    async fn status(&self, _: Request<proto::StatusRequest>) -> Result<Response<proto::StatusResponse>, Status> {
        Ok(Response::new(self.ask(|reply| Event::Status { reply }).await?))
    }

    type WatchSecurityAssociationsStream = Pin<Box<dyn Stream<Item = Result<proto::Step, Status>> + Send>>;

    async fn watch_security_associations(
        &self,
        req: Request<Streaming<proto::WatchRequest>>,
    ) -> Result<Response<Self::WatchSecurityAssociationsStream>, Status> {
        let mut inbound = req.into_inner();
        let inventory = match inbound.message().await?.and_then(|r| r.request) {
            Some(watch_request::Request::Inventory(inv)) => inv.ids,
            _ => return Err(Status::invalid_argument("the stream must start with the inventory")),
        };
        let watch = self.next_watch.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        let events = self.events.clone();
        events.send(Event::WatchOpened { watch, inventory, tx }).map_err(|_| Status::unavailable("shutting down"))?;
        tokio::spawn(async move {
            while let Ok(Some(r)) = inbound.message().await {
                if let Some(watch_request::Request::Confirmation(c)) = r.request {
                    let _ = events.send(Event::Confirmed { watch, step: c.step, error: c.error });
                }
            }
            let _ = events.send(Event::WatchClosed { watch });
        });
        Ok(Response::new(Box::pin(UnboundedReceiverStream::new(rx))))
    }
}

/// Keeps one delivery stream to the server open, reconnecting every second.
async fn server_connection(server: String, conn: u64, events: mpsc::UnboundedSender<Event>) {
    let url = if server.contains("://") { server } else { format!("http://{server}") };
    loop {
        let (tx, rx) = mpsc::unbounded_channel();
        if events.send(Event::ServerConnecting { conn, tx }).is_err() {
            return;
        }
        let res: Result<()> = async {
            let channel = Endpoint::from_shared(url.clone())?
                .connect_timeout(Duration::from_secs(2))
                .http2_keep_alive_interval(Duration::from_secs(5))
                .keep_alive_timeout(Duration::from_secs(5))
                .keep_alive_while_idle(true)
                .connect()
                .await?;
            let mut inbound = DeliveryClient::new(channel).stream(UnboundedReceiverStream::new(rx)).await?.into_inner();
            while let Some(m) = inbound.message().await? {
                if let Some(msg) = m.message {
                    if events.send(Event::FromServer { conn, msg }).is_err() {
                        return Ok(());
                    }
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = res {
            debug!("mlsbond server {url}: {e}");
        }
        if events.send(Event::ServerDisconnected { conn }).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

// ------------------------------------------------------------------------------------------------
// State
// ------------------------------------------------------------------------------------------------

/// A Security Association the orchestrator holds, with the epoch it was derived from. Generation
/// counts this client's VNI groups of one VNI, so that epochs of a regrouped VNI compare as newer;
/// 0 is an association known only from the orchestrator's inventory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Installed {
    id: SaId,
    generation: u64,
    epoch: u64,
}

impl Installed {
    fn at(&self) -> (u64, u64) {
        (self.generation, self.epoch)
    }
}

/// The epoch a pair is moving to, with the key material derived from it.
struct Target {
    generation: u64,
    epoch: u64,
    ingress: KeyMaterial,
    egress: KeyMaterial,
    ingress_spi: Option<u32>,
}

impl Target {
    fn at(&self) -> (u64, u64) {
        (self.generation, self.epoch)
    }
}

#[derive(Clone, Copy, Debug)]
enum Action {
    AddIngress { sa: SaId, generation: u64, epoch: u64 },
    SetEgress { old: Option<SaId>, sa: SaId, generation: u64, epoch: u64 },
    Remove { sa: SaId },
}

struct Inflight {
    step: u64,
    action: Action,
}

/// Two hosts in one VNI group, from this host's side.
struct Pair {
    egress: Option<Installed>,
    ingress: Vec<Installed>,
    target: Option<Target>,
    /// the latest Ready of the peer: (generation, epoch, the SPI to send under)
    peer_ready: Option<(u64, u64, u32)>,
    /// the latest Switched of the peer
    peer_switched: Option<(u64, u64)>,
    /// the pair ended: remove everything
    ending: bool,
    /// a pair from before a (re)join, ended unless its peer joins until then
    stale_at: Option<Instant>,
    inflight: Option<Inflight>,
    retry_at: Option<Instant>,
    backoff: Duration,
    last_error: String,
}

impl Pair {
    fn new() -> Pair {
        Pair {
            egress: None,
            ingress: Vec::new(),
            target: None,
            peer_ready: None,
            peer_switched: None,
            ending: false,
            stale_at: None,
            inflight: None,
            retry_at: None,
            backoff: BACKOFF_START,
            last_error: String::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.egress.is_none() && self.ingress.is_empty() && self.inflight.is_none()
    }

    /// The next step to carry out, in the safe order.
    fn next_action(&self, vni: u32, me: HostPrefix, peer: HostPrefix) -> Option<Action> {
        if self.ending {
            return self.egress.iter().chain(self.ingress.iter()).next().map(|i| Action::Remove { sa: i.id });
        }
        let t = self.target.as_ref()?;
        if !self.ingress.iter().any(|i| i.at() == t.at()) {
            let spi = t.ingress_spi?;
            return Some(Action::AddIngress { sa: SaId { vni, spi, egress: false, src: peer, dst: me }, generation: t.generation, epoch: t.epoch });
        }
        if let Some((generation, epoch, spi)) = self.peer_ready {
            if (generation, epoch) == t.at() && self.egress.is_none_or(|e| e.at() != t.at()) {
                let sa = SaId { vni, spi, egress: true, src: me, dst: peer };
                return Some(Action::SetEgress { old: self.egress.map(|e| e.id), sa, generation, epoch });
            }
        }
        if let Some(switched) = self.peer_switched {
            if let Some(old) = self.ingress.iter().find(|i| i.at() < switched) {
                return Some(Action::Remove { sa: old.id });
            }
        }
        None
    }

    fn waiting(&self) -> proto::Waiting {
        use proto::Waiting as W;
        if let Some(f) = &self.inflight {
            return match f.action {
                Action::AddIngress { .. } => W::Ingress,
                Action::SetEgress { .. } => W::Egress,
                Action::Remove { .. } => W::Remove,
            };
        }
        if self.ending {
            return W::Remove;
        }
        let Some(t) = &self.target else { return W::Nothing };
        if !self.ingress.iter().any(|i| i.at() == t.at()) {
            return W::Ingress;
        }
        if self.egress.is_none_or(|e| e.at() != t.at()) {
            return match self.peer_ready {
                Some((generation, epoch, _)) if (generation, epoch) == t.at() => W::Egress,
                _ => W::PeerReady,
            };
        }
        if self.ingress.iter().any(|i| i.at() < t.at()) {
            return W::PeerSwitched;
        }
        W::Nothing
    }
}

/// This host's view of one subscribed VNI.
struct Group {
    /// generation of the MLS group, see Installed
    generation: u64,
    /// None until the server had this client create the group or welcomed it
    mls: Option<MlsGroup>,
    last_seq: u64,
    /// the commit sent for a CommitWork, until it comes back in the log
    pending_commit: Option<PendingCommit>,
    /// group messages not yet accepted by the server
    outbox: VecDeque<proto::GroupMessage>,
}

struct PendingCommit {
    work: u64,
    scope: proto::Scope,
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

impl Group {
    fn new() -> Group {
        Group { generation: 0, mls: None, last_seq: 0, pending_commit: None, outbox: VecDeque::new() }
    }
}

struct Watch {
    id: u64,
    tx: StepTx,
}

struct Core {
    config: Config,
    events: mpsc::UnboundedSender<Event>,
    name: String,
    identity: Option<Identity>,
    instance: u64,
    conn: u64,
    conn_task: Option<AbortHandle>,
    server_tx: Option<mpsc::UnboundedSender<proto::ClientMessage>>,
    /// HelloAck received on the current stream
    connected: bool,
    boot_id: Option<String>,
    vnis: BTreeSet<u32>,
    /// VNIs left while the server was away
    leaving: BTreeSet<u32>,
    reset_pending: bool,
    groups: BTreeMap<u32, Group>,
    /// last generation per VNI, kept across groups
    generations: HashMap<u32, u64>,
    pairs: BTreeMap<(u32, HostPrefix), Pair>,
    watch: Option<Watch>,
    next_step: u64,
    next_msg_id: u64,
    /// SPIs that may still be installed without this client knowing
    avoid_spis: HashSet<u32>,
    /// Ready and Switched to send, per (vni, generation, epoch)
    ready: BTreeMap<(u32, u64, u64), Vec<(HostPrefix, u32)>>,
    switched: BTreeMap<(u32, u64, u64), Vec<HostPrefix>>,
}

impl Core {
    fn new(config: Config, events: mpsc::UnboundedSender<Event>) -> Core {
        Core {
            config,
            events,
            name: String::new(),
            identity: None,
            instance: 0,
            conn: 0,
            conn_task: None,
            server_tx: None,
            connected: false,
            boot_id: None,
            vnis: BTreeSet::new(),
            leaving: BTreeSet::new(),
            reset_pending: false,
            groups: BTreeMap::new(),
            generations: HashMap::new(),
            pairs: BTreeMap::new(),
            watch: None,
            next_step: 1,
            next_msg_id: 1,
            avoid_spis: HashSet::new(),
            ready: BTreeMap::new(),
            switched: BTreeMap::new(),
        }
    }

    async fn run(mut self, mut events: mpsc::UnboundedReceiver<Event>) {
        loop {
            let wake = self.next_wake();
            tokio::select! {
                ev = events.recv() => match ev {
                    Some(ev) => self.handle(ev),
                    None => return,
                },
                _ = tokio::time::sleep_until(wake.into()) => {}
            }
            self.expire_stale_pairs();
            self.flush_group_messages();
            self.drive();
        }
    }

    fn me(&self) -> HostPrefix {
        self.identity.as_ref().expect("initialized").prefix
    }

    fn next_wake(&self) -> Instant {
        let far = Instant::now() + Duration::from_secs(3600);
        // retries only matter while the orchestrator is there to carry them out
        let watching = self.watch.is_some();
        self.pairs
            .values()
            .flat_map(|p| [p.retry_at.filter(|_| watching && p.inflight.is_none()), p.stale_at])
            .flatten()
            .min()
            .unwrap_or(far)
            .min(far)
    }

    fn handle(&mut self, ev: Event) {
        match ev {
            Event::Init { name, prefix, reply } => {
                let _ = reply.send(self.init(name, prefix));
            }
            Event::Subscribe { vni, reply } => {
                let _ = reply.send(self.subscribe(vni));
            }
            Event::Unsubscribe { vni, reply } => {
                self.unsubscribe(vni);
                let _ = reply.send(Ok(()));
            }
            Event::DataplaneReset { reply } => {
                self.dataplane_reset();
                let _ = reply.send(Ok(()));
            }
            Event::Status { reply } => {
                let _ = reply.send(self.status());
            }
            Event::WatchOpened { watch, inventory, tx } => self.watch_opened(watch, inventory, tx),
            Event::Confirmed { watch, step, error } => {
                if self.watch.as_ref().is_some_and(|w| w.id == watch) {
                    self.confirmed(step, error);
                }
            }
            Event::WatchClosed { watch } => {
                if self.watch.as_ref().is_some_and(|w| w.id == watch) {
                    info!("orchestrator disconnected");
                    self.watch = None;
                }
            }
            Event::ServerConnecting { conn, tx } if conn == self.conn => {
                self.connected = false;
                let hello = proto::Hello {
                    client_name: self.name.clone(),
                    host_prefix: self.me().to_string(),
                    instance: self.instance,
                    last_boot_id: self.boot_id.clone().unwrap_or_default(),
                };
                let _ = tx.send(cmsg(client_message::Message::Hello(hello)));
                self.server_tx = Some(tx);
            }
            Event::FromServer { conn, msg } if conn == self.conn => {
                if let Err(e) = self.server_message(msg) {
                    error!("{e:#}");
                }
            }
            Event::ServerDisconnected { conn } if conn == self.conn => {
                if self.connected {
                    warn!("mlsbond server disconnected");
                }
                self.connected = false;
                self.server_tx = None;
            }
            _ => {}
        }
    }

    // --------------------------------------------------------------------------------------------
    // Client API
    // --------------------------------------------------------------------------------------------

    fn init(&mut self, name: String, prefix: HostPrefix) -> Result<(), Status> {
        if let Some(id) = &self.identity {
            if id.prefix == prefix {
                self.name = name;
                return Ok(());
            }
            if !self.vnis.is_empty() {
                return Err(Status::failed_precondition(format!("host prefix is {}, cannot change it while VNIs are subscribed", id.prefix)));
            }
        }
        info!("host {name}, host prefix {prefix}");
        self.identity = Some(Identity::new(prefix).map_err(|e| Status::internal(e.to_string()))?);
        self.name = name;
        self.instance = rand::random();
        self.groups.clear();
        self.leaving.clear();
        self.reset_pending = false;
        self.pairs.clear();
        if let Some(t) = self.conn_task.take() {
            t.abort();
        }
        self.conn += 1;
        self.connected = false;
        self.server_tx = None;
        let task = tokio::spawn(server_connection(self.config.server.clone(), self.conn, self.events.clone()));
        self.conn_task = Some(task.abort_handle());
        Ok(())
    }

    fn subscribe(&mut self, vni: u32) -> Result<(), Status> {
        if self.identity.is_none() {
            return Err(Status::failed_precondition("Init first"));
        }
        if !self.vnis.insert(vni) {
            return Ok(());
        }
        info!("vni {vni}: subscribed");
        self.leaving.remove(&vni);
        self.groups.insert(vni, Group::new());
        self.send(client_message::Message::Join(proto::Join { vni }));
        Ok(())
    }

    fn unsubscribe(&mut self, vni: u32) {
        if !self.vnis.remove(&vni) {
            return;
        }
        info!("vni {vni}: unsubscribed, removing its Security Associations");
        if let Some(mut g) = self.groups.remove(&vni) {
            self.delete_mls(&mut g);
        }
        if self.connected {
            self.send(client_message::Message::Leave(proto::Leave { vni }));
        } else {
            self.leaving.insert(vni);
        }
        for ((_, _), p) in self.pairs.range_mut((vni, HostPrefix::MIN)..=(vni, HostPrefix::MAX)) {
            end_pair(p);
        }
    }

    fn dataplane_reset(&mut self) {
        info!("dataplane reset: all Security Associations are gone, rekeying every pair");
        for p in self.pairs.values_mut() {
            if let Some(f) = p.inflight.take() {
                // carried out or not, it may be in the new dataplane
                if let Action::AddIngress { sa, .. } = f.action {
                    self.avoid_spis.insert(sa.spi);
                }
            }
            p.egress = None;
            p.ingress.clear();
            p.target = None;
            p.peer_ready = None;
            p.peer_switched = None;
            p.retry_at = None;
            p.backoff = BACKOFF_START;
            p.last_error.clear();
        }
        self.pairs.retain(|_, p| !p.ending);
        self.reset_pending = true;
        if self.connected {
            self.send_reset();
        }
    }

    fn send_reset(&mut self) {
        self.reset_pending = false;
        self.send(client_message::Message::ResetRequest(proto::ResetRequest {}));
    }

    fn status(&self) -> proto::StatusResponse {
        let pairs = self
            .pairs
            .iter()
            .map(|((vni, peer), p)| {
                let generation = self.groups.get(vni).map(|g| g.generation).unwrap_or(0);
                let settled = p.waiting() == proto::Waiting::Nothing;
                proto::PairStatus {
                    vni: *vni,
                    peer_host_prefix: peer.to_string(),
                    pair_epoch: p.egress.filter(|e| e.generation == generation && generation > 0).map(|e| e.epoch),
                    target_epoch: p.target.as_ref().filter(|_| !settled).map(|t| t.epoch),
                    waiting: p.waiting().into(),
                    last_error: p.last_error.clone(),
                    egress_spi: p.egress.map(|e| e.id.spi).unwrap_or(0),
                    ingress_spis: p.ingress.iter().map(|i| i.id.spi).collect(),
                }
            })
            .collect();
        proto::StatusResponse {
            client_name: self.name.clone(),
            host_prefix: self.identity.as_ref().map(|i| i.prefix.to_string()).unwrap_or_default(),
            vnis: self.vnis.iter().copied().collect(),
            server_connected: self.connected,
            server_boot_id: self.boot_id.clone().unwrap_or_default(),
            orchestrator_connected: self.watch.is_some(),
            pairs,
        }
    }

    // --------------------------------------------------------------------------------------------
    // Orchestrator stream
    // --------------------------------------------------------------------------------------------

    fn watch_opened(&mut self, watch: u64, inventory: Vec<proto::SecurityAssociationId>, tx: StepTx) {
        info!("orchestrator connected, holding {} Security Associations", inventory.len());
        self.watch = Some(Watch { id: watch, tx });
        let Some(identity) = &self.identity else { return };
        let me = identity.prefix;
        let held: HashSet<SaId> = inventory.iter().filter_map(SaId::from_proto).collect();
        for sa in &held {
            if !sa.egress {
                self.avoid_spis.insert(sa.spi);
            }
        }

        // steps of the previous stream: the inventory tells which were carried out
        let mut known = HashSet::new();
        let keys: Vec<(u32, HostPrefix)> = self.pairs.keys().copied().collect();
        for key in &keys {
            let p = self.pairs.get_mut(key).unwrap();
            if let Some(f) = p.inflight.take() {
                let done = match f.action {
                    Action::AddIngress { sa, .. } => held.contains(&sa),
                    Action::SetEgress { old, sa, .. } => {
                        if !held.contains(&sa) && old.is_some_and(|o| !held.contains(&o)) {
                            p.egress = None;
                        }
                        held.contains(&sa)
                    }
                    Action::Remove { sa } => !held.contains(&sa),
                };
                if done {
                    self.succeeded(*key, f.action);
                }
            }
            let p = &self.pairs[key];
            known.extend(p.egress.iter().chain(p.ingress.iter()).map(|i| i.id));
        }

        // associations this client does not know: from before it restarted or regrouped
        for sa in held.difference(&known) {
            let (peer, ok) = if sa.egress { (sa.dst, sa.src == me) } else { (sa.src, sa.dst == me) };
            if !ok {
                warn!("inventory: {sa:?} is not this host's, ignoring it");
                continue;
            }
            let p = self.pairs.entry((sa.vni, peer)).or_insert_with(Pair::new);
            let installed = Installed { id: *sa, generation: 0, epoch: 0 };
            if !self.vnis.contains(&sa.vni) || self.groups.get(&sa.vni).is_none_or(|g| g.mls.is_none()) {
                // the pair's peer is not known yet
                p.stale_at.get_or_insert(Instant::now() + self.config.stale_pairs_after);
            }
            if sa.egress {
                if p.egress.is_some() {
                    warn!("inventory: a second egress {sa:?}, removing it");
                    p.ingress.push(installed);
                } else {
                    p.egress = Some(installed);
                }
            } else {
                p.ingress.push(installed);
            }
        }
    }

    fn confirmed(&mut self, step: u64, error: String) {
        let Some((&key, _)) = self.pairs.iter().find(|(_, p)| p.inflight.as_ref().is_some_and(|f| f.step == step)) else {
            return;
        };
        let p = self.pairs.get_mut(&key).unwrap();
        let f = p.inflight.take().unwrap();
        if error.is_empty() {
            p.retry_at = None;
            p.backoff = BACKOFF_START;
            p.last_error.clear();
            self.succeeded(key, f.action);
        } else {
            warn!("vni {}: step {step} for {} failed, retrying in {:?}: {error}", key.0, key.1, p.backoff);
            p.retry_at = Some(Instant::now() + p.backoff);
            p.backoff = (p.backoff * 2).min(BACKOFF_MAX);
            p.last_error = error;
        }
    }

    fn succeeded(&mut self, (vni, peer): (u32, HostPrefix), action: Action) {
        let p = self.pairs.get_mut(&(vni, peer)).unwrap();
        match action {
            Action::AddIngress { sa, generation, epoch } => {
                p.ingress.push(Installed { id: sa, generation, epoch });
                if p.target.as_ref().is_some_and(|t| t.at() == (generation, epoch)) {
                    self.ready.entry((vni, generation, epoch)).or_default().push((peer, sa.spi));
                }
            }
            Action::SetEgress { sa, generation, epoch, .. } => {
                info!("vni {vni}: egress towards {peer} switched to epoch {epoch}");
                p.egress = Some(Installed { id: sa, generation, epoch });
                self.switched.entry((vni, generation, epoch)).or_default().push(peer);
            }
            Action::Remove { sa } => {
                p.ingress.retain(|i| i.id != sa);
                if p.egress.is_some_and(|e| e.id == sa) {
                    p.egress = None;
                }
            }
        }
    }

    /// Sends every pair's next step that may go now.
    fn drive(&mut self) {
        let Some(watch) = &self.watch else { return };
        let Some(identity) = &self.identity else { return };
        let me = identity.prefix;
        let now = Instant::now();
        let mut used: HashSet<u32> = self.avoid_spis.clone();
        for p in self.pairs.values() {
            used.extend(p.ingress.iter().map(|i| i.id.spi));
            used.extend(p.target.as_ref().and_then(|t| t.ingress_spi));
        }
        for (&(vni, peer), p) in self.pairs.iter_mut() {
            if p.inflight.is_some() || p.retry_at.is_some_and(|t| t > now) {
                continue;
            }
            if let Some(t) = p.target.as_mut() {
                if t.ingress_spi.is_none() && !p.ending {
                    let spi = mls::pick_spi(|s| used.contains(&s), rand::random);
                    used.insert(spi);
                    t.ingress_spi = Some(spi);
                }
            }
            let Some(action) = p.next_action(vni, me, peer) else { continue };
            let step = self.next_step;
            self.next_step += 1;
            let a = match action {
                Action::AddIngress { sa, .. } => {
                    step::Action::Add(proto::AddSecurityAssociation { sa: Some(sa_proto(sa, &p.target.as_ref().unwrap().ingress)) })
                }
                Action::SetEgress { old: None, sa, .. } => {
                    step::Action::Add(proto::AddSecurityAssociation { sa: Some(sa_proto(sa, &p.target.as_ref().unwrap().egress)) })
                }
                Action::SetEgress { old: Some(old), sa, .. } => step::Action::Update(proto::UpdateSecurityAssociation {
                    old: Some(old.to_proto()),
                    new: Some(sa_proto(sa, &p.target.as_ref().unwrap().egress)),
                }),
                Action::Remove { sa } => step::Action::Remove(proto::RemoveSecurityAssociation { id: Some(sa.to_proto()) }),
            };
            debug!("vni {vni}: step {step} for {peer}: {action:?}");
            let _ = watch.tx.send(Ok(proto::Step { step, action: Some(a) }));
            p.inflight = Some(Inflight { step, action });
            p.retry_at = None;
        }
        self.pairs.retain(|_, p| !(p.ending && p.is_empty()));
    }

    fn expire_stale_pairs(&mut self) {
        let now = Instant::now();
        for ((vni, peer), p) in self.pairs.iter_mut() {
            if p.stale_at.is_some_and(|t| t <= now) {
                info!("vni {vni}: {peer} did not join again, removing the pair");
                p.stale_at = None;
                end_pair(p);
            }
        }
    }

    // --------------------------------------------------------------------------------------------
    // Server stream
    // --------------------------------------------------------------------------------------------

    fn send(&self, m: client_message::Message) {
        if let Some(tx) = &self.server_tx {
            if self.connected || matches!(m, client_message::Message::Hello(_)) {
                let _ = tx.send(cmsg(m));
            }
        }
    }

    fn server_message(&mut self, m: server_message::Message) -> Result<()> {
        use server_message::Message as M;
        match m {
            M::HelloAck(ack) => self.hello_ack(ack.boot_id, ack.key_packages as usize)?,
            M::CreateGroup(c) => self.create_group(c.vni)?,
            M::Welcomed(w) => self.welcomed(w)?,
            M::Entry(e) => {
                let vni = e.vni;
                if let Err(err) = self.entry(e) {
                    error!("vni {vni}: {err:#}, joining the VNI group again");
                    self.rejoin(vni);
                }
            }
            M::CommitWork(w) => {
                let vni = w.vni;
                if let Err(err) = self.commit_work(w) {
                    error!("vni {vni}: cannot commit: {err:#}");
                }
            }
            M::Rejoin(r) => self.rejoin(r.vni),
            M::KeyPackagesUsed(u) => self.upload_key_packages(u.count as usize)?,
            M::Accepted(a) => {
                if let Some(g) = self.groups.get_mut(&a.vni) {
                    g.outbox.retain(|m| m.id != a.id);
                }
            }
            M::ProposeUpdate(p) => self.propose_update(p)?,
        }
        Ok(())
    }

    fn hello_ack(&mut self, boot_id: String, key_packages: usize) -> Result<()> {
        info!("connected to the mlsbond server (boot ID {boot_id})");
        self.connected = true;
        if self.boot_id.as_ref().is_some_and(|b| *b != boot_id) {
            info!("the mlsbond server restarted, regrouping every VNI");
            let vnis: Vec<u32> = self.groups.keys().copied().collect();
            for vni in vnis {
                let mut g = self.groups.insert(vni, Group::new()).unwrap();
                self.delete_mls(&mut g);
            }
        }
        self.boot_id = Some(boot_id);
        // the server keeps those of this process across a reconnect
        self.upload_key_packages(self.config.key_packages.saturating_sub(key_packages))?;
        for vni in std::mem::take(&mut self.leaving) {
            self.send(client_message::Message::Leave(proto::Leave { vni }));
        }
        let vnis: Vec<u32> = self.vnis.iter().copied().collect();
        for vni in vnis {
            let g = &self.groups[&vni];
            if g.mls.is_some() {
                self.send(client_message::Message::Resume(proto::Resume { vni, last_seq: g.last_seq }));
                for m in g.outbox.clone() {
                    self.send(client_message::Message::GroupMessage(m));
                }
            } else {
                self.send(client_message::Message::Join(proto::Join { vni }));
            }
        }
        if self.reset_pending {
            self.send_reset();
        }
        Ok(())
    }

    fn upload_key_packages(&mut self, count: usize) -> Result<()> {
        let identity = self.identity.as_ref().expect("initialized");
        let kps = (0..count).map(|_| identity.key_package()).collect::<Result<Vec<_>>>()?;
        self.send(client_message::Message::KeyPackages(proto::KeyPackages { key_packages: kps }));
        Ok(())
    }

    fn next_generation(&mut self, vni: u32) -> u64 {
        let generation = self.generations.entry(vni).or_default();
        *generation += 1;
        *generation
    }

    fn create_group(&mut self, vni: u32) -> Result<()> {
        if !self.vnis.contains(&vni) {
            return Ok(());
        }
        let mls = self.identity.as_ref().unwrap().create_group()?;
        let generation = self.next_generation(vni);
        let mut g = Group::new();
        g.generation = generation;
        g.mls = Some(mls);
        if let Some(mut old) = self.groups.insert(vni, g) {
            self.delete_mls(&mut old);
        }
        info!("vni {vni}: created the VNI group");
        self.send(client_message::Message::GroupCreated(proto::GroupCreated { vni }));
        self.mark_stale(vni);
        Ok(())
    }

    fn welcomed(&mut self, w: proto::Welcomed) -> Result<()> {
        if !self.vnis.contains(&w.vni) {
            // added by a commit under way when this host unsubscribed: leave again
            self.send(client_message::Message::Leave(proto::Leave { vni: w.vni }));
            return Ok(());
        }
        let mls = self.identity.as_ref().unwrap().join(&w.welcome)?;
        let generation = self.next_generation(w.vni);
        info!("vni {}: joined the VNI group in epoch {}", w.vni, mls.epoch().as_u64());
        let mut g = Group::new();
        g.generation = generation;
        g.mls = Some(mls);
        g.last_seq = w.seq;
        if let Some(mut old) = self.groups.insert(w.vni, g) {
            self.delete_mls(&mut old);
        }
        self.send(client_message::Message::Ack(proto::Ack { vni: w.vni, seq: w.seq }));
        self.apply_moves(w.vni, None, &proto::Scope::default())?;
        self.mark_stale(w.vni);
        Ok(())
    }

    /// After a (re)join: pairs whose peer is not in the group end unless it joins in time.
    fn mark_stale(&mut self, vni: u32) {
        let members = self.groups[&vni].mls.as_ref().map(mls::members).unwrap_or_default();
        let at = Instant::now() + self.config.stale_pairs_after;
        for ((_, peer), p) in self.pairs.range_mut((vni, HostPrefix::MIN)..=(vni, HostPrefix::MAX)) {
            if !members.contains_key(peer) && !p.ending {
                p.stale_at.get_or_insert(at);
            }
        }
    }

    fn rejoin(&mut self, vni: u32) {
        let Some(mut g) = self.groups.insert(vni, Group::new()) else { return };
        self.delete_mls(&mut g);
        if self.vnis.contains(&vni) {
            info!("vni {vni}: joining the VNI group again");
            self.send(client_message::Message::Join(proto::Join { vni }));
        } else {
            self.groups.remove(&vni);
        }
    }

    fn delete_mls(&self, g: &mut Group) {
        if let (Some(mls), Some(identity)) = (g.mls.as_mut(), &self.identity) {
            let _ = mls.delete(identity.provider.storage());
        }
        g.mls = None;
    }

    fn entry(&mut self, e: proto::Entry) -> Result<()> {
        let vni = e.vni;
        let Some(g) = self.groups.get_mut(&vni) else { return Ok(()) };
        if g.mls.is_none() || e.seq <= g.last_seq {
            return Ok(());
        }
        g.last_seq = e.seq;
        match e.kind {
            Some(entry::Kind::Commit(c)) => self.commit_entry(vni, c)?,
            Some(entry::Kind::Message(m)) => self.message_entry(vni, m)?,
            None => {}
        }
        self.send(client_message::Message::Ack(proto::Ack { vni, seq: e.seq }));
        Ok(())
    }

    fn commit_entry(&mut self, vni: u32, c: proto::CommitEntry) -> Result<()> {
        let identity = self.identity.as_ref().unwrap();
        let g = self.groups.get_mut(&vni).unwrap();
        let mls = g.mls.as_mut().unwrap();
        let before = mls::members(mls);
        let scope = match g.pending_commit.take() {
            Some(p) if p.work == c.work => {
                mls.merge_pending_commit(&identity.provider).map_err(|e| anyhow!("merging own commit: {e:?}"))?;
                p.scope
            }
            _ => {
                mls.clear_pending_commit(identity.provider.storage()).map_err(|e| anyhow!("{e:?}"))?;
                let msg = MlsMessageIn::tls_deserialize_exact(&c.commit)?.try_into_protocol_message().map_err(|e| anyhow!("{e:?}"))?;
                let processed = mls.process_message(&identity.provider, msg).map_err(|e| anyhow!("commit by {}: {e:?}", c.committer))?;
                let scope = proto::Scope::decode(processed.aad()).unwrap_or_default();
                let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
                    return Err(anyhow!("entry from {} is not a commit", c.committer));
                };
                if staged.self_removed() {
                    info!("vni {vni}: removed from the VNI group by {}", c.committer);
                    self.rejoin(vni);
                    return Ok(());
                }
                mls.merge_staged_commit(&identity.provider, *staged).map_err(|e| anyhow!("merging commit: {e:?}"))?;
                scope
            }
        };
        info!("vni {vni}: epoch {} by {}", mls.epoch().as_u64(), c.committer);
        self.apply_moves(vni, Some(&before), &scope)
    }

    /// Sets the pairs a commit (or joining, without `before`) moves on their way to the current
    /// epoch, and ends those of members that left.
    fn apply_moves(&mut self, vni: u32, before: Option<&BTreeMap<HostPrefix, (LeafNodeIndex, Vec<u8>)>>, scope: &proto::Scope) -> Result<()> {
        let identity = self.identity.as_ref().unwrap();
        let me = identity.prefix;
        let g = &self.groups[&vni];
        let mls = g.mls.as_ref().unwrap();
        let (generation, epoch) = (g.generation, mls.epoch().as_u64());
        let after = mls::members(mls);
        let scoped: Option<HostPrefix> = scope.host_prefix.parse().ok();
        let all = scope.kind() == proto::ScopeKind::ScopeAll;
        for (peer, (_, sig)) in after.iter().filter(|(p, _)| **p != me) {
            let new_leaf = before.is_none_or(|b| b.get(peer).is_none_or(|(_, s)| s != sig));
            let host = scope.kind() == proto::ScopeKind::ScopeHost && (scoped == Some(me) || scoped == Some(*peer));
            if !(new_leaf || all || host) {
                continue;
            }
            let ingress = mls::derive_sa(mls, &identity.provider, vni, *peer, me)?;
            let egress = mls::derive_sa(mls, &identity.provider, vni, me, *peer)?;
            let p = self.pairs.entry((vni, *peer)).or_insert_with(Pair::new);
            info!("vni {vni}: pair with {peer} moves to epoch {epoch}");
            p.target = Some(Target { generation, epoch, ingress, egress, ingress_spi: None });
            p.ending = false;
            p.stale_at = None;
        }
        if let Some(before) = before {
            for peer in before.keys().filter(|p| **p != me && !after.contains_key(p)) {
                if let Some(p) = self.pairs.get_mut(&(vni, *peer)) {
                    info!("vni {vni}: {peer} left, removing the pair");
                    end_pair(p);
                }
            }
        }
        Ok(())
    }

    fn message_entry(&mut self, vni: u32, m: proto::GroupMessage) -> Result<()> {
        let identity = self.identity.as_ref().unwrap();
        let me = identity.prefix;
        let g = self.groups.get_mut(&vni).unwrap();
        let generation = g.generation;
        let mls = g.mls.as_mut().unwrap();
        let msg = MlsMessageIn::tls_deserialize_exact(&m.message)?.try_into_protocol_message().map_err(|e| anyhow!("{e:?}"))?;
        let processed = match mls.process_message(&identity.provider, msg) {
            Ok(p) => p,
            Err(e) => {
                // not fatal: a message of an epoch long gone stalls one pair at worst
                warn!("vni {vni}: cannot process a group message: {e:?}");
                return Ok(());
            }
        };
        let Some(sender) = mls::credential_prefix(processed.credential()) else {
            return Err(anyhow!("group message without a host prefix"));
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                let app = proto::GroupApplication::decode(app.into_bytes().as_slice())?;
                match app.message {
                    Some(group_application::Message::Ready(r)) => {
                        for s in r.spis.iter().filter(|s| HostPrefix::from_underlay_bytes(&s.peer_underlay) == Some(me)) {
                            debug!("vni {vni}: {sender} is ready in epoch {}, send under SPI {}", r.epoch, s.spi);
                            let p = self.pairs.entry((vni, sender)).or_insert_with(Pair::new);
                            if p.peer_ready.is_none_or(|(g, e, _)| (g, e) < (generation, r.epoch)) {
                                p.peer_ready = Some((generation, r.epoch, s.spi));
                            }
                        }
                    }
                    Some(group_application::Message::Switched(s)) => {
                        if s.peer_underlays.iter().any(|u| HostPrefix::from_underlay_bytes(u) == Some(me)) {
                            debug!("vni {vni}: {sender} switched to epoch {}", s.epoch);
                            if let Some(p) = self.pairs.get_mut(&(vni, sender)) {
                                if p.peer_switched.is_none_or(|at| at < (generation, s.epoch)) {
                                    p.peer_switched = Some((generation, s.epoch));
                                }
                            }
                        }
                    }
                    None => {}
                }
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                mls.store_pending_proposal(identity.provider.storage(), *proposal).map_err(|e| anyhow!("{e:?}"))?;
            }
            _ => warn!("vni {vni}: unexpected group message from {sender}"),
        }
        Ok(())
    }

    fn commit_work(&mut self, w: proto::CommitWork) -> Result<()> {
        let identity = self.identity.as_ref().unwrap();
        let Some(g) = self.groups.get_mut(&w.vni) else { return Ok(()) };
        let Some(mls) = g.mls.as_mut() else { return Ok(()) };
        if mls.epoch().as_u64() != w.epoch {
            debug!("vni {}: commit work for epoch {}, but in {}", w.vni, w.epoch, mls.epoch().as_u64());
            return Ok(());
        }
        if let Some(p) = g.pending_commit.as_ref().filter(|p| p.work == w.work) {
            let c = proto::Commit { vni: w.vni, work: w.work, commit: p.commit.clone(), welcome: p.welcome.clone() };
            self.send(client_message::Message::Commit(c));
            return Ok(());
        }
        mls.clear_pending_commit(identity.provider.storage()).map_err(|e| anyhow!("{e:?}"))?;

        let mut bad = Vec::new();
        let mut kps = Vec::new();
        for (i, kp) in w.adds.iter().enumerate() {
            match mls::parse_key_package(&identity.provider, kp) {
                Ok(kp) => kps.push(kp),
                Err(e) => {
                    warn!("vni {}: refusing a key package: {e:#}", w.vni);
                    bad.push(i as u32);
                }
            }
        }
        if !bad.is_empty() {
            let f = proto::CommitFailed { vni: w.vni, work: w.work, reason: "invalid key packages".into(), bad_adds: bad };
            self.send(client_message::Message::CommitFailed(f));
            return Ok(());
        }
        let members = mls::members(mls);
        let removes: Vec<LeafNodeIndex> = w
            .removes
            .iter()
            .filter_map(|p| p.parse::<HostPrefix>().ok())
            .filter(|p| *p != identity.prefix)
            .filter_map(|p| members.get(&p).map(|(i, _)| *i))
            .collect();
        let scope = w.scope.clone().unwrap_or_default();

        mls.set_aad(scope.encode_to_vec());
        let bundle = mls
            .commit_builder()
            .consume_proposal_store(w.include_proposals)
            .force_self_update(true)
            .propose_removals(removes)
            .propose_adds(kps)
            .load_psks(identity.provider.storage())
            .map_err(|e| anyhow!("{e:?}"))
            .and_then(|b| b.build(identity.provider.rand(), identity.provider.crypto(), &identity.signer, |_| true).map_err(|e| anyhow!("{e:?}")))
            .and_then(|b| b.stage_commit(&identity.provider).map_err(|e| anyhow!("{e:?}")));
        mls.set_aad(Vec::new());
        let bundle = match bundle {
            Ok(b) => b,
            Err(e) => {
                let f = proto::CommitFailed { vni: w.vni, work: w.work, reason: e.to_string(), bad_adds: Vec::new() };
                self.send(client_message::Message::CommitFailed(f));
                return Err(e);
            }
        };
        let commit = bundle.commit().tls_serialize_detached()?;
        let welcome = bundle.to_welcome_msg().map(|m| m.tls_serialize_detached()).transpose()?.unwrap_or_default();
        g.pending_commit = Some(PendingCommit { work: w.work, scope, commit: commit.clone(), welcome: welcome.clone() });
        self.send(client_message::Message::Commit(proto::Commit { vni: w.vni, work: w.work, commit, welcome }));
        Ok(())
    }

    fn propose_update(&mut self, p: proto::ProposeUpdate) -> Result<()> {
        let identity = self.identity.as_ref().unwrap();
        let Some(g) = self.groups.get_mut(&p.vni) else { return Ok(()) };
        let Some(mls) = g.mls.as_mut() else { return Ok(()) };
        if mls.epoch().as_u64() != p.epoch {
            return Ok(());
        }
        // the server asks only members that are not the committer: a commit of this host is
        // one the server did not take
        mls.clear_pending_commit(identity.provider.storage()).map_err(|e| anyhow!("{e:?}"))?;
        g.pending_commit = None;
        let (msg, _) = mls
            .propose_self_update(&identity.provider, &identity.signer, LeafNodeParameters::default())
            .map_err(|e| anyhow!("proposing an update: {e:?}"))?;
        let gm = proto::GroupMessage {
            vni: p.vni,
            id: self.next_msg_id,
            kind: proto::GroupMessageKind::Proposal.into(),
            epoch: p.epoch,
            message: msg.tls_serialize_detached()?,
        };
        self.next_msg_id += 1;
        g.outbox.push_back(gm.clone());
        self.send(client_message::Message::GroupMessage(gm));
        Ok(())
    }

    /// Sends the Ready and Switched collected while handling the last event.
    fn flush_group_messages(&mut self) {
        let ready = std::mem::take(&mut self.ready);
        let switched = std::mem::take(&mut self.switched);
        for ((vni, generation, epoch), spis) in ready {
            let spis = spis.into_iter().map(|(p, spi)| proto::ReadySpi { peer_underlay: p.underlay().octets().to_vec(), spi }).collect();
            self.send_application(vni, generation, group_application::Message::Ready(proto::Ready { epoch, spis }));
        }
        for ((vni, generation, epoch), peers) in switched {
            let peer_underlays = peers.into_iter().map(|p| p.underlay().octets().to_vec()).collect();
            self.send_application(vni, generation, group_application::Message::Switched(proto::Switched { epoch, peer_underlays }));
        }
    }

    fn send_application(&mut self, vni: u32, generation: u64, m: group_application::Message) {
        let Some(identity) = &self.identity else { return };
        let Some(g) = self.groups.get_mut(&vni).filter(|g| g.generation == generation) else { return };
        let Some(mls) = g.mls.as_mut() else { return };
        let plain = proto::GroupApplication { message: Some(m) }.encode_to_vec();
        let msg = match mls.create_message(&identity.provider, &identity.signer, &plain) {
            Ok(msg) => msg,
            Err(e) => {
                error!("vni {vni}: cannot create a group message: {e:?}");
                return;
            }
        };
        let Ok(bytes) = msg.tls_serialize_detached() else { return };
        let gm = proto::GroupMessage {
            vni,
            id: self.next_msg_id,
            kind: proto::GroupMessageKind::Application.into(),
            epoch: mls.epoch().as_u64(),
            message: bytes,
        };
        self.next_msg_id += 1;
        g.outbox.push_back(gm.clone());
        self.send(client_message::Message::GroupMessage(gm));
    }
}

fn end_pair(p: &mut Pair) {
    p.ending = true;
    p.target = None;
    p.peer_ready = None;
    p.peer_switched = None;
    p.stale_at = None;
}

fn cmsg(m: client_message::Message) -> proto::ClientMessage {
    proto::ClientMessage { message: Some(m) }
}
