# mlsbond design

This document explains how mlsbond works at a high level: what each component does, where key
material lives, how a host joins a VNI group, how a pair of hosts changes keys without losing a
packet, and what happens when something restarts. The terms in bold are defined in
[CONTEXT.md](../CONTEXT.md). Each decision is argued in its own ADR under [adr/](adr), and this
document links to them instead of repeating the arguments.

## The problem

Underlay encryption protects tenant traffic between hosts with ESP. Each direction of a VNI's
traffic between two hosts needs its own **Security Association**, with the same key and salt
installed on both hosts. Those keys have to be agreed on, replaced from time to time, and replaced
whenever a host's dataplane loses its state. None of this may cost a packet, and no key may cross
the fabric that it protects.

mlsbond, after IronCore IEP-25, uses MLS (RFC 9420) to agree on the keys. All hosts subscribed to
one VNI form an MLS group, its **VNI group**. Every member can derive the Security Associations of
every pair of hosts in it from the group's exporter. A server orders the group's messages but
cannot read them.

## Components

![mlsbond components and where keys live](architecture.svg)

- **mlsbond-server** is the MLS Delivery Service for every VNI group.
  - It numbers and relays the groups' messages.
  - It names one **committer** per VNI group and hands it the pending changes.
  - It carries out the **rekey policy**.
  - It is not a member of any group and never sees a key. It keeps all its state in memory.
- **mlsbond-client** runs once per host and is that host's member in each VNI group the host
  subscribed to.
  - It holds the MLS group state and derives the Security Associations.
  - It paces every step with its peers.
  - It never touches a dataplane ([ADR 0003](adr/0003-the-orchestrator-installs-security-associations.md)).
- **The orchestrator** (metalnet) drives its client through the `ClientAPI` and installs what the
  client hands it into the dataplane.
  - It uses the Go package in [go/](../go).
  - It is the only component that knows the dataplane, just as with metalbond routes
    ([ADR 0011](adr/0011-the-orchestrator-is-called-with-dataplane-verbs.md)).
  - A host with an HA pair of dataplanes has two, one for each, which share the client
    ([ADR 0016](adr/0016-a-host-with-an-ha-pair-has-two-orchestrators.md)).
- **The dataplane** is dpservice, or the Linux kernel through XFRM
  ([ADR 0015](adr/0015-one-security-association-per-vni-and-direction-on-xfrm-too.md)). It
  encrypts the traffic.

Each client holds one bidirectional gRPC stream to the server
([ADR 0005](adr/0005-clients-reach-the-server-over-one-grpc-stream.md)). The stream carries:

- key packages, commits and Welcomes;
- the clients' own **Ready** and **Switched** messages, as MLS application messages;
- acknowledgements.

Clients and server are written in Rust on openmls, with a thin Go package for orchestrators
([ADR 0001](adr/0001-mlsbond-is-written-in-rust.md)).

## From a VNI group to Security Associations

Each **epoch** of a VNI group yields one exporter secret. A Security Association's key and salt
come from it, with the two **host prefixes** in direction order
([ADR 0002](adr/0002-sa-keys-come-from-the-mls-exporter-per-direction.md)):

```
MLS-Exporter("mlsbond sa", vni ‖ epoch ‖ src_prefix ‖ dst_prefix, 36)
  → key (32 bytes) ‖ salt (4 bytes)
```

- **Two directions, two keys.** A→B and B→A never share a key and salt, so their sequence numbers
  never produce the same AES-GCM nonce.
- **The receiver picks the SPI.** The SPI is chosen at random from 256 upwards among values none of
  the receiver's ingress associations uses, and announced in the receiver's Ready. It reveals
  nothing about the VNI and cannot collide on the receiver.
- **Fixed parameters:**
  - Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519. Each member's credential is a
    BasicCredential holding its host prefix.
  - ESP: AES-256-GCM with extended sequence numbers, and an anti-replay window of 64 on ingress.

A **pair** is two hosts in one VNI group. It is protected by two Security Associations, one per
direction, both derived from the same epoch: the pair's **pair epoch**.

## Membership: the server orders, one committer commits

![A host joins a VNI group](joining.svg)

A client that is asked to subscribe sends `Join` for the VNI. If the client is the first, the server
has it create the MLS group, and it becomes the committer. Otherwise the server collects the join,
together with any removals and rekeys pending for that VNI, for `--commit-delay-ms`. It then hands
all of it to the committer as one `CommitWork`. The committer is the oldest member that still has a
stream ([ADR 0006](adr/0006-one-committer-per-vni-group.md)).

The committer answers with one MLS commit that always includes a path update. The commit names, in
its authenticated data, the pairs it rekeys (its **scope**: none, all, or one host's).

The server appends the commit to the group's numbered log and fans it out:

- the commit as an `Entry` to every member;
- the Welcome to the hosts added.

So hosts that subscribe together cost one commit, and every member applies the same commits in the
same order. The scope is part of the authenticated commit, so the server can neither forge nor
alter it.

## Pairs keep their epoch; rekeys are policy

Every commit advances the group's epoch, but a commit only moves:

- the pairs of leaves it added;
- the pairs its scope names.

All other pairs stay on the epoch they were set up in
([ADR 0007](adr/0007-pairs-keep-their-epoch-and-rekeys-are-policy.md)). A host that joins therefore
costs its peers nothing beyond setting up their new pair with it.

Pairs are moved to the current epoch by the following, which together make up the rekey policy:

| What | Scope of the commit | Default |
|---|---|---|
| Periodic interval, globally or per VNI | all pairs | off |
| Rekey on removal of a member | all pairs | off |
| `Admin.Rekey{vni}` | all pairs | on request |
| A host's **dataplane reset** ([ADR 0008](adr/0008-a-dataplane-reset-rekeys-the-hosts-pairs-through-a-commit.md)) | that host's pairs | always |
| A client restart ([ADR 0009](adr/0009-a-restarted-client-rejoins-and-rekeys-its-pairs.md)) | that host's pairs, through its new leaf | always |

The server keeps the policy and changes it at runtime through its admin API. For a dataplane reset,
the resetting host's leaf has to be updated:

- If the resetting host is the committer, it does this itself with a self-update.
- Otherwise the server asks the host to propose an update of its leaf, and the committer's next
  commit includes that proposal.

## Moving a pair without a gap

![One pair moves to a new epoch](rekey.svg)

Whenever a pair moves to an epoch, whether it is new or rekeyed, both clients take the same steps
([ADR 0004](adr/0004-rekeys-are-paced-pairwise-by-mls-application-messages.md)):

1. **Ingress first.** Each side has its orchestrator add the ingress Security Association of the
   new epoch, under an SPI it picks.
2. **Ready.** Once that is confirmed, each side sends `Ready{epoch}` to the group, naming the SPI
   each peer is to send under.
3. **Egress.** On the peer's Ready, each side has its orchestrator switch its egress to the new
   epoch. This is one Update, so there is no moment without an egress. A new pair uses Add here.
4. **Switched.** Each side then sends `Switched{epoch}`.
5. **Old ingress last.** On the peer's Switched, each side removes its old ingress.

Ready and Switched are MLS application messages: the server relays them but can neither read nor
forge them, and it keeps no state about a rekey. Each step waits only on the host's own
orchestrator and on this one peer, never on the rest of the group.

A step the orchestrator fails is retried with backoff from 250 ms up to 30 s, and nothing after it
goes ahead. Steps are never forced by a timeout
([ADR 0012](adr/0012-stalled-steps-are-retried-never-timed-out.md)). Waiting is always safe:
a stalled rekey leaves the pair on its old keys, which still work.

The client's `Status` call shows, for each pair:

- its pair epoch, its egress SPI and its ingress SPIs;
- the step it is waiting on: `INGRESS`, `PEER_READY`, `EGRESS`, `PEER_SWITCHED` or `REMOVE`;
- the last error the orchestrator returned.

## Reliable delivery

A lost Ready would stall a pair for good, so the server and the client deliver reliably:

- **Numbered log.** Every entry in a VNI group's log has a sequence number. Members acknowledge
  what they have processed, and the server drops an entry once every member has acknowledged it.
- **Resume.** A client that reconnects sends `Resume{vni, last seq}` and gets everything after it.
  If the log no longer reaches back that far, or the client was removed meanwhile, the server
  answers `Rejoin` and the client joins afresh.
- **Accepted.** Group messages a client sends (Ready, Switched, update proposals) are kept and sent
  again until the server answers `Accepted`.
- **Grace period.** A member whose stream is gone stays in its groups for `--removal-grace`, and
  can resume within it. After that the committer removes it, and its peers remove their pairs with
  it.
- **Past epochs.** A client still accepts application messages from up to 16 past epochs, so a
  Ready sent just before a commit is not lost.

## When something restarts

| What restarts | What happens | Cost |
|---|---|---|
| The dataplane (e.g. dpservice) | The orchestrator notices the new instance and calls `DataplaneReset`. That host's pairs are rekeyed in every VNI group, and its old keys are never installed again (ADR 0008). On an HA pair the other dataplane keeps what it holds and moves on by an update (ADR 0016). | One gapless rekey of that host's pairs |
| The orchestrator | It reconnects, repeats `Init` and its subscriptions, and reports its **inventory** (the Security Association IDs it holds). The client compares the inventory with its own state and carries on ([ADR 0014](adr/0014-the-client-outlives-its-orchestrator-connection.md)). On an HA pair, nothing waits for the one that is away, and it catches up on its return (ADR 0016). | Nothing |
| The mlsbond client | It keeps nothing on disk, so it joins again with fresh key packages. The committer replaces its old leaf in the same commit, and the client replaces its pairs, using the inventory to know what is installed (ADR 0009). Associations for a peer that does not rejoin within `--stale-pairs-after` are removed. | One gapless rekey of that host's pairs |
| The mlsbond server | Clients see a new boot ID, drop their groups and subscribe again. Every VNI group is created anew, and every pair replaces its associations ([ADR 0010](adr/0010-a-restarted-server-regroups-every-vni-from-scratch.md)). | One gapless rekey of every pair |
| The committer's stream | The next-oldest member with a stream gets the work. The old committer is removed once the grace period is over. | Nothing beyond the removal |

Installed Security Associations keep protecting traffic throughout. While the server or a client is
away, only key changes wait.

## The orchestrator's side

The Go package wraps the client API in the shape of `metalbond.Client`:

```go
conn, err := mlsbond.Connect(ctx, "[::1]:4752", "hostA", hostPrefix, cb)
conn.Subscribe(ctx, 100)
```

`cb` implements `AddSecurityAssociation`, `UpdateSecurityAssociation` and
`RemoveSecurityAssociation`. These map one to one onto dpservice's Create, Update and Delete
(ADR 0011). A callback that returns `nil` confirms the step and releases the next one.

If `cb` also implements `Inventory`, it hands over the IDs of what it holds every time the stream
opens. After every reconnect, `Connect` repeats `Init`, the subscriptions and the stream.

An orchestrator that may find its dataplane new or empty when it connects settles that before any step
can come, as a step already sent when the reset is reported would stay in the dataplane with no one
knowing of it (ADR 0008):

```go
conn, err := mlsbond.Dial(ctx, "[::1]:4752", "hostA", hostPrefix, cb)
st, err := conn.Status(ctx)
// compare st with the dataplane
conn.DataplaneReset(ctx)
conn.Start()
```

On a host with an HA pair of dataplanes, each orchestrator names itself, and gives the same host name
and prefix (ADR 0016):

```go
conn, err := mlsbond.Connect(ctx, "[::1]:4752", "hostA", hostPrefix, cb, mlsbond.WithOrchestrator("metalnet-a"))
```

To keep the inventory and the dataplane in step, metalnet keeps no state on disk:

- a restarted metalnet takes the inventory from dpservice, which lists what it holds by identity only;
- it treats a dpservice it had to initialize itself as new, and reports a dataplane reset before any
  step can reach it.

## Security properties and limits

- **The server holds no secrets.** It sees MLS ciphertext, public key packages and the membership
  of each group. Neither a compromised server nor the fabric yields a key.
- **Every member can derive every pair of its VNI group** in its current epoch, including pairs
  between other hosts. Hosts are trusted under IEP-25's threat model.
- **A removed host keeps the keys of pairs on the epoch it saw**, until something rekeys them. Turn
  on rekey on removal or a periodic interval to bound this.
- **Participants are not authenticated in v1**
  ([ADR 0013](adr/0013-participants-are-not-authenticated-in-v1.md)). Anyone who reaches the server
  can join any VNI group or claim another host's prefix. mTLS with per-host certificates that name
  the host prefix is the intended remedy.
- **dpservice holds at most 64 Security Associations.** A host needs two per peer per VNI, and one
  more per peer while a rekey is in progress, so `LIMIT_REACHED` comes long before a host has many
  peers.

## Where to look in the code

| File | What it holds |
|---|---|
| [proto/mlsbond.proto](../proto/mlsbond.proto) | All three gRPC services, and the messages exchanged inside a group (Ready, Switched, Scope) |
| [src/mls.rs](../src/mls.rs) | The ciphersuite, identities, the exporter derivation and picking SPIs |
| [src/server.rs](../src/server.rs) | The Delivery Service: groups, logs, committers, batching, policy and the admin API |
| [src/client.rs](../src/client.rs) | The member: commits, the pairs' steps, the inventory and the orchestrator stream |
| [go/mlsbond.go](../go/mlsbond.go) | The Go package orchestrators use |
| [go/e2e/](../go/e2e) | The end-to-end suite: real server and clients, fake orchestrators that check the step order |
