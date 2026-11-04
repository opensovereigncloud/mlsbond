# mlsbond

Key exchange for underlay encryption, after IronCore IEP-25 ("Underlay Encryption - Key
Exchange"). Hosts that share a VNI form an MLS group, its **VNI group**, and every host derives
from the group's exporter the Security Associations protecting each **pair** of hosts in it. How it
works is described in [docs/README.md](docs/README.md), the vocabulary is in
[CONTEXT.md](CONTEXT.md), the decisions in [docs/adr](docs/adr).

```
            mlsbond-server  (Delivery Service: orders, relays, names committers; no secrets)
             ^           ^
   delivery  |           |  one gRPC stream per client
             |           |
  mlsbond-client     mlsbond-client     (one per host: MLS member, derives SAs, paces rekeys)
        ^                  ^
        | client API       |  Init, Subscribe, DataplaneReset, Status, WatchSecurityAssociations
  orchestrator        orchestrator      (control plane / metalnet: installs SAs into dpservice)
```

## Build and test

```bash
cargo build --release        # target/release/mlsbond-server, target/release/mlsbond-client
cargo test                   # unit tests: exporter derivation, SPI picking
cd go && go test ./...       # end-to-end suite: builds the binaries (debug) and runs them
```

`make test` runs both, and `make clean` removes the build output. The Go module in `go/` (module
`mlsbond`) holds the package orchestrators import and the generated stubs; `make generate`
regenerates the stubs from [proto/mlsbond.proto](proto/mlsbond.proto) and needs `protoc`. The Rust
build brings its own `protoc`.

## Run

```bash
mlsbond-server --listen '[::]:4712' --admin-listen '[::1]:4713'
mlsbond-client --server 'fd00::1:4712' --listen '[::1]:4714'
```

The client does nothing until its orchestrator calls `Init` with the host's name and underlay /64.
From Go:

```go
conn, err := mlsbond.Connect(ctx, "[::1]:4714", "hostA", netip.MustParsePrefix("fd00:a::/64"), cb)
conn.Subscribe(ctx, 100)
```

where `cb` implements `mlsbond.Client` (add, update, remove a Security Association) and, to hand
over what it holds on every connect, `mlsbond.Inventory`. `Connect` repeats `Init`, the
subscriptions and the stream after every reconnect.

The admin API (`Admin` service) gets and sets the rekey policy, globally or per VNI, rekeys a VNI
on demand and lists the VNI groups; both policies are off by default.

Server flags worth knowing:

- `--removal-grace` (10 s): how long a member's stream may be gone before the committer removes it.
  A client back within it resumes where it left off.
- `--commit-delay-ms` (200): how long pending joins, removals and rekeys are collected into one
  commit, so that hosts subscribing together cost one commit.

Client flag: `--stale-pairs-after` (60 s): after a client restart or a regroup, Security
Associations its orchestrator reports for a peer that does not join the new VNI group within this
time are removed.

## Notes on the implementation

- The Delivery Service messages, the commit scope in the MLS authenticated data and the Ready and
  Switched payloads are all in the one protobuf package.
- A dataplane reset of the committer is a self-update commit; any other host proposes the update
  of its leaf when the server asks it to, and the committer's next commit includes it.
- A committer that unsubscribes cannot commit its own removal in MLS, so the next-oldest member
  becomes committer and removes it, as when a committer's stream is gone.
- Pairs keep their epoch (ADR 0007): a commit moves only the pairs of newly added leaves and those
  its scope names, and every commit carries a path update.
