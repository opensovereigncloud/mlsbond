# mlsbond is written in Rust, with a Go client package

Status: accepted

IEP-25 has Go code handle the orchestration (subscriptions, key rotation) and puts OpenMLS behind
a small Rust wrapper that the Go code reaches over gRPC: two processes in one "Key Exchange
Container" per host. mlsbond instead writes the server and the client daemon entirely in Rust,
calling openmls directly and dpservice over gRPC. Consumers in Go (the control plane, later
metalnet) drive the client daemon through a thin Go package of generated gRPC stubs. MLS group
state, key derivation and SA installation then live in one process, so there is no internal gRPC
hop and no state split that can go out of sync when one side restarts, and one `cargo build`
builds everything.

## Considered Options

- **The IEP layout: Go orchestration with an OpenMLS process behind gRPC.** Rejected for the
  internal hop and the split state described above.
- **Go linking openmls through cgo/FFI.** One process, but cgo brings a C ABI across which Rust
  types and errors have to be marshalled by hand, and complicates the build.
- **A Go-native MLS implementation** (thomas-vilte/mls-go, trevex/mls-go). Already rejected in
  IEP-25 as much less actively maintained than OpenMLS.

## Consequences

The controlplane and metalnet see only gRPC either way, so the choice is invisible to them. The
Go package can still offer a metalbond-style callback interface, driven by a gRPC stream from the
client daemon (see ADR 0003).
