# The orchestrator installs Security Associations, not mlsbond

Status: accepted

The mlsbond client never talks to a dataplane. It streams the Security Associations it derives to
its consumer, the orchestrator (the control plane, later metalnet), which installs them into
dpservice or the Linux kernel, exactly as a metalbond client hands routes to its consumer through
`AddRoute`/`RemoveRoute`. The Go package wraps that stream in a callback interface the orchestrator
registers, in the same shape as `metalbond.Client`. The orchestrator is the one component that
knows and manages the dataplane; mlsbond, like metalbond, supplies what it is asked for and keeps
no record of what was done with it.

This departs from IEP-25, whose diagram has the MLS client call dpservice directly.

## Considered Options

- **The client daemon installs Security Associations through a pluggable sink** (dpservice now,
  XFRM later). Rejected: it makes mlsbond a second component managing the dataplane beside the
  orchestrator, and gives it dataplane state of its own to keep and reconcile.

## Consequences

The rekey order (new ingress everywhere, then egress switched, then old ingress removed) is only
safe if mlsbond learns when each step was carried out, so the stream needs an acknowledgement path
back from the orchestrator. Whether a Security Association is installed is the orchestrator's
knowledge, not mlsbond's, which makes IEP-25's `IsKeyReady` redundant.
