# The mlsbond client outlives its orchestrator's connection

Status: accepted

The orchestrator drives the mlsbond client through idempotent unary calls (`Init`, `Subscribe`,
`Unsubscribe`, `DataplaneReset`, `Status`) and one bidirectional `WatchSecurityAssociations`
stream, on which it first sends its inventory and then a confirmation per step. The client's
subscriptions do not depend on that stream: when the orchestrator goes away, the client stays in
its VNI groups and only stops sending `Ready` until a stream is open again. A reconnecting
orchestrator repeats `Init` and its `Subscribe`s and reopens the stream. `IsKeyReady` from IEP-25
does not exist (ADR 0003).

## Considered Options

- **Subscriptions tied to the stream.** One connection to reason about, but every orchestrator
  restart would make the host leave its VNI groups, its peers remove their pairs with it, and
  traffic stop until it rejoined.
- **Host prefix and name as command-line flags of the client**, with no `Init`. The orchestrator is
  usually what knows the host prefix, so the two would have to be configured to agree.
