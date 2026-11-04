# The orchestrator is called with dataplane verbs, and reports what it holds on connect

Status: accepted

The mlsbond client hands Security Associations to its orchestrator as three explicit steps, which
the Go package exposes as a callback interface in the shape of `metalbond.Client`:

```go
type Client interface {
	AddSecurityAssociation(sa SecurityAssociation) error
	UpdateSecurityAssociation(old SecurityAssociationID, new SecurityAssociation) error
	RemoveSecurityAssociation(id SecurityAssociationID) error
}
```

Add installs an ingress Security Association, or the first egress of a pair; Update switches a
pair's egress to a new epoch; Remove takes away an old ingress or the Security Associations of a
pair that ended. A call returning `nil` is the orchestrator's confirmation that releases the next
step. They map one to one onto dpservice's Create, Update and Delete. Whenever the orchestrator
opens the stream it first lists the IDs of the Security Associations it holds, without keys, so a
client that restarted or regrouped can name the ones it replaces.

## Considered Options

- **Desired state per pair**, diffed by the orchestrator. Close to how metalnet reconciles, but a
  pair the client does not know yet must never arrive as an empty set, or the orchestrator deletes
  working Security Associations.
- **Add and Remove only**, as metalbond has, with the orchestrator turning an Add onto an existing
  egress into an Update. The switch, the one step whose timing matters, would be implicit.

## Consequences

If the orchestrator and the client restart together while the dataplane keeps running, the
orchestrator gets the installed IDs from dpservice's `ListSecurityAssociations`, so it needs no file
to report its inventory, and the client replaces them as after any restart (ADR 0009). A host
needs two Security Associations per peer per VNI, plus one more ingress per peer while a rekey is in
progress, and dpservice holds at most 64 (`DP_IPSEC_MAX_SA`), so the orchestrator has to expect
`LIMIT_REACHED` well before a host has many peers.
