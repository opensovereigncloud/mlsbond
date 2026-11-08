# A dataplane reset rekeys the host's pairs through a commit

Status: accepted; on a host with two dataplanes, the reset names the one that lost its Security
Associations (ADR 0016)

A dataplane that restarts loses its Security Associations and would count its sequence numbers
from 1 again, so its old keys must not be installed again: AES-GCM would repeat nonces, and the
peers' anti-replay windows would drop its frames. Only the orchestrator can see this happen, so it
tells its mlsbond client with an explicit `DataplaneReset`. The client has the committer commit an
update of its leaf, and in the resulting epoch only the pairs of this host are rekeyed, in every VNI
group it belongs to; the host adds its Security Associations afresh while its peers replace theirs.

An orchestrator that restarts while its dataplane keeps running does not call it: the installed
Security Associations are still valid, and a reconnecting orchestrator alone says nothing about the
dataplane.

**An orchestrator reports a reset it finds out when connecting before it opens the step stream.** The
client forgets the steps it asked of that dataplane, but it cannot recall one already sent, and nothing
orders the stream against the unary call. A step sent before the reset and carried out after it would
stay in the dataplane with no one knowing of it, under a key the client has moved on from, until the
orchestrator next restarts. With no stream open, no step can be underway, so `Dial`, `Status`,
`DataplaneReset` and `Start` in the Go package close that by construction, and the client needs no
change. A reset reported with the stream open is still accepted, and this does not protect it.

## Considered Options

- **A per-pair generation counter in the derivation context**, announced by application message.
  Avoids a commit, but adds a second way of making keys fresh beside epochs, and brings no fresh
  entropy into the group.
- **Stamping every step with a count of resets**, which the orchestrator compares, to refuse a step from
  before its reset. It also covers a reset reported with the stream open, but it changes the protocol for
  every orchestrator, to protect against what opening the stream later rules out.
- **Removing what the client does not know after a reset**, by comparing with the dataplane. It heals
  orphans of any cause, but only after the fact, with the old key accepted until then.
- **Unsubscribing and subscribing again.** No new call, but it looks like a removal and a join to
  the group, and triggers rekey on removal where that policy is on.
