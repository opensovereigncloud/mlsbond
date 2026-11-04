# A dataplane reset rekeys the host's pairs through a commit

Status: accepted

A dataplane that restarts loses its Security Associations and would count its sequence numbers
from 1 again, so its old keys must not be installed again: AES-GCM would repeat nonces, and the
peers' anti-replay windows would drop its frames. Only the orchestrator can see this happen, so it
tells its mlsbond client with an explicit `DataplaneReset`. The client has the committer commit an
update of its leaf, and in the resulting epoch only the pairs of this host are rekeyed, in every VNI
group it belongs to; the host adds its Security Associations afresh while its peers replace theirs.

An orchestrator that restarts while its dataplane keeps running does not call it: the installed
Security Associations are still valid, and a reconnecting orchestrator alone says nothing about the
dataplane.

## Considered Options

- **A per-pair generation counter in the derivation context**, announced by application message.
  Avoids a commit, but adds a second way of making keys fresh beside epochs, and brings no fresh
  entropy into the group.
- **Unsubscribing and subscribing again.** No new call, but it looks like a removal and a join to
  the group, and triggers rekey on removal where that policy is on.
