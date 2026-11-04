# Stalled steps are retried, never timed out

Status: accepted

A callback the orchestrator fails is retried with exponential backoff, capped at about 30 seconds,
and nothing that depends on it proceeds until it succeeds. A peer whose `Ready` or `Switched` does
not arrive is waited for indefinitely. Only membership ends a wait: a peer whose stream to the
server is gone is removed by a commit, and its pairs end. The client's read-only `Status` call shows
each pair's pair epoch and the step it is waiting on.

Waiting is always safe here. A stalled rekey leaves the pair on its old epoch, whose keys still
work; a stalled new pair has nothing installed, and an encrypting interface drops rather than
falling back to cleartext; a pending removal only keeps an old ingress Security Association
occupying a slot.

## Considered Options

- **Timeouts that force the step anyway.** Switching egress before the peer is `Ready`, or removing
  an ingress before it has `Switched`, is precisely what loses traffic.
- **Timeouts that evict the silent peer.** A failing orchestrator would cut its host out of the
  VNI altogether.
