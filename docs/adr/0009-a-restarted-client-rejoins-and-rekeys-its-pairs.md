# A restarted mlsbond client rejoins and rekeys its pairs; nothing is kept on disk

Status: accepted

An mlsbond client keeps no MLS state on disk. After a restart it subscribes again with fresh key
packages, and the committer of each VNI group removes the client's old leaf, found by its host
prefix, and adds the new one in the same commit. Since the host prefix stays in the group, its
peers keep their pairs with it and rekey on removal does not apply. The client then rekeys its own
pairs as after a dataplane reset (ADR 0008), replacing rather than adding on its own side, since its
dataplane still holds the old Security Associations; this also completes a rekey the restart
interrupted. Orchestrators keep installed Security Associations when their stream to the client
drops.

## Considered Options

- **Persisting the MLS state** (`openmls_sqlite_storage`). Puts key material at rest, and a client
  that missed a commit while down has to rejoin anyway.
- **Rejoining by external commit** (RFC 9420 resync). OpenMLS 0.9 removes the old leaf in an
  external commit only if it carries the same signature key, so the client would have to keep its
  signature key on disk, and the server would have to keep every group's GroupInfo and ratchet tree.
- **Rejoining without a rekey.** The client would not know which pair epoch each pair is on, and a
  rekey interrupted by the restart would stay half done.

## Consequences

Each client restart costs one gapless rekey of that host's pairs and nothing for other hosts. A host
prefix is a member's identity: a second host claiming the same prefix replaces the first, which is
accepted while participants are not authenticated (IEP-25 non-goal).
