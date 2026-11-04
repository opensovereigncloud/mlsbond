# A restarted mlsbond server regroups every VNI from scratch

Status: accepted

The mlsbond server keeps its state (subscriptions, committers, pending key packages, messages in
flight) in memory only, and has a boot ID that changes with every start. A client that reconnects
to a server with a different boot ID discards its VNI groups and subscribes again; the first
subscriber to a VNI creates a new group and the others join it. Every pair then receives Security
Associations from the new group and replaces the ones its hosts hold, paced by `Ready` and
`Switched` as in any rekey. A new group starts from fresh key packages, so its keys and SPIs differ
from the old group's although its epochs count from 0 again. Installed Security Associations keep
protecting traffic while the server is away.

This is what IEP-25 describes for a server reboot or crash.

## Considered Options

- **Rebuilding the server's state from the members**, who report their groups and epochs on
  reconnect. Keeps the groups, but a commit in flight during the crash may have reached only some
  members, and the server would have to detect and repair that split.
- **Persisting the server's state.** The most work, with partial writes as edge cases of their own.

## Consequences

Each server restart costs one gapless rekey of every pair in every VNI. A standby server taking over
looks to the clients like a restart, which is a starting point for redundancy, still out of scope.
