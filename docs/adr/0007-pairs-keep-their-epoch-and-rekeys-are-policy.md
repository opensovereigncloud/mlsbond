# Pairs keep their epoch, and rekeys are a policy that is off by default

Status: accepted

Every commit advances a VNI group's epoch, but a pair's Security Associations do not follow it on
their own. A pair is set up from the epoch current when it comes into being and stays on that epoch
until a rekey moves it, so pairs in one VNI group may be on different epochs.

A join therefore never touches existing pairs: the newcomer receives only the new epoch through its
Welcome and cannot derive Security Associations of earlier ones, so keeping them loses nothing.

Rekeys of existing pairs are governed by a rekey policy the mlsbond server holds, as a global
default with optional overrides per VNI, changeable at runtime through the server's admin API:

- a periodic interval, restarted by any rekey; **off by default**;
- rekey on removal; **off by default**;
- an explicit rekey of one VNI on request.

The server carries the policy out by asking the VNI group's committer for a commit.

## Considered Options

- **Every commit rekeys every pair.** One code path, but a VNI group of N hosts filling up costs N
  rekeys of every pair, with no security gained from the joins.
- **The committer or the orchestrator holds the timer.** The first loses the timer whenever the
  committer changes; the second puts key policy into metalnet and every other orchestrator.

## Consequences

Every member can derive every Security Association of its VNI group in its current epoch, including
those between other hosts. With rekey on removal off, a removed host keeps the keys of all pairs
that were on the current epoch when it left, until something rekeys them. With the periodic
interval off, nothing bounds how much traffic one key protects: dpservice keeps no byte counters
that could trigger a rekey. Both are accepted under IEP-25's threat model, in which hosts are
trusted and the adversary sits on the fabric.
