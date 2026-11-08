# A host with an HA pair of dataplanes has two orchestrators

Status: accepted; changes ADR 0008 and ADR 0014 for such a host

A host can run two dataplanes as an HA pair: one forwards, and the other takes over when it dies. Both
need the same Security Associations, or a failover drops the traffic. They share a host prefix, so
they are one member of each VNI group, with one mlsbond client. Neither orchestrator may touch the
other's dataplane, so the client has to serve both.

- **Named streams:** an orchestrator names its stream in its inventory. The same name replaces the
  old stream, so that a half dead connection of a restarted orchestrator stalls nothing. Another name
  adds a stream. A third name is refused while two are connected, and otherwise takes the place of
  one that is away, whose state is forgotten. An empty name is a name like any other, so a host with
  one orchestrator needs to change nothing.
- **What is held, per orchestrator:** each pair records what each orchestrator holds, and each
  orchestrator moves through the steps on its own, getting `Add` or `Update` according to what it
  holds. Retries only go to the one that failed. What the pair is moving to stays shared, so that
  both install the very same associations.
- **Ready and Switched wait for all that are connected:** a peer may send under an ingress once every
  connected orchestrator holds it, and may remove an old ingress once all have left it. One that is
  away is not waited for, and catches up from the pair's target when it returns.
- **Scoped reset:** `DataplaneReset` names the orchestrator, and only what that one holds is forgotten.
  The commit it asks for rekeys the host's pairs as before: that orchestrator adds afresh, and the
  other one keeps what it holds and moves on through `Update`.
- **Union of interest:** `Subscribe` and `Unsubscribe` carry the name, and the host leaves a VNI group
  once no orchestrator wants it. An orchestrator decides by its own dataplane, so one lagging behind
  must not take away what the other uses. Its interest ends when its stream closes, except for the
  last stream's, as a client stays in its groups while its orchestrator is away (ADR 0014).
- **Status per orchestrator:** `Status` tells the pairs from one orchestrator's side, as an
  orchestrator compares them with its own dataplane to find out that it lost associations.

An orchestrator can move its egress while the other one has yet to install the ingress of that epoch:
what the egress needs is the peer's ingress, which the peer's Ready vouches for.

## Considered Options

- **A second client per dataplane.** Both have one host prefix, so the server takes the second for a new
  instance of the first and replaces it.
- **One orchestrator installing in both dataplanes.** No change here, but it breaks the rule that an
  orchestrator only knows its own dataplane.
- **All orchestrators in lockstep**, with a pair's next step waiting until each has confirmed the last.
  It holds up a healthy dataplane behind a failing one with no gain in safety, since only Ready and
  Switched are visible to the peer.
- **An HA flag on the client.** It would catch a misconfigured second orchestrator earlier, but it has
  to match how the host is deployed, and it could not change anything else: the client must not wait
  for an orchestrator that is absent.

## Consequences

The step handling changed for everyone, so a single orchestrator runs through it too. The server, the
derivation and the messages between clients did not change.

A dataplane that was away can briefly lag behind the other one when it returns, and would drop traffic
if it took over in that moment. That is what not waiting for it costs.

Repeating an association's sequence numbers across a failover is not something the client can prevent,
as it never sees them. The two dataplanes have to settle that between them.
