# Rekeys are paced pairwise, by MLS application messages

Status: accepted

When pairs move to an epoch (new pairs after a join, or existing ones in a rekey, see ADR 0007),
each mlsbond client hands its orchestrator the ingress Security Associations of that epoch and,
once the orchestrator has confirmed them, sends `Ready{epoch}` to the group as an MLS application
message, naming the SPI it picked for each peer (ADR 0002). A client adds or replaces its egress towards a peer as soon as that peer's `Ready` for the
epoch has arrived, then sends `Switched{epoch}`; a peer removes its old ingress from a client, if
there is one, once that client's `Switched` has arrived. Each step only waits for the one peer it
concerns.

IEP-25 has the MLS server ensure "that all clients on the hosts of the group are in sync". That
coordination is not part of MLS: RFC 9420 ends at the exporter, and what an application does with
exported keys, and when, is its own protocol. Carrying it in application messages keeps it inside
MLS's encryption and authentication, so the mlsbond server relays these messages without being
able to read or forge them, and keeps no state about a rekey.

## Considered Options

- **A global barrier on the server.** Every member reports each step to the server, which
  releases the next step once all have. Rejected: one slow or dead member stalls the rekey of the
  whole VNI group, and the barrier is server state that a crash loses.
- **Timers only.** The epoch is announced and each orchestrator switches egress and removes the
  old ingress after fixed delays. Rejected: every orchestrator would have to implement the same
  timing, and a slow host loses traffic without anyone noticing.

## Consequences

Per epoch each member sends two application messages, each delivered to every other member:
about 2·N·(N−1) deliveries for a VNI group of N hosts, independent of hosts outside it. Receiving a
peer's `Ready` also proves that the peer has processed the commit, since only members in that
epoch can decrypt it. A lost message stalls one pair, so reliable delivery is the mlsbond server's
and client's to provide.
