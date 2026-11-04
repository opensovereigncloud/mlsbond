# One Security Association per VNI and direction, on Linux XFRM too

Status: accepted

A Security Association covers one direction of one VNI between two host prefixes, whatever the
dataplane; it has no endpoint field. dpservice matches associations on the /64 and needs nothing
more. A Linux orchestrator maps each one onto exactly one XFRM state:

- **Egress towards a dpservice host**: one tunnel-mode state whose destination is the peer's
  `prefix::`, with policies over the peer's overlay prefixes. Before encryption, `skb->mark` is set
  from the inner destination; after encryption, in `POSTROUTING`, the outer destination is
  rewritten from the mark to that endpoint's underlay address. The ICV does not cover the outer
  header, so the rewrite is invisible to the crypto, and all endpoints share one sequence counter.
- **Ingress**: one state; the kernel's inbound lookup uses (mark, destination, SPI) and never the
  outer source, so frames from all of a dpservice host's per-VM source addresses arrive in it.

Both rely on the tunnel-mode template resolving the state by the template's destination
(`xfrm_tmpl_resolve_one`), the outer header being written from the state, `skb->mark` surviving
encryption within one network namespace, and `xfrm_output_resume` passing the encrypted packet
through `POSTROUTING` (Linux v7.0).

## Considered Options

- **One state per destination endpoint, each with the pair's key.** The obvious mapping, since an
  XFRM state's destination is exact and dpservice finds the VM from the full outer address. Every
  state counts its own sequence numbers from 1, so the key and salt would repeat AES-GCM nonces.
- **Security Associations per endpoint**, with the destination address in the derivation context.
  Safe, but it gives up one Security Association per VNI and direction, needs dpservice to hold an
  ingress association per remote endpoint, and needs a protocol for requesting them.

## Consequences

Never install one Security Association's key into more than one XFRM state. The Linux host must
reach the peer /64 via a gateway, so that the next hop does not depend on the destination rewritten
after routing; it must not use NIC packet offload, where the NIC builds the outer header; and its
map from inner address to endpoint must be keyed per VNI where tenant addresses overlap, for IPv4
inner traffic as well (with `flag af-unspec` on the states). A missing map entry sends the frame to
`prefix::`, which dpservice drops: it fails closed.
