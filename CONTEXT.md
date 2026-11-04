# mlsbond

Key exchange for underlay encryption: hosts that share a VNI agree on keys through MLS and derive
the Security Associations that protect the traffic between each pair of them.

## Language

### Components

**mlsbond server**:
The delivery service every mlsbond client connects to; it orders the commits of each VNI group and
fans them out. It is not a member of any VNI group.
_Avoid_: MLS server, key server

**mlsbond client**:
The daemon on a host that is that host's member in each VNI group it subscribed to, and derives
the Security Associations for it. It never touches a dataplane.
_Avoid_: MLS client, agent

**Committer**:
The one member of a VNI group that the mlsbond server lets commit changes to it; the longest-standing
member.

**Orchestrator**:
The component on a host that drives the mlsbond client and installs what it supplies into the
dataplane, e.g. the control plane or metalnet.
_Avoid_: consumer, controller

**Dataplane**:
Whatever finally encrypts the underlay traffic of a host: dpservice, or the Linux kernel through XFRM.

### Keys

**VNI group**:
The MLS group of all hosts subscribed to one VNI. There is exactly one per VNI.
_Avoid_: group key, VNI key

**Host prefix**:
The underlay /64 of a host, unique per host, which identifies the host's end of every Security
Association.
_Avoid_: IP prefix, underlay address

**Epoch**:
One state of a VNI group; it advances with every commit, and all keys derived in it change with it.

**Exporter secret**:
The secret a VNI group's epoch exports for mlsbond, from which every Security Association of that
epoch is derived. MLS has no single "group key"; this is what IEP-25 calls one.
_Avoid_: group key

**Security Association**:
The key material, salt and SPI protecting one direction of traffic in one VNI from one host
prefix to another, valid for one epoch.
_Avoid_: SA (in prose), tunnel, key

**Pair**:
Two hosts in one VNI group, protected by two Security Associations, one per direction, both from
the same epoch.
_Avoid_: tunnel, peering

**Pair epoch**:
The epoch a pair's Security Associations were derived from: the epoch current when the pair came
into being or was last rekeyed. It can lag behind the VNI group's epoch.

**Rekey**:
Moving pairs to the VNI group's current epoch, pair by pair, without a gap in protection.
_Avoid_: rotation, rollover

**Rekey policy**:
What makes the mlsbond server rekey a VNI group: a periodic interval, rekeying on removal, or an
explicit request.

**Regroup**:
Recreating every VNI group from scratch because the mlsbond server lost its state, recognised by
its new boot ID.

**Dataplane reset**:
A host's dataplane having lost all its Security Associations, as on a dpservice restart; it needs
fresh keys for every pair of that host, never the old ones again.

**Ready**:
A member's word to its VNI group that its ingress Security Associations for an epoch are installed,
naming the SPI each peer is to send under, so its peers may switch egress towards it.

**Switched**:
A member's word to its VNI group that its egress Security Associations now use an epoch, so its
peers may remove their old ingress from it.

**Direction**:
Egress or ingress, as seen from the host installing a Security Association; the same Security
Association is egress on its source host and ingress on its destination host.
