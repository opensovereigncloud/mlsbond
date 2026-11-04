# Participants are not authenticated in v1

Status: accepted

As IEP-25 makes it a non-goal, mlsbond v1 authenticates nobody: clients and server talk plaintext
gRPC, the server accepts any client and any subscription, and a member's MLS credential is a
`BasicCredential` holding its host prefix, which nothing vouches for. IEP-25's threat model places
the adversary on the tenant fabric and trusts the control plane network, which is where all
mlsbond traffic runs; Security Association keys never cross the fabric.

## Consequences

Anyone who can reach the mlsbond server can join any VNI group and derive every Security
Association in it (ADR 0007), and can claim a host prefix that another host holds, which removes
that host's leaf (ADR 0009). The intended remedy is mTLS with a certificate per host that names its
host prefix, the server accepting only a credential whose host prefix matches the certificate.
Transport security is configured in one place, so adding it does not touch the protocol.
