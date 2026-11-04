# mlsbond clients reach the server over one bidirectional gRPC stream

Status: accepted

Each mlsbond client holds a single bidirectional gRPC stream to the mlsbond server. Everything
travels on it: MLS handshake messages (key packages, commits, Welcome, GroupInfo), MLS application
messages (`Ready`, `Switched`), and mlsbond's own Delivery Service messages (subscribing to a VNI,
naming the committer, delivery acknowledgements). Messages are numbered per VNI group, and a
reconnecting client names the last one it received.

IEP-25 calls this "a second parallel HTTP connection"; "second" is relative to metalbond, whose
protocol stays free of MLS. RFC 9420 and RFC 9750 leave the Delivery Service's transport open, and
the server has to push to clients, which request/response HTTP cannot do alone. A gRPC stream gives
push, ordering and detection of a vanished client in one connection, runs over HTTP/2, and is the
same stack as the client's API towards its orchestrator.

## Considered Options

- **HTTP REST plus a WebSocket or server-sent events for push**, as Wire does. Two mechanisms
  where one suffices.
- **A framed TCP protocol of our own**, as metalbond has. Framing, keepalive and reconnect would
  all be ours to write.
