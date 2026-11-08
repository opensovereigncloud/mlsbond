// Package mlsbond connects an orchestrator to its host's mlsbond client.
//
// The orchestrator implements Client, the three steps the mlsbond client hands it, and calls
// Connect once. Connect keeps the mlsbond client's state alive across reconnects: whenever the
// connection is new, it repeats Init and the subscriptions and reopens the step stream, handing
// over the inventory if the Client also implements Inventory.
//
// An orchestrator that may have to report a DataplaneReset calls Dial, reports it, and calls Start,
// so that no step is underway across the reset.
//
// A host running an HA pair of dataplanes has one mlsbond client and two orchestrators, each driving
// its own dataplane. They tell themselves apart with WithOrchestrator.
package mlsbond

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "mlsbond/proto"
)

// Direction is egress or ingress, as seen by the host installing a Security Association.
type Direction int

const (
	Egress Direction = iota + 1
	Ingress
)

func (d Direction) String() string {
	switch d {
	case Egress:
		return "egress"
	case Ingress:
		return "ingress"
	}
	return fmt.Sprintf("Direction(%d)", int(d))
}

// SecurityAssociationID is the identity dpservice uses for a Security Association. Src and Dst
// are the network addresses of the two host prefixes.
type SecurityAssociationID struct {
	VNI       uint32
	SPI       uint32
	Direction Direction
	Src       netip.Addr
	Dst       netip.Addr
}

func (id SecurityAssociationID) String() string {
	return fmt.Sprintf("vni %d %s spi %d %s -> %s", id.VNI, id.Direction, id.SPI, id.Src, id.Dst)
}

// SecurityAssociation is one direction of one pair in one VNI, with its key material.
type SecurityAssociation struct {
	ID SecurityAssociationID
	// "aes-256-gcm"
	Algorithm string
	Key       []byte
	Salt      []byte
	ESN       bool
	// 64 on ingress, 0 on egress
	ReplayWindow uint32
}

// Client is what the orchestrator implements. Each method is one step; returning nil confirms it
// and releases the next one, returning an error has it retried with backoff. Steps arrive one at
// a time.
type Client interface {
	// AddSecurityAssociation installs an ingress, or the first egress of a pair.
	AddSecurityAssociation(sa SecurityAssociation) error
	// UpdateSecurityAssociation switches a pair's egress to a new epoch.
	UpdateSecurityAssociation(old SecurityAssociationID, new SecurityAssociation) error
	// RemoveSecurityAssociation removes an old ingress, or one of a pair that ended.
	RemoveSecurityAssociation(id SecurityAssociationID) error
}

// Inventory is implemented by a Client that can list the Security Associations it holds, so that
// an mlsbond client that lost its memory can replace them.
type Inventory interface {
	SecurityAssociations() []SecurityAssociationID
}

// Waiting is what a pair waits on.
type Waiting int

const (
	WaitingNothing Waiting = iota
	WaitingIngress
	WaitingPeerReady
	WaitingEgress
	WaitingPeerSwitched
	WaitingRemove
)

func (w Waiting) String() string {
	switch w {
	case WaitingNothing:
		return "nothing"
	case WaitingIngress:
		return "ingress"
	case WaitingPeerReady:
		return "peer-ready"
	case WaitingEgress:
		return "egress"
	case WaitingPeerSwitched:
		return "peer-switched"
	case WaitingRemove:
		return "remove"
	}
	return fmt.Sprintf("Waiting(%d)", int(w))
}

// PairStatus is the mlsbond client's view of one pair.
type PairStatus struct {
	VNI  uint32
	Peer netip.Prefix
	// epoch of the installed egress, nil before the first one
	PairEpoch *uint64
	// epoch the pair is moving to, nil if it is not moving
	TargetEpoch *uint64
	Waiting     Waiting
	// what the orchestrator last returned for the pending step
	LastError   string
	EgressSPI   uint32
	IngressSPIs []uint32
}

// OrchestratorStatus is one orchestrator the mlsbond client knows.
type OrchestratorStatus struct {
	Name      string
	Connected bool
}

// Status is the mlsbond client's state, with the pairs from this orchestrator's side.
type Status struct {
	Name            string
	HostPrefix      netip.Prefix
	VNIs            []uint32
	ServerConnected bool
	ServerBootID    string
	// whether any orchestrator is connected
	OrchestratorConnected bool
	Orchestrators         []OrchestratorStatus
	Pairs                 []PairStatus
}

// Conn is the connection to one mlsbond client.
type Conn struct {
	name         string
	orchestrator string
	hostPrefix   netip.Prefix
	client       Client
	conn         *grpc.ClientConn
	api          pb.ClientAPIClient
	cancel       context.CancelFunc
	done         chan struct{}

	mtx  sync.Mutex
	vnis map[uint32]bool
	// unsubscribed, but not yet confirmed by the mlsbond client
	leaving map[uint32]bool
}

// Option changes how Connect behaves.
type Option func(*Conn)

// WithOrchestrator names this orchestrator to the mlsbond client, for a host with two of them. Each
// has its own name, while the name of the host stays the same. A connection of the same name replaces
// the old one, and a third name is refused while two others are connected.
func WithOrchestrator(name string) Option {
	return func(c *Conn) { c.orchestrator = name }
}

// Connect is Dial followed by Start, for an orchestrator that has nothing to settle before steps come.
func Connect(ctx context.Context, address, name string, hostPrefix netip.Prefix, client Client, opts ...Option) (*Conn, error) {
	c, err := Dial(ctx, address, name, hostPrefix, client, opts...)
	if err != nil {
		return nil, err
	}
	c.Start()
	return c, nil
}

// Dial connects to the mlsbond client at address (host:port) and names this host to it. No step
// reaches client until Start. It fails if the mlsbond client is unreachable or refuses the name or
// host prefix.
func Dial(ctx context.Context, address, name string, hostPrefix netip.Prefix, client Client, opts ...Option) (*Conn, error) {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	c := &Conn{
		name:       name,
		hostPrefix: hostPrefix,
		client:     client,
		conn:       conn,
		api:        pb.NewClientAPIClient(conn),
		done:       make(chan struct{}),
		vnis:       map[uint32]bool{},
		leaving:    map[uint32]bool{},
	}
	for _, opt := range opts {
		opt(c)
	}
	if err := c.init(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Start opens the step stream, handing over the inventory, and keeps it open from here on. Call it
// once.
func (c *Conn) Start() {
	runCtx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go c.run(runCtx)
}

// Close stops handing over steps. The mlsbond client keeps the subscriptions of the last orchestrator
// connected, and ends those of one that closes while the other stays.
func (c *Conn) Close() error {
	if c.cancel != nil {
		c.cancel()
		<-c.done
	}
	return c.conn.Close()
}

// Subscribe makes this host a member of the VNI group. It is remembered and repeated after a
// reconnect even if this call fails.
func (c *Conn) Subscribe(ctx context.Context, vni uint32) error {
	c.mtx.Lock()
	c.vnis[vni] = true
	delete(c.leaving, vni)
	c.mtx.Unlock()
	_, err := c.api.Subscribe(ctx, &pb.SubscribeRequest{Vni: vni, Orchestrator: c.orchestrator})
	return err
}

// Unsubscribe leaves the VNI group, once no other orchestrator of this host wants it; its Security
// Associations are removed through the Client. It is remembered and repeated after a reconnect until the mlsbond client confirms it.
func (c *Conn) Unsubscribe(ctx context.Context, vni uint32) error {
	c.mtx.Lock()
	delete(c.vnis, vni)
	c.leaving[vni] = true
	c.mtx.Unlock()
	return c.unsubscribe(ctx, vni)
}

func (c *Conn) unsubscribe(ctx context.Context, vni uint32) error {
	if _, err := c.api.Unsubscribe(ctx, &pb.UnsubscribeRequest{Vni: vni, Orchestrator: c.orchestrator}); err != nil {
		return err
	}
	c.mtx.Lock()
	if !c.vnis[vni] {
		delete(c.leaving, vni)
	}
	c.mtx.Unlock()
	return nil
}

// DataplaneReset reports that this orchestrator's dataplane lost all its Security Associations. The
// mlsbond client forgets what it asked of this orchestrator, but it cannot recall a step already sent:
// carried out after this call, that step stays in the dataplane with no one knowing of it. So report
// a reset found out when connecting between Dial and Start, when no step can be underway.
func (c *Conn) DataplaneReset(ctx context.Context) error {
	_, err := c.api.DataplaneReset(ctx, &pb.DataplaneResetRequest{Orchestrator: c.orchestrator})
	return err
}

// Status returns the mlsbond client's state.
func (c *Conn) Status(ctx context.Context) (*Status, error) {
	res, err := c.api.Status(ctx, &pb.StatusRequest{Orchestrator: c.orchestrator})
	if err != nil {
		return nil, err
	}
	s := &Status{
		Name:                  res.ClientName,
		VNIs:                  res.Vnis,
		ServerConnected:       res.ServerConnected,
		ServerBootID:          res.ServerBootId,
		OrchestratorConnected: res.OrchestratorConnected,
	}
	s.HostPrefix, _ = netip.ParsePrefix(res.HostPrefix)
	for _, o := range res.Orchestrators {
		s.Orchestrators = append(s.Orchestrators, OrchestratorStatus{Name: o.Name, Connected: o.Connected})
	}
	for _, p := range res.Pairs {
		ps := PairStatus{
			VNI:         p.Vni,
			PairEpoch:   p.PairEpoch,
			TargetEpoch: p.TargetEpoch,
			Waiting:     Waiting(p.Waiting),
			LastError:   p.LastError,
			EgressSPI:   p.EgressSpi,
			IngressSPIs: p.IngressSpis,
		}
		ps.Peer, _ = netip.ParsePrefix(p.PeerHostPrefix)
		s.Pairs = append(s.Pairs, ps)
	}
	return s, nil
}

func (c *Conn) init(ctx context.Context) error {
	_, err := c.api.Init(ctx, &pb.InitRequest{ClientName: c.name, HostPrefix: c.hostPrefix.String()})
	return err
}

func (c *Conn) run(ctx context.Context) {
	defer close(c.done)
	for ctx.Err() == nil {
		err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		slog.Warn("mlsbond client connection lost, reconnecting", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// session (re)establishes the client's state and carries out steps until the stream breaks.
func (c *Conn) session(ctx context.Context) error {
	if err := c.init(ctx); err != nil {
		return err
	}
	c.mtx.Lock()
	vnis := slices.Sorted(maps.Keys(c.vnis))
	leaving := slices.Sorted(maps.Keys(c.leaving))
	c.mtx.Unlock()
	for _, vni := range vnis {
		if _, err := c.api.Subscribe(ctx, &pb.SubscribeRequest{Vni: vni, Orchestrator: c.orchestrator}); err != nil {
			return err
		}
	}
	for _, vni := range leaving {
		if err := c.unsubscribe(ctx, vni); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.api.WatchSecurityAssociations(ctx)
	if err != nil {
		return err
	}
	inventory := &pb.Inventory{Orchestrator: c.orchestrator}
	if inv, ok := c.client.(Inventory); ok {
		for _, id := range inv.SecurityAssociations() {
			inventory.Ids = append(inventory.Ids, idToProto(id))
		}
	}
	if err := stream.Send(&pb.WatchRequest{Request: &pb.WatchRequest_Inventory{Inventory: inventory}}); err != nil {
		return err
	}
	for {
		step, err := stream.Recv()
		if err != nil {
			return err
		}
		conf := &pb.Confirmation{Step: step.Step}
		if err := c.apply(step); err != nil {
			conf.Error = err.Error()
			if conf.Error == "" {
				conf.Error = "error"
			}
		}
		if err := stream.Send(&pb.WatchRequest{Request: &pb.WatchRequest_Confirmation{Confirmation: conf}}); err != nil {
			return err
		}
	}
}

func (c *Conn) apply(step *pb.Step) error {
	switch a := step.Action.(type) {
	case *pb.Step_Add:
		sa, err := saFromProto(a.Add.Sa)
		if err != nil {
			return err
		}
		return c.client.AddSecurityAssociation(sa)
	case *pb.Step_Update:
		old, err := idFromProto(a.Update.Old)
		if err != nil {
			return err
		}
		sa, err := saFromProto(a.Update.New)
		if err != nil {
			return err
		}
		return c.client.UpdateSecurityAssociation(old, sa)
	case *pb.Step_Remove:
		id, err := idFromProto(a.Remove.Id)
		if err != nil {
			return err
		}
		return c.client.RemoveSecurityAssociation(id)
	}
	return errors.New("unknown step")
}

func idToProto(id SecurityAssociationID) *pb.SecurityAssociationID {
	dir := pb.Direction_EGRESS
	if id.Direction == Ingress {
		dir = pb.Direction_INGRESS
	}
	src, dst := id.Src.As16(), id.Dst.As16()
	return &pb.SecurityAssociationID{Vni: id.VNI, Spi: id.SPI, Direction: dir, SrcUnderlay: src[:], DstUnderlay: dst[:]}
}

func idFromProto(p *pb.SecurityAssociationID) (SecurityAssociationID, error) {
	var id SecurityAssociationID
	if p == nil {
		return id, errors.New("no Security Association ID")
	}
	src, ok1 := netip.AddrFromSlice(p.SrcUnderlay)
	dst, ok2 := netip.AddrFromSlice(p.DstUnderlay)
	if !ok1 || !ok2 {
		return id, errors.New("bad underlay address")
	}
	switch p.Direction {
	case pb.Direction_EGRESS:
		id.Direction = Egress
	case pb.Direction_INGRESS:
		id.Direction = Ingress
	default:
		return id, errors.New("no direction")
	}
	id.VNI, id.SPI, id.Src, id.Dst = p.Vni, p.Spi, src, dst
	return id, nil
}

func saFromProto(p *pb.SecurityAssociation) (SecurityAssociation, error) {
	var sa SecurityAssociation
	if p == nil {
		return sa, errors.New("no Security Association")
	}
	id, err := idFromProto(p.Id)
	if err != nil {
		return sa, err
	}
	if p.Algorithm != pb.Algorithm_AES_256_GCM {
		return sa, fmt.Errorf("unknown algorithm %v", p.Algorithm)
	}
	return SecurityAssociation{ID: id, Algorithm: "aes-256-gcm", Key: p.Key, Salt: p.Salt, ESN: p.Esn, ReplayWindow: p.ReplayWindow}, nil
}
