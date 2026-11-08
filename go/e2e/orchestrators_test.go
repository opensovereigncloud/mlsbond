package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"mlsbond"
	pb "mlsbond/proto"
)

// member is an orchestrator of h's mlsbond client, with a dataplane of its own. As a host, it works
// with the checks that look at what a host holds.
func member(h *host, name string) *host {
	m := unconnectedMember(h, name)
	m.connect()
	return m
}

func unconnectedMember(h *host, name string) *host {
	return &host{name: h.name + "/" + name, prefix: h.prefix, addr: h.addr, client: h.client, orch: newFakeOrchestrator(name), orchestrator: name}
}

// haNode starts a host with an HA pair: one mlsbond client, and two orchestrators.
func haNode(s *server, name, prefix string) (*host, *host) {
	h := startClient(s, name, prefix)
	return member(h, "one"), member(h, "two")
}

// failIngress has an orchestrator fail to install any ingress.
func failIngress(c call) error {
	if c.kind == add && c.id.Direction == ingress {
		return errors.New("LIMIT_REACHED")
	}
	return nil
}

func (f *fakeOrchestrator) attemptsAt(want func(call) bool) int {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	n := 0
	for _, c := range f.attempts {
		if want(c) {
			n++
		}
	}
	return n
}

func isIngressAdd(c call) bool { return c.kind == add && c.id.Direction == ingress }

// holdsTheSame checks that both Members hold the very same Security Associations.
func holdsTheSame(g Gomega, x, y *host) {
	GinkgoHelper()
	g.Expect(x.orch.held()).To(Equal(y.orch.held()))
}

// expectPairedAsNode checks that both Members are paired with peer, under the same associations.
func expectPairedAsNode(g Gomega, one, two, peer *host, vni uint32) {
	GinkgoHelper()
	expectPaired(g, one, peer, vni)
	expectPaired(g, two, peer, vni)
	holdsTheSame(g, one, two)
}

func expectSettled(g Gomega, hosts ...*host) {
	GinkgoHelper()
	for _, h := range hosts {
		st, err := h.conn.Status(context.Background())
		g.Expect(err).NotTo(HaveOccurred())
		for _, p := range st.Pairs {
			g.Expect(p.Waiting).To(Equal(mlsbond.WaitingNothing), "%s towards %s", h.name, p.Peer)
		}
	}
}

// rawStream opens a step stream by hand, for an orchestrator that does not do what the Go package does.
func rawStream(h *host, name string) pb.ClientAPI_WatchSecurityAssociationsClient {
	ctx, cancel := context.WithCancel(context.Background())
	DeferCleanup(cancel)
	stream, err := pb.NewClientAPIClient(dial(h.addr)).WatchSecurityAssociations(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(stream.Send(&pb.WatchRequest{Request: &pb.WatchRequest_Inventory{Inventory: &pb.Inventory{Orchestrator: name}}})).To(Succeed())
	return stream
}

func connectedOrchestrators(h *host) []string {
	res, err := pb.NewClientAPIClient(dial(h.addr)).Status(context.Background(), &pb.StatusRequest{})
	Expect(err).NotTo(HaveOccurred())
	names := []string{}
	for _, o := range res.Orchestrators {
		if o.Connected {
			names = append(names, o.Name)
		}
	}
	return names
}

// endsCleanly drains a stream until the mlsbond client ends it.
func endsCleanly(stream pb.ClientAPI_WatchSecurityAssociationsClient) {
	GinkgoHelper()
	Eventually(func() error {
		for {
			if _, err := stream.Recv(); err != nil {
				return err
			}
		}
	}).Should(MatchError(io.EOF))
}

var _ = Describe("Two orchestrators of one host", func() {
	var (
		s        *server
		one, two *host
		b        *host
	)

	BeforeEach(func() {
		s = startServer()
		one, two = haNode(s, "a", "fd00:a::/64")
		b = newHost(s, "b", "fd00:b::/64")
	})

	subscribeAll := func(vnis ...uint32) {
		one.subscribe(vnis...)
		two.subscribe(vnis...)
		b.subscribe(vnis...)
	}

	It("installs the same Security Associations in both, as one member of the VNI group", func() {
		subscribeAll(100)
		Eventually(func(g Gomega) {
			expectPairedAsNode(g, one, two, b, 100)
			expectSettled(g, one, two, b)
		}).Should(Succeed())
		Expect(s.group(100).Members).To(HaveLen(2))
		expectSafeOrder(one, b)
		expectSafeOrder(two, b)
	})

	It("rekeys both, by an update of the egress in each", func() {
		subscribeAll(100)
		Eventually(func(g Gomega) { expectPairedAsNode(g, one, two, b, 100) }).Should(Succeed())
		before := order.Load()
		epoch := s.epoch(100)

		_, err := s.admin.Rekey(context.Background(), &pb.RekeyRequest{Vni: 100})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func(g Gomega) {
			g.Expect(s.epoch(100)).To(BeNumerically(">", epoch))
			expectPairedAsNode(g, one, two, b, 100)
			expectSettled(g, one, two, b)
		}).Should(Succeed())
		for _, h := range []*host{one, two} {
			kinds := map[callKind]int{}
			for _, c := range h.orch.callsSince(before) {
				kinds[c.kind]++
			}
			Expect(kinds).To(HaveKeyWithValue(update, 1), h.name)
			Expect(kinds).To(HaveKeyWithValue(remove, 1), h.name)
			Expect(kinds).To(HaveKeyWithValue(add, 1), h.name)
		}
		expectSafeOrder(one, b)
		expectSafeOrder(two, b)
	})

	It("tells the peer to send only once both hold the ingress, and retries only the one that failed", func() {
		two.orch.setFail(failIngress)
		subscribeAll(100)

		Eventually(func() int { return one.orch.attemptsAt(isIngressAdd) }).Should(Equal(1))
		Eventually(func() int { return two.orch.attemptsAt(isIngressAdd) }).Should(BeNumerically(">=", 3))
		Eventually(func(g Gomega) {
			g.Expect(b.status().Pairs).To(HaveLen(1))
			g.Expect(b.status().Pairs[0].Waiting).To(Equal(mlsbond.WaitingPeerReady))
		}).Should(Succeed())
		Expect(saOf(b, 100, egress, b, one)).To(BeEmpty(), "b does not send before both hold the ingress")
		Expect(one.orch.attemptsAt(isIngressAdd)).To(Equal(1), "the one that confirmed gets no retry")

		two.orch.setFail(nil)
		Eventually(func(g Gomega) {
			expectPairedAsNode(g, one, two, b, 100)
			expectSettled(g, one, two, b)
		}).Should(Succeed())
		expectSafeOrder(one, b)
		expectSafeOrder(two, b)
	})

	It("shows each pair from each one's side", func() {
		two.orch.setFail(failIngress)
		subscribeAll(100)

		Eventually(func(g Gomega) {
			pairs := two.status().Pairs
			g.Expect(pairs).To(HaveLen(1))
			g.Expect(pairs[0].Waiting).To(Equal(mlsbond.WaitingIngress))
			g.Expect(pairs[0].LastError).To(ContainSubstring("LIMIT_REACHED"))
			g.Expect(pairs[0].IngressSPIs).To(BeEmpty())
			pairs = one.status().Pairs
			g.Expect(pairs).To(HaveLen(1))
			g.Expect(pairs[0].LastError).To(BeEmpty())
			g.Expect(pairs[0].IngressSPIs).To(HaveLen(1))
		}).Should(Succeed())

		out, err := exec.Command(filepath.Join(binDir, "mlsbond-client"), "status", "--address", one.addr).CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
		spi := one.status().Pairs[0].IngressSPIs[0]
		Expect(string(out)).To(ContainSubstring("orchestrator one: connected"))
		Expect(string(out)).To(ContainSubstring("orchestrator two: connected"))
		// one may already send to b, which holds its ingress: only b has to wait for two
		Expect(string(out)).To(MatchRegexp(fmt.Sprintf(`vni 100 pair fd00:b::/64: epoch \S+, spi out \d+ in %d, .*orchestrator one`, spi)))
		Expect(string(out)).To(MatchRegexp(`vni 100 pair fd00:b::/64: epoch -, spi out 0 in , .*last error: .*LIMIT_REACHED, orchestrator two`))
	})

	It("does not wait for one that is away, which catches up when it returns", func() {
		two.orch.setFail(failIngress)
		subscribeAll(100)
		Eventually(func() int { return two.orch.attemptsAt(isIngressAdd) }).Should(BeNumerically(">=", 2))

		Expect(two.conn.Close()).To(Succeed())
		Eventually(func(g Gomega) {
			expectPaired(g, one, b, 100)
			expectSettled(g, one, b)
		}).Should(Succeed())
		epoch := s.epoch(100)
		before := order.Load()

		two.orch.setFail(nil)
		two.connect()
		two.subscribe(100)
		Eventually(func(g Gomega) {
			expectPairedAsNode(g, one, two, b, 100)
			expectSettled(g, one, two, b)
		}).Should(Succeed())
		Expect(s.epoch(100)).To(Equal(epoch), "no rekey")
		Expect(one.orch.callsSince(before)).To(BeEmpty())
		Expect(b.orch.callsSince(before)).To(BeEmpty())
	})

	It("rekeys on the reset of one: it adds afresh, while the other moves on by an update", func() {
		subscribeAll(100)
		Eventually(func(g Gomega) { expectPairedAsNode(g, one, two, b, 100) }).Should(Succeed())
		epoch := s.epoch(100)
		before := order.Load()

		// its dpservice restarted
		two.orch.mtx.Lock()
		clear(two.orch.sas)
		two.orch.mtx.Unlock()
		Expect(two.conn.DataplaneReset(context.Background())).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(s.epoch(100)).To(BeNumerically(">", epoch))
			expectPairedAsNode(g, one, two, b, 100)
			expectSettled(g, one, two, b)
		}).Should(Succeed())
		for _, c := range two.orch.callsSince(before) {
			Expect(c.kind).To(Equal(add), "two adds afresh: %v", c)
		}
		for _, c := range one.orch.callsSince(before) {
			Expect(c.id.Direction == ingress || c.kind == update).To(BeTrue(), "one only moves its egress: %v", c)
		}
		expectSafeOrder(one, b)
		expectSafeOrder(two, b)
	})

	It("moves one that was away while the other's reset rekeyed, by an update", func() {
		subscribeAll(100)
		Eventually(func(g Gomega) { expectPairedAsNode(g, one, two, b, 100) }).Should(Succeed())
		Expect(two.conn.Close()).To(Succeed())
		epoch := s.epoch(100)
		before := order.Load()

		one.orch.mtx.Lock()
		clear(one.orch.sas)
		one.orch.mtx.Unlock()
		Expect(one.conn.DataplaneReset(context.Background())).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(s.epoch(100)).To(BeNumerically(">", epoch))
			expectPaired(g, one, b, 100)
			expectSettled(g, one, b)
		}).Should(Succeed())
		Expect(two.orch.callsSince(before)).To(BeEmpty())

		two.connect()
		two.subscribe(100)
		Eventually(func(g Gomega) {
			expectPairedAsNode(g, one, two, b, 100)
			expectSettled(g, one, two, b)
		}).Should(Succeed())
		kinds := map[callKind]int{}
		for _, c := range two.orch.callsSince(before) {
			kinds[c.kind]++
		}
		Expect(kinds).To(Equal(map[callKind]int{add: 1, update: 1, remove: 1}), "ingress added, egress moved, old ingress removed")
	})

	It("replaces both's Security Associations when the client restarts, repeating the subscriptions of each", func() {
		subscribeAll(100)
		Eventually(func(g Gomega) { expectPairedAsNode(g, one, two, b, 100) }).Should(Succeed())
		old := one.orch.held()
		before := order.Load()

		one.client.restart()

		Eventually(func(g Gomega) {
			expectPairedAsNode(g, one, two, b, 100)
			expectSettled(g, one, two, b)
			for id := range old {
				g.Expect(one.orch.held()).NotTo(HaveKey(id))
			}
		}).Should(Succeed())
		for _, h := range []*host{one, two, b} {
			for _, c := range h.orch.callsSince(before) {
				Expect(c.id.Direction == ingress || c.kind == update).To(BeTrue(), "%s: egress only switched: %v", h.name, c)
			}
		}
		Expect(s.group(100).Members).To(HaveLen(2))
	})

	It("lets a new stream of the same name replace a half dead one, which stalled the steps", func() {
		// connected, but it never confirms anything
		Expect(two.conn.Close()).To(Succeed())
		dead := rawStream(one, "two")
		Eventually(func() []string { return connectedOrchestrators(one) }).Should(ConsistOf("one", "two"))
		one.subscribe(100)
		b.subscribe(100)
		Eventually(func(g Gomega) {
			g.Expect(b.status().Pairs).To(HaveLen(1))
			g.Expect(b.status().Pairs[0].Waiting).To(Equal(mlsbond.WaitingPeerReady))
		}).Should(Succeed())
		Consistently(func() []mlsbond.SecurityAssociation { return saOf(b, 100, egress, b, one) }, "1s").Should(BeEmpty())

		restarted := member(startedAs(one), "two")
		restarted.subscribe(100)

		Eventually(func(g Gomega) {
			expectPairedAsNode(g, one, restarted, b, 100)
			expectSettled(g, one, restarted, b)
		}).Should(Succeed())
		Expect(connectedOrchestrators(one)).To(ConsistOf("one", "two"))
		endsCleanly(dead)
	})

	It("refuses a third while two are connected, leaving them alone", func() {
		subscribeAll(100)
		Eventually(func(g Gomega) { expectPairedAsNode(g, one, two, b, 100) }).Should(Succeed())
		before := order.Load()

		_, err := rawStream(one, "three").Recv()
		Expect(status.Code(err)).To(Equal(codes.ResourceExhausted))
		_, err = pb.NewClientAPIClient(dial(one.addr)).Subscribe(context.Background(), &pb.SubscribeRequest{Vni: 200, Orchestrator: "three"})
		Expect(status.Code(err)).To(Equal(codes.ResourceExhausted))

		Expect(connectedOrchestrators(one)).To(ConsistOf("one", "two"))
		Expect(s.group(200)).To(BeNil())
		Consistently(func() []call { return one.orch.callsSince(before) }, "1s").Should(BeEmpty())
	})

	It("lets a third take the place of one that is away, keeping what its dataplane holds", func() {
		subscribeAll(100)
		Eventually(func(g Gomega) { expectPairedAsNode(g, one, two, b, 100) }).Should(Succeed())
		Expect(two.conn.Close()).To(Succeed())
		epoch := s.epoch(100)
		before := order.Load()

		// the same dataplane, under another name
		third := unconnectedMember(startedAs(one), "three")
		third.orch = two.orch
		third.connect()
		third.subscribe(100)

		Eventually(func() []string { return connectedOrchestrators(one) }).Should(ConsistOf("one", "three"))
		Consistently(func(g Gomega) {
			g.Expect(two.orch.callsSince(before)).To(BeEmpty(), "what it holds counts as installed")
			g.Expect(s.epoch(100)).To(Equal(epoch))
			expectSettled(g, one, third, b)
		}).Should(Succeed())
	})

	It("keeps a VNI while the other one wants it, and leaves once neither does", func() {
		subscribeAll(100)
		Eventually(func(g Gomega) { expectPairedAsNode(g, one, two, b, 100) }).Should(Succeed())
		before := order.Load()

		two.unsubscribe(100)
		Consistently(func(g Gomega) {
			g.Expect(one.orch.callsSince(before)).To(BeEmpty())
			g.Expect(two.orch.callsSince(before)).To(BeEmpty())
			g.Expect(b.orch.callsSince(before)).To(BeEmpty())
			g.Expect(s.group(100).Members).To(HaveLen(2))
		}).Should(Succeed())

		one.unsubscribe(100)
		Eventually(func(g Gomega) {
			g.Expect(one.orch.held()).To(BeEmpty())
			g.Expect(two.orch.held()).To(BeEmpty())
			g.Expect(b.orch.held()).To(BeEmpty())
			g.Expect(s.group(100).Members).To(HaveLen(1))
		}).Should(Succeed())
	})

	It("ends what one wanted when its stream closes, unless it was the last", func() {
		one.subscribe(100)
		two.subscribe(100, 200)
		b.subscribe(100, 200)
		Eventually(func(g Gomega) {
			expectPairedAsNode(g, one, two, b, 100)
			expectPaired(g, one, b, 200)
			expectPaired(g, two, b, 200)
		}).Should(Succeed())

		// only two wanted 200, and one stays
		Expect(two.conn.Close()).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(saOf(one, 200, egress, one, b)).To(BeEmpty())
			g.Expect(saOf(b, 200, egress, b, one)).To(BeEmpty())
			g.Expect(s.group(200).Members).To(HaveLen(1))
		}).Should(Succeed())
		expectPaired(Default, one, b, 100)

		// the last one away keeps its subscriptions, and the host stays in the group
		epoch := s.epoch(100)
		before := order.Load()
		Expect(one.conn.Close()).To(Succeed())
		Eventually(func() []string { return connectedOrchestrators(one) }).Should(BeEmpty())
		Consistently(func(g Gomega) {
			g.Expect(s.group(100).Members).To(HaveLen(2))
			g.Expect(s.epoch(100)).To(Equal(epoch))
			g.Expect(b.orch.callsSince(before)).To(BeEmpty())
		}).Should(Succeed())
	})
})

var _ = Describe("One orchestrator without a name", func() {
	It("has one slot, the next one replacing it", func() {
		s := startServer()
		h := startClient(s, "a", "fd00:a::/64")
		h.connect()
		Eventually(func() []string { return connectedOrchestrators(h) }).Should(ConsistOf(""))
		Expect(h.conn.Close()).To(Succeed())

		first := rawStream(h, "")
		Eventually(func() []string { return connectedOrchestrators(h) }).Should(ConsistOf(""))
		second := rawStream(h, "")
		endsCleanly(first)
		Expect(connectedOrchestrators(h)).To(ConsistOf(""))
		DeferCleanup(second.CloseSend)
	})
})

// startedAs is the host of an orchestrator, to add another one to.
func startedAs(m *host) *host {
	return &host{name: m.clientName(), prefix: m.prefix, addr: m.addr, client: m.client}
}
