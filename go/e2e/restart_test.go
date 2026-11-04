package e2e

import (
	"context"
	"errors"
	"net/netip"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"mlsbond"
	pb "mlsbond/proto"
)

// involves tells whether a call concerns the pair of h with peer.
func involves(c call, peer *host) bool {
	return c.id.Src == peer.underlay() || c.id.Dst == peer.underlay()
}

// expectUntouched checks that x and y made no calls about their pair since before.
func expectUntouched(x, y *host, before int64) {
	GinkgoHelper()
	for _, c := range x.orch.callsSince(before) {
		Expect(involves(c, y)).To(BeFalse(), "%s: call about its pair with %s: %v", x.name, y.name, c)
	}
	for _, c := range y.orch.callsSince(before) {
		Expect(involves(c, x)).To(BeFalse(), "%s: call about its pair with %s: %v", y.name, x.name, c)
	}
}

var _ = Describe("Restarts", func() {
	var s *server

	BeforeEach(func() {
		s = startServer()
	})

	DescribeTable("gives a host whose dataplane was reset fresh Security Associations for its pairs only", func(resetting int) {
		hosts := threeHosts(s, 100)
		// a is the committer, having created the group
		a, b, c := hosts[resetting], hosts[(resetting+1)%3], hosts[(resetting+2)%3]
		old := keysOf(hosts)
		before := order.Load()

		// dpservice restarted: everything it held is gone
		a.orch.mtx.Lock()
		clear(a.orch.sas)
		a.orch.mtx.Unlock()
		Expect(a.conn.DataplaneReset(context.Background())).To(Succeed())

		expectAllReplaced(hosts, 100, map[mlsbond.SecurityAssociationID]string{})
		for id, k := range keysOf(hosts) {
			fromA := id.Src == a.underlay() || id.Dst == a.underlay()
			if fromA {
				Expect(old).NotTo(ContainElement(k), "%v of a's pairs is fresh", id)
			}
		}
		for _, cl := range a.orch.callsSince(before) {
			Expect(cl.kind).To(Equal(add), "a adds afresh: %v", cl)
		}
		for _, h := range []*host{b, c} {
			for _, cl := range h.orch.callsSince(before) {
				Expect(cl.id.Direction == ingress || cl.kind == update).To(BeTrue(), "%s replaces its egress towards a: %v", h.name, cl)
			}
		}
		expectUntouched(b, c, before)
		expectSafeOrder(hosts...)
	},
		Entry("the committer", 0),
		Entry("another member, by an update proposal", 1),
	)

	It("does nothing when the orchestrator reconnects", func() {
		hosts := threeHosts(s, 100)
		a := hosts[0]
		epoch := s.epoch(100)
		before := order.Load()

		Expect(a.conn.Close()).To(Succeed())
		probe := pb.NewClientAPIClient(dial(a.addr))
		Eventually(func(g Gomega) {
			res, err := probe.Status(context.Background(), &pb.StatusRequest{})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(res.OrchestratorConnected).To(BeFalse())
		}).Should(Succeed())
		a.connect()
		a.subscribe(100)
		Eventually(func() bool { return a.status().OrchestratorConnected }).Should(BeTrue())

		Consistently(func(g Gomega) {
			for _, h := range hosts {
				g.Expect(h.orch.callsSince(before)).To(BeEmpty(), h.name)
			}
			g.Expect(s.epoch(100)).To(Equal(epoch))
			g.Expect(s.group(100).Members).To(HaveLen(3))
		}).Should(Succeed())
	})

	It("has a restarted client rejoin and replace its own pairs only", func() {
		hosts := threeHosts(s, 100)
		a, b, c := hosts[0], hosts[1], hosts[2]
		old := keysOf(hosts)
		before := order.Load()

		a.client.restart()
		// the Go package repeats Init, the subscription and the inventory by itself
		Eventually(func(g Gomega) {
			expectAllPaired(g, hosts, 100)
			for id, k := range keysOf(hosts) {
				if id.Src == a.underlay() || id.Dst == a.underlay() {
					g.Expect(old).NotTo(ContainElement(k), "%v of a's pairs is replaced", id)
				}
			}
		}).Should(Succeed())
		for _, h := range hosts {
			for _, cl := range h.orch.callsSince(before) {
				Expect(cl.id.Direction == ingress || cl.kind == update).To(BeTrue(), "%s: egress only switched: %v", h.name, cl)
			}
		}
		expectUntouched(b, c, before)
		expectSafeOrder(hosts...)
		Expect(s.group(100).Members).To(HaveLen(3))
	})

	It("regroups after a server restart, replacing every pair without a gap", func() {
		hosts := threeHosts(s, 100)
		for _, h := range hosts {
			h.subscribe(200)
		}
		Eventually(func(g Gomega) { expectAllPaired(g, hosts, 200) }).Should(Succeed())
		old := keysOf(hosts)
		before := order.Load()
		boot := hosts[0].status().ServerBootID

		s.proc.restart()
		Eventually(func() string { return hosts[0].status().ServerBootID }).ShouldNot(Equal(boot))
		expectAllReplaced(hosts, 100, old)
		expectAllReplaced(hosts, 200, old)
		for _, h := range hosts {
			for _, cl := range h.orch.callsSince(before) {
				Expect(cl.id.Direction == ingress || cl.kind == update).To(BeTrue(), "%s: egress only switched: %v", h.name, cl)
			}
		}
		expectSafeOrder(hosts...)
	})

	It("retries a failing callback until it succeeds, while other pairs proceed", func() {
		a := newHost(s, "a", "fd00:a::/64")
		b := newHost(s, "b", "fd00:b::/64")
		a.subscribe(100)
		b.subscribe(100)
		Eventually(func(g Gomega) { expectPaired(g, a, b, 100) }).Should(Succeed())

		c := newHost(s, "c", "fd00:c::/64")
		a.orch.setFail(func(cl call) error {
			if involves(cl, c) {
				return errors.New("LIMIT_REACHED")
			}
			return nil
		})
		c.subscribe(100)

		Eventually(func(g Gomega) { expectPaired(g, b, c, 100) }).Should(Succeed())
		Eventually(func(g Gomega) {
			var p *mlsbond.PairStatus
			for _, ps := range a.status().Pairs {
				if ps.Peer == c.prefix {
					p = &ps
				}
			}
			g.Expect(p).NotTo(BeNil())
			g.Expect(p.Waiting).To(Equal(mlsbond.WaitingIngress))
			g.Expect(p.LastError).To(ContainSubstring("LIMIT_REACHED"))
			g.Expect(p.PairEpoch).To(BeNil())
		}).Should(Succeed())
		Eventually(func(g Gomega) {
			for _, ps := range c.status().Pairs {
				if ps.Peer == a.prefix {
					g.Expect(ps.Waiting).To(Equal(mlsbond.WaitingPeerReady))
				}
			}
		}).Should(Succeed())
		Expect(saOf(c, 100, egress, c, a)).To(BeEmpty(), "c does not send to a before a is ready")
		failures := func() int {
			a.orch.mtx.Lock()
			defer a.orch.mtx.Unlock()
			n := 0
			for _, cl := range a.orch.attempts {
				if involves(cl, c) && cl.err != nil {
					n++
				}
			}
			return n
		}
		Eventually(failures).Should(BeNumerically(">=", 3), "retried")

		a.orch.setFail(nil)
		Eventually(func(g Gomega) {
			expectPaired(g, a, b, 100)
			expectPaired(g, a, c, 100)
		}).Should(Succeed())
		expectSafeOrder(a, b, c)
	})
})

var _ = Describe("Init", func() {
	var s *server

	BeforeEach(func() {
		s = startServer()
	})

	It("refuses a host prefix that is not an IPv6 /64", func() {
		h := newHost(s, "a", "fd00:a::/64")
		for _, p := range []string{"fd00:a::/48", "fd00:a::1/64", "10.0.0.0/24"} {
			_, err := mlsbond.Connect(context.Background(), h.addr, "a", netip.MustParsePrefix(p), h.orch)
			Expect(status.Code(err)).To(Equal(codes.InvalidArgument), p)
		}
	})

	It("refuses another host prefix while VNIs are subscribed, and takes it once none are", func() {
		h := newHost(s, "a", "fd00:a::/64")
		h.subscribe(100)
		_, err := mlsbond.Connect(context.Background(), h.addr, "a", netip.MustParsePrefix("fd00:b::/64"), h.orch)
		Expect(status.Code(err)).To(Equal(codes.FailedPrecondition))
		_, err = mlsbond.Connect(context.Background(), h.addr, "a", h.prefix, h.orch)
		Expect(err).NotTo(HaveOccurred(), "the same values again")

		h.unsubscribe(100)
		conn, err := mlsbond.Connect(context.Background(), h.addr, "a", netip.MustParsePrefix("fd00:b::/64"), h.orch)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(conn.Close)
	})
})
