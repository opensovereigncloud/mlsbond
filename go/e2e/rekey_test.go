package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"mlsbond"
	pb "mlsbond/proto"
)

// threeHosts starts three hosts in vni and waits for all their pairs.
func threeHosts(s *server, vni uint32) []*host {
	GinkgoHelper()
	hosts := []*host{newHost(s, "a", "fd00:a::/64"), newHost(s, "b", "fd00:b::/64"), newHost(s, "c", "fd00:c::/64")}
	for _, h := range hosts {
		h.subscribe(vni)
	}
	Eventually(func(g Gomega) { expectAllPaired(g, hosts, vni) }).Should(Succeed())
	return hosts
}

func expectAllPaired(g Gomega, hosts []*host, vni uint32) {
	for i, x := range hosts {
		for _, y := range hosts[i+1:] {
			expectPaired(g, x, y, vni)
		}
		n := 0
		for id := range x.orch.held() {
			if id.VNI == vni {
				n++
			}
		}
		g.Expect(n).To(Equal(2*(len(hosts)-1)), "%s holds only its pairs in vni %d", x.name, vni)
	}
}

// keysOf returns the keys held per Security Association ID.
func keysOf(hosts []*host) map[mlsbond.SecurityAssociationID]string {
	res := map[mlsbond.SecurityAssociationID]string{}
	for _, h := range hosts {
		for id, sa := range h.orch.held() {
			res[id] = string(sa.Key)
		}
	}
	return res
}

// expectAllReplaced waits until every pair of hosts holds key material none of them held in old.
func expectAllReplaced(hosts []*host, vni uint32, old map[mlsbond.SecurityAssociationID]string) {
	GinkgoHelper()
	oldKeys := map[string]bool{}
	for _, k := range old {
		oldKeys[k] = true
	}
	Eventually(func(g Gomega) {
		expectAllPaired(g, hosts, vni)
		for id, k := range keysOf(hosts) {
			g.Expect(oldKeys).NotTo(HaveKey(k), "%v still has an old key", id)
		}
	}).Should(Succeed())
}

var _ = Describe("Rekeys", func() {
	var s *server

	BeforeEach(func() {
		s = startServer()
	})

	It("does not rekey without a trigger", func() {
		hosts := threeHosts(s, 100)
		before := order.Load()
		Consistently(func() int {
			n := 0
			for _, h := range hosts {
				n += len(h.orch.callsSince(before))
			}
			return n
		}, 3*time.Second).Should(BeZero())
	})

	It("moves every pair to a new epoch through updates on request", func() {
		hosts := threeHosts(s, 100)
		old := keysOf(hosts)
		before := order.Load()

		_, err := s.admin.Rekey(context.Background(), &pb.RekeyRequest{Vni: 100})
		Expect(err).NotTo(HaveOccurred())
		expectAllReplaced(hosts, 100, old)

		for _, h := range hosts {
			calls := h.orch.callsSince(before)
			Expect(calls).To(HaveLen(2*3), "%s: per peer an ingress added, the egress updated, the old ingress removed", h.name)
			for _, c := range calls {
				Expect(c.id.Direction == ingress || c.kind == update).To(BeTrue(), "%s: egress only ever updated: %v", h.name, c)
			}
		}
		expectSafeOrder(hosts...)
	})

	It("rekeys periodically under a per-VNI policy, and stops when it is cleared", func() {
		hosts := threeHosts(s, 100)
		_, err := s.admin.SetVNIPolicy(context.Background(), &pb.SetVNIPolicyRequest{Vni: 100, Policy: &pb.RekeyPolicy{IntervalSeconds: 2}})
		Expect(err).NotTo(HaveOccurred())

		old := keysOf(hosts)
		expectAllReplaced(hosts, 100, old)
		old = keysOf(hosts)
		expectAllReplaced(hosts, 100, old)
		expectSafeOrder(hosts...)

		_, err = s.admin.ClearVNIPolicy(context.Background(), &pb.ClearVNIPolicyRequest{Vni: 100})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func(g Gomega) { expectAllPaired(g, hosts, 100) }).Should(Succeed())
		epoch := s.epoch(100)
		Consistently(func() uint64 { return s.epoch(100) }, 4*time.Second).Should(Equal(epoch))
	})

	It("restarts the periodic timer after any rekey", func() {
		hosts := threeHosts(s, 100)
		_, err := s.admin.SetPolicy(context.Background(), &pb.SetPolicyRequest{Policy: &pb.RekeyPolicy{IntervalSeconds: 4}})
		Expect(err).NotTo(HaveOccurred())
		time.Sleep(2 * time.Second)
		_, err = s.admin.Rekey(context.Background(), &pb.RekeyRequest{Vni: 100})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() uint64 { return s.epoch(100) }).Should(BeNumerically(">=", 2))
		epoch := s.epoch(100)
		// the periodic rekey due 4s after the start does not come 2s after the manual one
		Consistently(func() uint64 { return s.epoch(100) }, 3*time.Second).Should(Equal(epoch))
		Eventually(func() uint64 { return s.epoch(100) }, 4*time.Second).Should(Equal(epoch + 1))
		Eventually(func(g Gomega) { expectAllPaired(g, hosts, 100) }).Should(Succeed())
	})

	DescribeTable("on removal",
		func(rekeyOnRemoval bool, leave func(*host)) {
			hosts := threeHosts(s, 100)
			if rekeyOnRemoval {
				_, err := s.admin.SetPolicy(context.Background(), &pb.SetPolicyRequest{Policy: &pb.RekeyPolicy{RekeyOnRemoval: true}})
				Expect(err).NotTo(HaveOccurred())
			}
			a, b, c := hosts[0], hosts[1], hosts[2]
			ab, ba := expectPaired(Default, a, b, 100)
			before := order.Load()

			leave(c)
			Eventually(func(g Gomega) { expectAllPaired(g, hosts[:2], 100) }).Should(Succeed())
			for _, h := range hosts[:2] {
				removed := 0
				for _, cl := range h.orch.callsSince(before) {
					if cl.kind == remove && (cl.id.Src == c.underlay() || cl.id.Dst == c.underlay()) {
						removed++
					}
				}
				Expect(removed).To(Equal(2), "%s removed both Security Associations with c", h.name)
			}
			if rekeyOnRemoval {
				expectAllReplaced(hosts[:2], 100, map[mlsbond.SecurityAssociationID]string{ab.ID: string(ab.Key), ba.ID: string(ba.Key)})
			} else {
				Consistently(func(g Gomega) {
					ab2, ba2 := expectPaired(g, a, b, 100)
					g.Expect(ab2).To(Equal(ab))
					g.Expect(ba2).To(Equal(ba))
				}).Should(Succeed())
			}
			expectSafeOrder(hosts...)
		},
		Entry("keeps the remaining pairs when off, after an unsubscribe", false, func(h *host) { h.unsubscribe(100) }),
		Entry("keeps the remaining pairs when off, after the client vanished", false, func(h *host) { h.client.kill() }),
		Entry("rekeys the remaining pairs when on", true, func(h *host) { h.unsubscribe(100) }),
	)

	It("hands the committer role on when the committer vanishes", func() {
		hosts := threeHosts(s, 100)
		a, b, c := hosts[0], hosts[1], hosts[2]
		Expect(s.group(100).Committer).To(Equal(a.prefix.String()))
		a.client.kill()
		Eventually(func(g Gomega) { expectAllPaired(g, []*host{b, c}, 100) }).Should(Succeed())
		Expect(s.group(100).Committer).To(Equal(b.prefix.String()))

		old := keysOf([]*host{b, c})
		_, err := s.admin.Rekey(context.Background(), &pb.RekeyRequest{Vni: 100})
		Expect(err).NotTo(HaveOccurred())
		expectAllReplaced([]*host{b, c}, 100, old)
	})

	It("removes all Security Associations of a VNI on unsubscribe", func() {
		hosts := threeHosts(s, 100)
		hosts[0].unsubscribe(100)
		Eventually(hosts[0].orch.held).Should(BeEmpty())
	})
})
