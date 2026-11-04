package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hosts subscribing a VNI", func() {
	var s *server

	BeforeEach(func() {
		s = startServer()
	})

	It("gives two hosts matching Security Associations in both directions", func() {
		a := newHost(s, "a", "fd00:a::/64")
		b := newHost(s, "b", "fd00:b::/64")
		a.subscribe(100)
		b.subscribe(100)

		Eventually(func(g Gomega) { expectPaired(g, a, b, 100) }).Should(Succeed())
		Expect(a.orch.held()).To(HaveLen(2))
		Expect(b.orch.held()).To(HaveLen(2))
		expectSafeOrder(a, b)
	})

	It("gives every pair of three hosts its own keys, under SPIs each receiver picked uniquely", func() {
		hosts := []*host{newHost(s, "a", "fd00:a::/64"), newHost(s, "b", "fd00:b::/64"), newHost(s, "c", "fd00:c::/64")}
		for _, h := range hosts {
			h.subscribe(100)
		}

		Eventually(func(g Gomega) {
			for i, x := range hosts {
				for _, y := range hosts[i+1:] {
					expectPaired(g, x, y, 100)
				}
			}
		}).Should(Succeed())
		keys := map[string]bool{}
		for _, h := range hosts {
			Expect(h.orch.held()).To(HaveLen(4))
			spis := map[uint32]bool{}
			for id, sa := range h.orch.held() {
				if id.Direction.String() == "ingress" {
					Expect(spis).NotTo(HaveKey(id.SPI), "%s picked SPI %d twice", h.name, id.SPI)
					spis[id.SPI] = true
				}
				keys[fmt.Sprintf("%x", sa.Key)] = true
			}
		}
		Expect(keys).To(HaveLen(6), "one key per direction of each pair")
		expectSafeOrder(hosts...)
	})

	It("keeps two VNIs shared by the same hosts independent", func() {
		a := newHost(s, "a", "fd00:a::/64")
		b := newHost(s, "b", "fd00:b::/64")
		a.subscribe(100, 200)
		b.subscribe(100, 200)

		Eventually(func(g Gomega) {
			expectPaired(g, a, b, 100)
			expectPaired(g, a, b, 200)
		}).Should(Succeed())
		e100, _ := expectPaired(Default, a, b, 100)
		e200, _ := expectPaired(Default, a, b, 200)
		Expect(e100.Key).NotTo(Equal(e200.Key))

		before := order.Load()
		b.unsubscribe(200)
		Eventually(func(g Gomega) {
			g.Expect(saOf(a, 200, egress, a, b)).To(BeEmpty())
			g.Expect(saOf(a, 200, ingress, b, a)).To(BeEmpty())
		}).Should(Succeed())
		Consistently(func(g Gomega) { expectPaired(g, a, b, 100) }).Should(Succeed())
		for _, c := range append(a.orch.callsSince(before), b.orch.callsSince(before)...) {
			Expect(c.id.VNI).To(Equal(uint32(200)), "vni 100 untouched")
		}
	})

	It("sets up only the newcomer's pairs when a host joins later", func() {
		a := newHost(s, "a", "fd00:a::/64")
		b := newHost(s, "b", "fd00:b::/64")
		a.subscribe(100)
		b.subscribe(100)
		Eventually(func(g Gomega) { expectPaired(g, a, b, 100) }).Should(Succeed())
		ab, ba := expectPaired(Default, a, b, 100)

		before := order.Load()
		c := newHost(s, "c", "fd00:c::/64")
		c.subscribe(100)
		Eventually(func(g Gomega) {
			expectPaired(g, a, c, 100)
			expectPaired(g, b, c, 100)
		}).Should(Succeed())

		ab2, ba2 := expectPaired(Default, a, b, 100)
		Expect(ab2).To(Equal(ab))
		Expect(ba2).To(Equal(ba))
		for _, h := range []*host{a, b} {
			for _, cl := range h.orch.callsSince(before) {
				Expect(cl.kind).To(Equal(add), "%s: only adds", h.name)
				Expect([]any{cl.id.Src, cl.id.Dst}).To(ContainElement(c.underlay()), "%s: only pairs with c", h.name)
			}
		}
		expectSafeOrder(a, b, c)
	})

	It("adds hosts subscribing at once in one commit", func() {
		var hosts []*host
		for i := 1; i <= 5; i++ {
			hosts = append(hosts, newHost(s, fmt.Sprintf("h%d", i), fmt.Sprintf("fd00:%d::/64", i)))
		}
		for _, h := range hosts {
			go func() {
				defer GinkgoRecover()
				h.subscribe(300)
			}()
		}
		Eventually(func(g Gomega) {
			for _, h := range hosts {
				g.Expect(h.orch.held()).To(HaveLen(8), h.name)
			}
		}).Should(Succeed())
		Expect(s.group(300).Members).To(HaveLen(5))
		Expect(s.epoch(300)).To(Equal(uint64(1)), "one commit adds the four that did not create the group")
	})
})
