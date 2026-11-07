package e2e

import (
	"fmt"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("mlsbond-client status", func() {
	It("shows the VNIs, and each pair's epoch, SPIs and what it waits on", func() {
		s := startServer()
		a := newHost(s, "a", "fd00:a::/64")
		b := newHost(s, "b", "fd00:b::/64")
		a.subscribe(100)
		b.subscribe(100)
		Eventually(func(g Gomega) { expectPaired(g, a, b, 100) }).Should(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(a.status().Pairs).To(HaveLen(1))
			g.Expect(a.status().Pairs[0].PairEpoch).NotTo(BeNil())
			g.Expect(a.status().Pairs[0].Waiting.String()).To(Equal("nothing"))
		}).Should(Succeed())
		pair := a.status().Pairs[0]

		out, err := exec.Command(filepath.Join(binDir, "mlsbond-client"), "status", "--address", a.addr).CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
		Expect(string(out)).To(ContainSubstring("client a, host prefix fd00:a::/64"))
		Expect(string(out)).To(ContainSubstring("vnis: 100"))
		Expect(string(out)).To(ContainSubstring(fmt.Sprintf("vni 100 pair fd00:b::/64: epoch %d, spi out %d in %d, waiting: nothing",
			*pair.PairEpoch, pair.EgressSPI, pair.IngressSPIs[0])))
	})

	It("fails if nothing listens", func() {
		out, err := exec.Command(filepath.Join(binDir, "mlsbond-client"), "status", "--address", freeAddr()).CombinedOutput()
		Expect(err).To(HaveOccurred(), string(out))
	})
})
