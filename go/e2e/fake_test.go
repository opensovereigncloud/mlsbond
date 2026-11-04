package e2e

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"mlsbond"
)

// order numbers the calls of all fake orchestrators, so that calls on different hosts can be
// put in order.
var order atomic.Int64

type callKind string

const (
	add    callKind = "add"
	update callKind = "update"
	remove callKind = "remove"
)

type call struct {
	kind  callKind
	order int64
	// the added or new Security Association, or the removed ID
	id  mlsbond.SecurityAssociationID
	old mlsbond.SecurityAssociationID
	sa  mlsbond.SecurityAssociation
	err error
}

// fakeOrchestrator holds Security Associations in memory, like dpservice, and records every call.
type fakeOrchestrator struct {
	name string
	mtx  sync.Mutex
	sas  map[mlsbond.SecurityAssociationID]mlsbond.SecurityAssociation
	// calls that succeeded
	calls []call
	// all calls, including the failed ones
	attempts []call
	// returns an error to fail a call
	fail func(call) error
}

func newFakeOrchestrator(name string) *fakeOrchestrator {
	return &fakeOrchestrator{name: name, sas: map[mlsbond.SecurityAssociationID]mlsbond.SecurityAssociation{}}
}

func (f *fakeOrchestrator) record(c call) error {
	c.order = order.Add(1)
	if f.fail != nil {
		c.err = f.fail(c)
	}
	f.attempts = append(f.attempts, c)
	if c.err != nil {
		return c.err
	}
	f.calls = append(f.calls, c)
	return nil
}

func (f *fakeOrchestrator) AddSecurityAssociation(sa mlsbond.SecurityAssociation) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if _, ok := f.sas[sa.ID]; ok {
		return fmt.Errorf("%v already exists", sa.ID)
	}
	if err := f.record(call{kind: add, id: sa.ID, sa: sa}); err != nil {
		return err
	}
	f.sas[sa.ID] = sa
	return nil
}

func (f *fakeOrchestrator) UpdateSecurityAssociation(old mlsbond.SecurityAssociationID, sa mlsbond.SecurityAssociation) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if _, ok := f.sas[old]; !ok {
		return fmt.Errorf("%v not found", old)
	}
	if old.Direction != mlsbond.Egress || sa.ID.Direction != mlsbond.Egress {
		return fmt.Errorf("only egress can be updated")
	}
	if err := f.record(call{kind: update, id: sa.ID, old: old, sa: sa}); err != nil {
		return err
	}
	delete(f.sas, old)
	f.sas[sa.ID] = sa
	return nil
}

func (f *fakeOrchestrator) RemoveSecurityAssociation(id mlsbond.SecurityAssociationID) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if err := f.record(call{kind: remove, id: id}); err != nil {
		return err
	}
	// gone already counts as removed, as for the control plane and dpservice
	delete(f.sas, id)
	return nil
}

func (f *fakeOrchestrator) SecurityAssociations() []mlsbond.SecurityAssociationID {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	ids := make([]mlsbond.SecurityAssociationID, 0, len(f.sas))
	for id := range f.sas {
		ids = append(ids, id)
	}
	return ids
}

// held returns a copy of the Security Associations held.
func (f *fakeOrchestrator) held() map[mlsbond.SecurityAssociationID]mlsbond.SecurityAssociation {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	res := make(map[mlsbond.SecurityAssociationID]mlsbond.SecurityAssociation, len(f.sas))
	for id, sa := range f.sas {
		res[id] = sa
	}
	return res
}

// callsSince returns the successful calls with order > since.
func (f *fakeOrchestrator) callsSince(since int64) []call {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	var res []call
	for _, c := range f.calls {
		if c.order > since {
			res = append(res, c)
		}
	}
	return res
}

func (f *fakeOrchestrator) allCalls() []call {
	return f.callsSince(0)
}

func (f *fakeOrchestrator) setFail(fail func(call) error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.fail = fail
}

// held Security Associations of one direction of a pair, from src's view
func saOf(h *host, vni uint32, dir mlsbond.Direction, src, dst *host) []mlsbond.SecurityAssociation {
	var res []mlsbond.SecurityAssociation
	for id, sa := range h.orch.held() {
		if id.VNI == vni && id.Direction == dir && id.Src == src.underlay() && id.Dst == dst.underlay() {
			res = append(res, sa)
		}
	}
	return res
}

// expectPaired checks that a and b hold exactly the two Security Associations of their pair in
// vni, matching on both ends, and returns a's egress and ingress.
func expectPaired(g Gomega, a, b *host, vni uint32) (egress, ingress mlsbond.SecurityAssociation) {
	ab := expectDirection(g, a, b, vni)
	ba := expectDirection(g, b, a, vni)
	g.Expect(ab.Key).NotTo(Equal(ba.Key), "keys differ per direction")
	g.Expect(ab.Salt).NotTo(Equal(ba.Salt), "salts differ per direction")
	return ab, ba
}

// expectDirection checks the direction from src to dst: one egress on src, one ingress on dst,
// same SPI, key and salt.
func expectDirection(g Gomega, src, dst *host, vni uint32) mlsbond.SecurityAssociation {
	eg := saOf(src, vni, mlsbond.Egress, src, dst)
	in := saOf(dst, vni, mlsbond.Ingress, src, dst)
	g.Expect(eg).To(HaveLen(1), "%s egress towards %s in vni %d", src.name, dst.name, vni)
	g.Expect(in).To(HaveLen(1), "%s ingress from %s in vni %d", dst.name, src.name, vni)
	e, i := eg[0], in[0]
	g.Expect(e.ID.SPI).To(Equal(i.ID.SPI), "%s sends under the SPI %s picked", src.name, dst.name)
	g.Expect(e.ID.SPI).To(BeNumerically(">=", 256))
	g.Expect(bytes.Equal(e.Key, i.Key)).To(BeTrue(), "key %s -> %s", src.name, dst.name)
	g.Expect(bytes.Equal(e.Salt, i.Salt)).To(BeTrue(), "salt %s -> %s", src.name, dst.name)
	g.Expect(e.Key).To(HaveLen(32))
	g.Expect(e.Salt).To(HaveLen(4))
	g.Expect(e.Algorithm).To(Equal("aes-256-gcm"))
	g.Expect(e.ESN).To(BeTrue())
	g.Expect(i.ESN).To(BeTrue())
	g.Expect(e.ReplayWindow).To(BeZero())
	g.Expect(i.ReplayWindow).To(Equal(uint32(64)))
	return e
}

// expectSafeOrder checks the calls of all hosts: an egress is added or switched only after its
// receiver confirmed the matching ingress, and an ingress is removed only once its sender's
// egress is another one (or its pair ended on the remover's side).
func expectSafeOrder(hosts ...*host) {
	GinkgoHelper()
	ingressAdded := map[mlsbond.SecurityAssociationID]int64{}
	for _, h := range hosts {
		for _, c := range h.orch.allCalls() {
			if c.kind == add && c.id.Direction == mlsbond.Ingress {
				ingressAdded[asEgress(c.id)] = c.order
			}
		}
	}
	for _, h := range hosts {
		for _, c := range h.orch.allCalls() {
			switch {
			case c.id.Direction == mlsbond.Egress && (c.kind == add || c.kind == update):
				at, ok := ingressAdded[c.id]
				Expect(ok).To(BeTrue(), "%s: %s of %v without its ingress", h.name, c.kind, c.id)
				Expect(at).To(BeNumerically("<", c.order), "%s: %s of %v before its ingress", h.name, c.kind, c.id)
			case c.kind == remove && c.id.Direction == mlsbond.Ingress:
				Expect(movedOn(hosts, c) || ended(h, c.id)).To(BeTrue(), "%s: removed %v while its sender still used it", h.name, c.id)
			}
		}
	}
}

// movedOn tells whether, when the ingress was removed, its sender's last egress call towards the
// remover installed another egress or removed it.
func movedOn(hosts []*host, removal call) bool {
	in := removal.id
	for _, s := range hosts {
		if s.underlay() != in.Src {
			continue
		}
		var last *call
		for _, c := range s.orch.allCalls() {
			if c.order < removal.order && c.id.Direction == mlsbond.Egress && c.id.VNI == in.VNI && c.id.Dst == in.Dst {
				last = &c
			}
		}
		return last != nil && (last.kind == remove || last.id != asEgress(in))
	}
	// the sender is not one of the hosts checked
	return true
}

// ended tells whether h ended the pair of an ingress: removed its egress towards the sender too.
func ended(h *host, in mlsbond.SecurityAssociationID) bool {
	for _, c := range h.orch.allCalls() {
		if c.kind == remove && c.id.Direction == mlsbond.Egress && c.id.VNI == in.VNI && c.id.Dst == in.Src {
			return true
		}
	}
	return false
}

func asEgress(id mlsbond.SecurityAssociationID) mlsbond.SecurityAssociationID {
	id.Direction = mlsbond.Egress
	return id
}

func asIngress(id mlsbond.SecurityAssociationID) mlsbond.SecurityAssociationID {
	id.Direction = mlsbond.Ingress
	return id
}

const (
	egress  = mlsbond.Egress
	ingress = mlsbond.Ingress
)
