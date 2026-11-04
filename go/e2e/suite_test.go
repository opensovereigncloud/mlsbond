// Package e2e runs real mlsbond server and client processes against fake orchestrators, and
// checks what each host ends up holding.
package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"mlsbond"
	pb "mlsbond/proto"
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	SetDefaultEventuallyTimeout(20 * time.Second)
	SetDefaultEventuallyPollingInterval(50 * time.Millisecond)
	SetDefaultConsistentlyDuration(2 * time.Second)
	RunSpecs(t, "mlsbond end to end")
}

var binDir string

var _ = BeforeSuite(func() {
	binDir = os.Getenv("MLSBOND_BIN")
	if binDir == "" {
		root, err := filepath.Abs("../..")
		Expect(err).NotTo(HaveOccurred())
		cmd := exec.Command("cargo", "build")
		cmd.Dir = root
		cmd.Stdout, cmd.Stderr = GinkgoWriter, GinkgoWriter
		Expect(cmd.Run()).To(Succeed(), "cargo build")
		binDir = filepath.Join(root, "target", "debug")
	}
})

func freeAddr() string {
	l, err := net.Listen("tcp", "[::1]:0")
	Expect(err).NotTo(HaveOccurred())
	defer l.Close()
	return l.Addr().String()
}

// process is one mlsbond binary running, its output going to the Ginkgo log.
type process struct {
	name string
	args []string
	cmd  *exec.Cmd
	done chan struct{}
}

func startProcess(name string, args ...string) *process {
	p := &process{name: name, args: args}
	p.start()
	DeferCleanup(p.kill)
	return p
}

func (p *process) start() {
	p.cmd = exec.Command(filepath.Join(binDir, p.args[0]), p.args[1:]...)
	p.cmd.Env = append(os.Environ(), "RUST_LOG=info")
	out, err := p.cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	p.cmd.Stderr = p.cmd.Stdout
	Expect(p.cmd.Start()).To(Succeed())
	p.done = make(chan struct{})
	go func(out io.Reader, done chan struct{}) {
		s := bufio.NewScanner(out)
		for s.Scan() {
			fmt.Fprintf(GinkgoWriter, "%s %s: %s\n", time.Now().Format("15:04:05.000"), p.name, s.Text())
		}
		close(done)
	}(out, p.done)
}

// kill ends the process at once, as a crash would.
func (p *process) kill() {
	if p.cmd.ProcessState == nil {
		_ = p.cmd.Process.Signal(syscall.SIGKILL)
		<-p.done
		_ = p.cmd.Wait()
	}
}

func (p *process) restart() {
	p.kill()
	p.start()
}

// server is an mlsbond server with its admin API.
type server struct {
	proc  *process
	addr  string
	admin pb.AdminClient
}

func startServer() *server {
	addr, adminAddr := freeAddr(), freeAddr()
	s := &server{addr: addr}
	s.proc = startProcess("server", "mlsbond-server", "--listen", addr, "--admin-listen", adminAddr, "--removal-grace", "1", "--commit-delay-ms", "100")
	s.admin = pb.NewAdminClient(dial(adminAddr))
	Eventually(func() error {
		_, err := s.admin.ListGroups(context.Background(), &pb.ListGroupsRequest{})
		return err
	}).Should(Succeed())
	return s
}

func dial(addr string) *grpc.ClientConn {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(conn.Close)
	return conn
}

func (s *server) group(vni uint32) *pb.GroupStatus {
	res, err := s.admin.ListGroups(context.Background(), &pb.ListGroupsRequest{})
	Expect(err).NotTo(HaveOccurred())
	for _, g := range res.Groups {
		if g.Vni == vni {
			return g
		}
	}
	return nil
}

func (s *server) epoch(vni uint32) uint64 {
	g := s.group(vni)
	if g == nil {
		return 0
	}
	return g.Epoch
}

// host is one host: an mlsbond client process and a fake orchestrator driving it.
type host struct {
	name   string
	prefix netip.Prefix
	addr   string
	client *process
	orch   *fakeOrchestrator
	conn   *mlsbond.Conn
}

func newHost(s *server, name, prefix string) *host {
	h := &host{name: name, prefix: netip.MustParsePrefix(prefix), addr: freeAddr(), orch: newFakeOrchestrator(name)}
	h.client = startProcess(name, "mlsbond-client", "--listen", h.addr, "--server", s.addr, "--stale-pairs-after", "5")
	h.connect()
	return h
}

// connect starts the orchestrator's connection, as on its start.
func (h *host) connect() {
	Eventually(func() error {
		conn, err := mlsbond.Connect(context.Background(), h.addr, h.name, h.prefix, h.orch)
		h.conn = conn
		return err
	}).Should(Succeed())
	conn := h.conn
	DeferCleanup(func() { _ = conn.Close() })
}

func (h *host) subscribe(vnis ...uint32) {
	for _, vni := range vnis {
		Expect(h.conn.Subscribe(context.Background(), vni)).To(Succeed())
	}
}

func (h *host) unsubscribe(vni uint32) {
	Expect(h.conn.Unsubscribe(context.Background(), vni)).To(Succeed())
}

func (h *host) status() *mlsbond.Status {
	s, err := h.conn.Status(context.Background())
	Expect(err).NotTo(HaveOccurred())
	return s
}

func (h *host) underlay() netip.Addr {
	return h.prefix.Addr()
}
