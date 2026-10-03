package kernel

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/ndpid"
	"github.com/lib4u/vnm/internal/infrastructure/nftables"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/p2pwatch"
)

// The whole classifier path with the real parts (p2p ТЗ §8): nDPId reads a
// capture of BitTorrent peer connections and writes its verdicts to the
// agent's listener; the watcher refuses the peers; the kernel set holds them.
//
// nDPId is not part of the repository (GPL-3.0, its own build): the test runs
// when VNM_TEST_NDPID names its binary and VNM_TEST_PCAP a capture of
// BitTorrent — libnDPI's tests/cfgs/default/pcap/bittorrent.pcap.
func TestP2PWithNDPId(t *testing.T) {
	bin, pcap := os.Getenv("VNM_TEST_NDPID"), os.Getenv("VNM_TEST_PCAP")
	if bin == "" || pcap == "" {
		t.Skip("VNM_TEST_NDPID and VNM_TEST_PCAP are not set")
	}
	r := newRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	in := testsupport.PlanInput()
	socket := filepath.Join(t.TempDir(), "ndpid.sock")
	in.Policy.P2P = policy.P2P{
		Mode: policy.ModeEnforce, Signatures: policy.Signatures,
		NDPI: policy.NDPI{Enabled: true, Socket: socket, PeerTTL: 5 * time.Minute},
		Ban:  policy.Ban{Threshold: 5, Window: 5 * time.Minute, TTL: 10 * time.Minute},
	}
	state := testsupport.MustPlan(t, in)
	if err := r.applier.Apply(ctx, state); err != nil {
		t.Fatal(err)
	}

	w := p2pwatch.New(p2pwatch.Deps{
		Sets: &nftables.P2PSets{}, Listener: &ndpid.Listener{},
		Local: func(netip.Addr) bool { return false },
		GID:   os.Getgid(),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now,
	})
	w.Update(ctx, in.Policy.P2P, true)

	// In the test's user namespace we are root; nDPId must not drop to nobody.
	cmd := exec.CommandContext(ctx, bin, "-i", pcap, "-c", socket, "-u", "root", "-g", "root", "-a", "test",
		"-p", filepath.Join(t.TempDir(), "ndpid.pid"), "-o", "max-reader-threads=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	for w.Stats().Peers == 0 && ctx.Err() == nil {
		time.Sleep(100 * time.Millisecond)
	}
	st := w.Stats()
	if st.Detections == 0 || st.Peers == 0 {
		t.Fatalf("stats = %+v: nDPId's verdicts did not arrive", st)
	}
	// The first BitTorrent peer of the capture.
	if out := r.sh(t, "nft list set inet vnm p2p_peers4"); !strings.Contains(out, "82.58.216.115") {
		t.Fatalf("the peer is not refused:\n%s", out)
	}
}
