package probe_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/probe"
	"github.com/lib4u/vnm/internal/testsupport"
)

// SO_MARK needs CAP_NET_ADMIN, which the test has inside its own namespace.
func TestMain(m *testing.M) {
	os.Exit(testsupport.MainInNetns(m))
}

func exitFor(t *testing.T, raw string) policy.Exit {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return policy.Exit{Name: "warp", Iface: "lo", Health: policy.Probe{URL: u, Expect: regexp.MustCompile(`warp=(on|plus)`)}}
}

func server(t *testing.T, body string) (*httptest.Server, *probe.HTTP) {
	t.Helper()
	testsupport.RequireInNetns(t)
	// Loopback exists but is down in a fresh namespace.
	if out, err := testsupport.Shell("ip link set lo up"); err != nil {
		t.Fatalf("lo up: %v %s", err, out)
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts, probe.New(probe.WithRootCAs(ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs))
}

func TestProbeMatches(t *testing.T) {
	ts, p := server(t, "fl=1\nip=104.28.0.1\nwarp=on\n")
	if err := p.Probe(context.Background(), exitFor(t, ts.URL+"/cdn-cgi/trace")); err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

// An answer without the marker — a Cloudflare error page, a captive portal —
// does not confirm that traffic leaves through the exit.
func TestProbeRejectsUnexpectedBody(t *testing.T) {
	ts, p := server(t, "fl=1\nwarp=off\n")
	err := p.Probe(context.Background(), exitFor(t, ts.URL+"/cdn-cgi/trace"))
	if !errors.Is(err, probe.ErrUnexpected) {
		t.Fatalf("want ErrUnexpected, got %v", err)
	}
}

func TestProbeFailsWhenNothingAnswers(t *testing.T) {
	testsupport.RequireInNetns(t)
	p := probe.New()
	if err := p.Probe(context.Background(), exitFor(t, "https://127.0.0.1:1/cdn-cgi/trace")); err == nil {
		t.Fatal("probe of a closed port passed")
	}
}
