package testsupport

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

var (
	netnsOnce sync.Once
	netnsOK   bool
)

// RequireNetns skips the test unless an unprivileged user and network namespace
// can be created and nft can load a table inside it. That is enough to check
// rulesets against the real kernel without root and without touching the host.
func RequireNetns(t *testing.T) {
	t.Helper()
	netnsOnce.Do(func() {
		cmd := exec.Command("unshare", "-Urn", "nft", "add", "table", "inet", "probe")
		netnsOK = cmd.Run() == nil
	})
	if !netnsOK {
		t.Skip("unprivileged network namespaces with nft are not available")
	}
}

// InNetns runs a shell script inside a fresh user and network namespace and
// returns its combined output. The namespace dies with the script.
func InNetns(t *testing.T, script string) (string, error) {
	t.Helper()
	cmd := exec.Command("unshare", "-Urn", "sh", "-euc", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// inNetnsEnv marks a test binary re-executed inside its own namespaces.
const inNetnsEnv = "VNM_TEST_IN_NETNS"

// MainInNetns is a TestMain body for packages whose tests drive the real nft
// and ip tools. It re-executes the test binary inside a fresh user and network
// namespace, so the tests change a throwaway kernel state instead of the host's.
// Where namespaces are unavailable, the tests run in place and RequireInNetns
// skips them.
func MainInNetns(m *testing.M) int {
	if os.Getenv(inNetnsEnv) != "" {
		return m.Run()
	}
	if exec.Command("unshare", "-Urn", "true").Run() != nil {
		return m.Run()
	}
	cmd := exec.Command("unshare", append([]string{"-Urn"}, os.Args...)...)
	cmd.Env = append(os.Environ(), inNetnsEnv+"=1")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "re-exec in a network namespace: %v\n", err)
		return 1
	}
	return 0
}

// RequireInNetns skips the test unless it runs inside the namespace set up by
// MainInNetns.
func RequireInNetns(t *testing.T) {
	t.Helper()
	if os.Getenv(inNetnsEnv) == "" {
		t.Skip("needs its own network namespace (unshare unavailable)")
	}
}

// Shell runs a script in the test's own namespaces — inside the one set up by
// MainInNetns when the test runs there.
func Shell(script string) (string, error) {
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
