// Package sdnotify tells systemd a Type=notify service is ready. The protocol
// is one datagram to $NOTIFY_SOCKET — too small to justify a dependency.
package sdnotify

import (
	"fmt"
	"net"
	"os"
)

// Ready reports readiness. Outside systemd — no NOTIFY_SOCKET — it does
// nothing. The variable is removed from the environment, as sd_notify's
// unset_environment does: the processes the service runs later — systemctl
// among them — would otherwise inherit it and notify on the service's behalf.
func Ready() error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if err := os.Unsetenv("NOTIFY_SOCKET"); err != nil {
		return fmt.Errorf("unset notify socket: %w", err)
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("dial notify socket: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		return fmt.Errorf("notify ready: %w", err)
	}
	return nil
}
