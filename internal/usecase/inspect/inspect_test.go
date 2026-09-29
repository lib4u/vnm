package inspect_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/inspect"
)

type kernel struct{ live inspect.Live }

func (k kernel) Live(context.Context, netip.Addr) (inspect.Live, error) { return k.live, nil }

type store struct {
	state netstate.State
	ok    bool
}

func (s store) LastGood() (netstate.State, bool, error) { return s.state, s.ok, nil }

func applied(t *testing.T, mode policy.Mode) store {
	in := testsupport.PlanInput()
	in.Policy.Mode = mode
	return store{state: testsupport.MustPlan(t, in), ok: true}
}

func TestExplain(t *testing.T) {
	yandex := netip.MustParseAddr("77.88.55.88")
	tests := []struct {
		name    string
		mode    policy.Mode
		addr    netip.Addr
		live    inspect.Live
		want    inspect.Outcome
		would   inspect.Outcome
		matches int
	}{
		{
			name: "listed address goes through the exit",
			mode: policy.ModeEnforce, addr: yandex,
			live: inspect.Live{Present: true, Holding: map[string]bool{"ru_ip_4": true, "ru_suffix_d4": true}},
			want: inspect.OutcomeExit, would: inspect.OutcomeExit, matches: 2,
		},
		{
			name: "dead exit refuses at once",
			mode: policy.ModeEnforce, addr: yandex,
			live: inspect.Live{Present: true, Holding: map[string]bool{"ru_ip_4": true}, Health: netstate.Health{DeadSlots: []int{0}}},
			want: inspect.OutcomeRefused, would: inspect.OutcomeRefused, matches: 1,
		},
		{
			name: "observe counts but lets it out",
			mode: policy.ModeObserve, addr: yandex,
			live: inspect.Live{Present: true, Holding: map[string]bool{"ru_ip_4": true}},
			want: inspect.OutcomeDirect, would: inspect.OutcomeExit, matches: 1,
		},
		{
			name: "unlisted address is direct",
			mode: policy.ModeEnforce, addr: netip.MustParseAddr("8.8.8.8"),
			live: inspect.Live{Present: true},
			want: inspect.OutcomeDirect, would: inspect.OutcomeDirect,
		},
		{
			name: "exempt beats every list",
			mode: policy.ModeEnforce, addr: netip.MustParseAddr("10.1.2.3"),
			live: inspect.Live{Present: true, Holding: map[string]bool{"ru_ip_4": true}},
			want: inspect.OutcomeDirect, would: inspect.OutcomeDirect, matches: 1,
		},
		{
			name: "no table, nothing classified",
			mode: policy.ModeEnforce, addr: yandex,
			live: inspect.Live{},
			want: inspect.OutcomeUnmanaged, would: inspect.OutcomeUnmanaged,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex, err := inspect.New(kernel{tt.live}, applied(t, tt.mode)).Explain(context.Background(), tt.addr)
			if err != nil {
				t.Fatal(err)
			}
			if ex.Outcome != tt.want || ex.Would != tt.would || len(ex.Matches) != tt.matches {
				t.Fatalf("outcome %d would %d matches %+v", ex.Outcome, ex.Would, ex.Matches)
			}
			if tt.want == inspect.OutcomeExit && (ex.Exit == nil || ex.Exit.Iface != "warp") {
				t.Fatalf("exit = %+v", ex.Exit)
			}
		})
	}
}

// The guard's side: a listed source is refused, an exempt one never.
func TestExplainInbound(t *testing.T) {
	scanner := inspect.Live{Present: true, Holding: map[string]bool{"scanners_4": true}}
	ex, err := inspect.New(kernel{scanner}, applied(t, policy.ModeEnforce)).Explain(context.Background(), testsupport.Scanner)
	if err != nil || ex.Guarded == nil || ex.Guarded.List != "scanners" || ex.GuardObserve {
		t.Fatalf("scanner: %+v %v", ex, err)
	}
	ex, err = inspect.New(kernel{scanner}, applied(t, policy.ModeEnforce)).Explain(context.Background(), testsupport.Management.Addr())
	if err != nil || ex.Guarded != nil {
		t.Fatalf("exempt source refused: %+v %v", ex.Guarded, err)
	}
}
