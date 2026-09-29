package netstate

// ExitRules returns the two routing rules of an exit slot, in the order they
// are evaluated.
//
// The lookup rule sends marked packets to the exit's table; the unreachable
// rule right after it catches them when that table has no route — that is,
// whenever the exit's interface is gone. Fail-closed for a missing exit
// therefore holds in the kernel alone, with no agent running (invariant I-2,
// ТЗ §3.3); an exit that is up but declared dead is refused by the dead set.
func ExitRules(slot int) [2]IPRule {
	mark := ExitMark(slot)
	priority := exitPriorityBase + 2*slot
	return [2]IPRule{
		{Priority: priority, Mark: mark, Mask: ExitMarkMask, Action: RuleLookup, Table: ExitTable(slot)},
		{Priority: priority + 1, Mark: mark, Mask: ExitMarkMask, Action: RuleUnreachable},
	}
}
