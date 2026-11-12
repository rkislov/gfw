package agent

import (
	"strings"
	"testing"
)

func TestPrintedLabelAssignmentIsGroupedForRestore(t *testing.T) {
	raw := `ct label set ct label & (2 | 64 | 127) | 2 | 4 | 6 counter accept comment "gfw:test"`
	got := restorableRules(raw)
	want := `ct label set (ct label & (2 | 64 | 127)) | (2 | 4 | 6) counter accept comment "gfw:test"`
	if got != want {
		t.Fatal(got)
	}
	if restorableRules(got) != got {
		t.Fatal("normalization is not idempotent")
	}
	unrelated := `ct label & (0 | 1) == 1 counter accept`
	if restorableRules(unrelated) != unrelated || !strings.Contains(got, `comment "gfw:test"`) {
		t.Fatal("unrelated expression changed")
	}
}
