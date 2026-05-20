package main

import (
	"runtime"
	"testing"
)

func TestNormalizeParallel(t *testing.T) {
	t.Parallel()

	if got := normalizeParallel(3); got != 3 {
		t.Fatalf("normalizeParallel(3) = %d, want 3", got)
	}
	if got := normalizeParallel(0); got != runtime.NumCPU() {
		t.Fatalf("normalizeParallel(0) = %d, want %d", got, runtime.NumCPU())
	}
	if got := normalizeParallel(-1); got != runtime.NumCPU() {
		t.Fatalf("normalizeParallel(-1) = %d, want %d", got, runtime.NumCPU())
	}
}

func TestIsDeadlineOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "deadline only",
			output: "--- FAIL: FuzzXxx (60.07s)\n    context deadline exceeded\nFAIL\n",
			want:   true,
		},
		{
			name:   "real crash",
			output: "--- FAIL: FuzzXxx (5.23s)\n    --- FAIL: FuzzXxx/abc123 (0.00s)\nFAIL\n",
			want:   false,
		},
		{
			name:   "no deadline message",
			output: "--- FAIL: FuzzXxx (5.23s)\n    some other error\nFAIL\n",
			want:   false,
		},
		{
			name:   "pass output",
			output: "PASS\nok  example/pkg 60.058s\n",
			want:   false,
		},
		{
			name:   "seed corpus failure",
			output: "--- FAIL: FuzzXxx (0.00s)\n    --- FAIL: FuzzXxx/seed#0 (0.00s)\n        test.go:14: got true; want false\nFAIL\n",
			want:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isDeadlineOnly(tc.output); got != tc.want {
				t.Fatalf("isDeadlineOnly() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNonEmptyLines(t *testing.T) {
	t.Parallel()

	got := nonEmptyLines("\n  FuzzOne  \n\nok example/package 0.1s\n")
	want := []string{"FuzzOne", "ok example/package 0.1s"}
	if len(got) != len(want) {
		t.Fatalf("len(nonEmptyLines) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("nonEmptyLines()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
