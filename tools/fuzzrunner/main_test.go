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
