package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestNormalizeParallel(t *testing.T) {
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
		{
			name:   "deadline with real subtest failure is not suppressed",
			output: "--- FAIL: FuzzXxx (60.07s)\n    --- FAIL: FuzzXxx/abc123 (0.00s)\n    context deadline exceeded\nFAIL\n",
			want:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDeadlineOnly(tc.output); got != tc.want {
				t.Fatalf("isDeadlineOnly() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNonEmptyLines(t *testing.T) {
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

func stubFuzzOrchestration(
	t *testing.T,
	targets []fuzzTarget,
	discoverErr error,
	runErr error,
) *[]fuzzTarget {
	t.Helper()
	var mu sync.Mutex
	var attempted []fuzzTarget
	restoreDiscover := discoverFuzzTargetsFn
	restoreRun := runFuzzTargetFn
	t.Cleanup(func() {
		discoverFuzzTargetsFn = restoreDiscover
		runFuzzTargetFn = restoreRun
	})
	discoverFuzzTargetsFn = func(context.Context) ([]fuzzTarget, error) {
		return targets, discoverErr
	}
	runFuzzTargetFn = func(_ context.Context, target fuzzTarget, _ string) error {
		mu.Lock()
		attempted = append(attempted, target)
		mu.Unlock()
		return runErr
	}
	return &attempted
}

func TestRun(t *testing.T) {
	t.Run("no targets found", func(t *testing.T) {
		stubFuzzOrchestration(t, nil, nil, nil)
		if err := run(context.Background(), "1s", 2); err != nil {
			t.Fatalf("run() with no targets = %v, want nil", err)
		}
	})

	t.Run("discover error propagates", func(t *testing.T) {
		stubFuzzOrchestration(t, nil, errors.New("list boom"), nil)
		if err := run(context.Background(), "1s", 2); err == nil {
			t.Fatal("run() with discover error = nil, want error")
		}
	})

	t.Run("all targets succeed", func(t *testing.T) {
		targets := []fuzzTarget{{pkg: "a", name: "FuzzA"}, {pkg: "b", name: "FuzzB"}}
		attempted := stubFuzzOrchestration(t, targets, nil, nil)
		if err := run(context.Background(), "1s", 10); err != nil {
			t.Fatalf("run() = %v, want nil", err)
		}
		if len(*attempted) != len(targets) {
			t.Fatalf("attempted %d targets, want %d", len(*attempted), len(targets))
		}
	})

	t.Run("failures are aggregated", func(t *testing.T) {
		targets := []fuzzTarget{{pkg: "a", name: "FuzzA"}, {pkg: "b", name: "FuzzB"}}
		attempted := stubFuzzOrchestration(t, targets, nil, errors.New("fuzz boom"))
		err := run(context.Background(), "1s", 10)
		if err == nil {
			t.Fatal("run() with failing targets = nil, want error")
		}
		if !strings.Contains(err.Error(), "2 fuzz target(s) failed") {
			t.Fatalf("run() error = %q, want failure aggregation", err)
		}
		if len(*attempted) != len(targets) {
			t.Fatalf("attempted %d targets, want %d", len(*attempted), len(targets))
		}
	})
}

func TestDiscoverFuzzTargets(t *testing.T) {
	targets, err := discoverFuzzTargets(context.Background())
	if err != nil {
		t.Fatalf("discoverFuzzTargets() = %v, want nil", err)
	}
	for _, target := range targets {
		if !strings.HasPrefix(target.name, "Fuzz") {
			t.Fatalf("discovered target %q does not start with Fuzz", target.name)
		}
		if target.pkg == "" {
			t.Fatal("discovered target has empty package")
		}
	}
}

func TestDiscoverFuzzTargetsContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := discoverFuzzTargets(ctx); err == nil {
		t.Fatal("discoverFuzzTargets() with canceled context = nil, want error")
	}
}

func TestGoList(t *testing.T) {
	packages, err := goList(context.Background(), ".")
	if err != nil {
		t.Fatalf("goList() = %v, want nil", err)
	}
	if len(packages) == 0 {
		t.Fatal("goList() returned no packages")
	}
	if !strings.HasSuffix(packages[0], "tools/fuzzrunner") {
		t.Fatalf("goList() = %q, want fuzzrunner package", packages)
	}
}

func TestGoListContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := goList(ctx, "."); err == nil {
		t.Fatal("goList() with canceled context = nil, want error")
	}
}

func TestGoTestListFuzz(t *testing.T) {
	names, err := goTestListFuzz(context.Background(), ".")
	if err != nil {
		t.Fatalf("goTestListFuzz() = %v, want nil", err)
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "Fuzz") {
			t.Fatalf("listed fuzz target %q does not start with Fuzz", name)
		}
	}
}

func TestGoTestListFuzzContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := goTestListFuzz(ctx, "."); err == nil {
		t.Fatal("goTestListFuzz() with canceled context = nil, want error")
	}
}

func TestGoTestListFuzzFindsRealTargets(t *testing.T) {
	names, err := goTestListFuzz(
		context.Background(),
		"github.com/yashikota/minis3/internal/backend",
	)
	if err != nil {
		t.Fatalf("goTestListFuzz() = %v, want nil", err)
	}
	if len(names) == 0 {
		t.Fatal("goTestListFuzz() found no fuzz targets in internal/backend")
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "Fuzz") {
			t.Fatalf("listed fuzz target %q does not start with Fuzz", name)
		}
	}
}

func TestDiscoverFuzzTargetsListError(t *testing.T) {
	restore := goTestListFuzzFn
	t.Cleanup(func() {
		goTestListFuzzFn = restore
	})
	goTestListFuzzFn = func(context.Context, string) ([]string, error) {
		return nil, errors.New("list boom")
	}
	if _, err := discoverFuzzTargets(context.Background()); err == nil {
		t.Fatal("discoverFuzzTargets() with listing error = nil, want error")
	}
}

func TestDiscoverFuzzTargetsAccumulatesTargets(t *testing.T) {
	restore := goTestListFuzzFn
	t.Cleanup(func() {
		goTestListFuzzFn = restore
	})
	goTestListFuzzFn = func(_ context.Context, pkg string) ([]string, error) {
		return []string{"FuzzStub"}, nil
	}
	targets, err := discoverFuzzTargets(context.Background())
	if err != nil {
		t.Fatalf("discoverFuzzTargets() = %v, want nil", err)
	}
	if len(targets) == 0 {
		t.Fatal("discoverFuzzTargets() accumulated no targets")
	}
	for _, target := range targets {
		if target.name != "FuzzStub" || target.pkg == "" {
			t.Fatalf("unexpected accumulated target %+v", target)
		}
	}
}

// FuzzNonEmptyLines is a property test for the go-output parser: returned
// lines are never empty and never carry surrounding whitespace, by
// construction. The property holds definitionally, so the fuzzer can never
// find a counterexample; it additionally registers a fast fuzz target for
// the fuzzrunner itself.
func FuzzNonEmptyLines(f *testing.F) {
	f.Add("\n  FuzzOne  \n\nok example/package 0.1s\n")
	f.Add("")
	f.Add("   \n\t\n")
	f.Fuzz(func(t *testing.T, s string) {
		for _, line := range nonEmptyLines(s) {
			if line == "" {
				t.Fatalf("nonEmptyLines(%q) contains empty line", s)
			}
			if strings.TrimSpace(line) != line {
				t.Fatalf("nonEmptyLines(%q) contains untrimmed line %q", s, line)
			}
		}
	})
}

func TestRunMain(t *testing.T) {
	t.Run("invalid flag exits 2", func(t *testing.T) {
		if got := runMain([]string{"-badflag"}, io.Discard); got != 2 {
			t.Fatalf("runMain(-badflag) = %d, want 2", got)
		}
	})

	t.Run("discover error exits 1", func(t *testing.T) {
		stubFuzzOrchestration(t, nil, errors.New("list boom"), nil)
		if got := runMain([]string{"-fuzztime=1s"}, io.Discard); got != 1 {
			t.Fatalf("runMain() with discover error = %d, want 1", got)
		}
	})

	t.Run("no targets exits 0", func(t *testing.T) {
		stubFuzzOrchestration(t, nil, nil, nil)
		if got := runMain([]string{"-fuzztime=1s"}, io.Discard); got != 0 {
			t.Fatalf("runMain() with no targets = %d, want 0", got)
		}
	})
}

// installFakeGo shadows the go toolchain with a script whose output and exit
// status are controlled via FAKE_GO_OUTPUT / FAKE_GO_EXIT, so runFuzzTarget
// can be tested without executing real fuzz runs.
func installFakeGo(t *testing.T, output string, exitCode string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s' \"$FAKE_GO_OUTPUT\"\nexit \"$FAKE_GO_EXIT\"\n"
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake go script failed: %v", err)
	}
	t.Setenv("FAKE_GO_OUTPUT", output)
	t.Setenv("FAKE_GO_EXIT", exitCode)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRunFuzzTarget(t *testing.T) {
	target := fuzzTarget{pkg: "example/pkg", name: "FuzzXxx"}

	t.Run("success", func(t *testing.T) {
		installFakeGo(t, "ok  example/pkg 1.0s\n", "0")
		if err := runFuzzTarget(context.Background(), target, "1s"); err != nil {
			t.Fatalf("runFuzzTarget() = %v, want nil", err)
		}
	})

	t.Run("deadline only is not a failure", func(t *testing.T) {
		installFakeGo(
			t,
			"--- FAIL: FuzzXxx (60.07s)\n    context deadline exceeded\nFAIL\n",
			"1",
		)
		if err := runFuzzTarget(context.Background(), target, "1s"); err != nil {
			t.Fatalf("runFuzzTarget() with deadline-only output = %v, want nil", err)
		}
	})

	t.Run("real failure propagates", func(t *testing.T) {
		installFakeGo(
			t,
			"--- FAIL: FuzzXxx (5.23s)\n    --- FAIL: FuzzXxx/abc123 (0.00s)\nFAIL\n",
			"1",
		)
		err := runFuzzTarget(context.Background(), target, "1s")
		if err == nil {
			t.Fatal("runFuzzTarget() with crashing output = nil, want error")
		}
		if !strings.Contains(err.Error(), "example/pkg FuzzXxx") {
			t.Fatalf("runFuzzTarget() error = %q, want target identification", err)
		}
	})
}
