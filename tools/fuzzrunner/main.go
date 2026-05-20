package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

type fuzzTarget struct {
	pkg  string
	name string
}

func main() {
	fuzzTime := flag.String("fuzztime", "3m", "value for go test -fuzztime")
	parallel := flag.Int(
		"parallel",
		0,
		"number of fuzz targets to run concurrently; 0 uses runtime.NumCPU",
	)
	flag.Parse()

	if err := run(context.Background(), *fuzzTime, normalizeParallel(*parallel)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, fuzzTime string, parallel int) error {
	targets, err := discoverFuzzTargets(ctx)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("no fuzz targets found")
		return nil
	}
	if parallel > len(targets) {
		parallel = len(targets)
	}

	fmt.Printf(
		"running %d fuzz targets with parallel=%d fuzztime=%s\n",
		len(targets),
		parallel,
		fuzzTime,
	)

	jobs := make(chan fuzzTarget)
	errs := make(chan error, len(targets))
	var wg sync.WaitGroup
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if err := runFuzzTarget(ctx, target, fuzzTime); err != nil {
					errs <- err
				}
			}
		}()
	}

	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wg.Wait()
	close(errs)

	var failures []string
	for err := range errs {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf(
			"%d fuzz target(s) failed:\n%s",
			len(failures),
			strings.Join(failures, "\n"),
		)
	}
	return nil
}

func normalizeParallel(parallel int) int {
	if parallel > 0 {
		return parallel
	}
	if n := runtime.NumCPU(); n > 0 {
		return n
	}
	return 1
}

func discoverFuzzTargets(ctx context.Context) ([]fuzzTarget, error) {
	packages, err := goList(ctx, "./...")
	if err != nil {
		return nil, err
	}

	var targets []fuzzTarget
	for _, pkg := range packages {
		names, err := goTestListFuzz(ctx, pkg)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			targets = append(targets, fuzzTarget{pkg: pkg, name: name})
		}
	}
	return targets, nil
}

func goList(ctx context.Context, pattern string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", pattern)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"go list %s failed: %w\n%s",
			pattern,
			err,
			strings.TrimSpace(string(out)),
		)
	}
	return nonEmptyLines(string(out)), nil
}

func goTestListFuzz(ctx context.Context, pkg string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-list", "^Fuzz", pkg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"go test -list ^Fuzz %s failed: %w\n%s",
			pkg,
			err,
			strings.TrimSpace(string(out)),
		)
	}

	var names []string
	for _, line := range nonEmptyLines(string(out)) {
		if strings.HasPrefix(line, "Fuzz") {
			names = append(names, line)
		}
	}
	return names, nil
}

func runFuzzTarget(ctx context.Context, target fuzzTarget, fuzzTime string) error {
	fmt.Printf("fuzz %s %s\n", target.pkg, target.name)
	cmd := exec.CommandContext(
		ctx,
		"go",
		"test",
		target.pkg,
		"-run=^$",
		"-fuzz=^"+target.name+"$",
		"-fuzztime="+fuzzTime,
		"-parallel=1",
	)

	var buf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &buf)

	if err := cmd.Run(); err != nil {
		// Go 1.25+ exits with status 1 and "context deadline exceeded"
		// when a fuzz target reaches its -fuzztime limit. This is expected
		// and not a real failure.
		if isDeadlineOnly(buf.String()) {
			return nil
		}
		return fmt.Errorf("%s %s: %w", target.pkg, target.name, err)
	}
	return nil
}

// isDeadlineOnly returns true when the only failure reason is the fuzz-time
// context deadline being reached (Go 1.25+ behaviour). Real fuzz crashes
// produce sub-test failures (e.g. "--- FAIL: FuzzXxx/corpus-entry") and
// are never suppressed.
func isDeadlineOnly(output string) bool {
	if !strings.Contains(output, "context deadline exceeded") {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--- FAIL:") && strings.Contains(trimmed, "/") {
			return false
		}
	}
	return true
}

func nonEmptyLines(s string) []string {
	scanner := bufio.NewScanner(strings.NewReader(s))
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
