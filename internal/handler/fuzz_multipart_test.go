package handler

import (
	"math"
	"regexp"
	"strconv"
	"testing"
)

func FuzzParseByteRange(f *testing.F) {
	f.Add("bytes=0-100")
	f.Add("bytes=50-200")
	f.Add("")
	f.Add("bytes=-1")
	f.Add("bytes=0-")
	f.Add("items=0-100")
	f.Add("bytes=abc-def")
	f.Add("bytes=0-0")
	f.Add("bytes=100-50")
	f.Add("bytes=9223372036854775807-9223372036854775807")
	f.Add("bytes=-9223372036854775807")
	f.Add("bytes=0-9223372036854775807")
	f.Add("BYTES=0-100")
	f.Add("bytes =0-100")
	f.Add("bytes=0 - 100")

	f.Add("bytes=+1-+2")
	copySourceRange := regexp.MustCompile(`\Abytes=([0-9]+)-([0-9]+)\z`)
	f.Fuzz(func(t *testing.T, rangeHeader string) {
		start, end, err := parseByteRange(rangeHeader)
		m := copySourceRange.FindStringSubmatch(rangeHeader)
		if m == nil {
			if err == nil {
				t.Fatalf("parseByteRange(%q) = (%d, %d), want an error", rangeHeader, start, end)
			}
			return
		}
		// Positions past int64 saturate.
		wantStart, wantEnd := saturatingInt64(m[1]), saturatingInt64(m[2])
		if wantStart > wantEnd {
			if err == nil {
				t.Fatalf("parseByteRange(%q) accepted a reversed range", rangeHeader)
			}
			return
		}
		if err != nil || start != wantStart || end != wantEnd {
			t.Fatalf("parseByteRange(%q) = (%d, %d, %v), want (%d, %d)",
				rangeHeader, start, end, err, wantStart, wantEnd)
		}
	})
}

func saturatingInt64(digits string) int64 {
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return math.MaxInt64
	}
	return n
}
