package backend

import "testing"

func FuzzParseLifecycleDate(f *testing.F) {
	f.Add("2024-01-01T00:00:00Z")
	f.Add("2024-01-01")
	f.Add("")
	f.Add("not-a-date")
	f.Add("9999-12-31T23:59:59Z")
	f.Add("0000-00-00")

	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseLifecycleDate(value)
	})
}
