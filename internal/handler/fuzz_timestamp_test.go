package handler

import "testing"

func FuzzParseTimestampFlexible(f *testing.F) {
	f.Add("2024-01-15T10:30:00Z")
	f.Add("2024-01-15T10:30:00.123456789Z")
	f.Add("Mon, 15 Jan 2024 10:30:00 GMT")
	f.Add("")
	f.Add("not-a-timestamp")
	f.Add("9999-99-99T99:99:99Z")
	f.Add("2024-01-15T10:30:00+09:00")

	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseTimestampFlexible(value)
	})
}

func FuzzParseLifecycleExpirationDate(f *testing.F) {
	f.Add("2024-01-15T00:00:00Z")
	f.Add("2024-01-15")
	f.Add("")
	f.Add("not-a-date")
	f.Add("1999-12-31")
	f.Add("2000-01-01T00:00:00Z")

	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseLifecycleExpirationDate(value)
	})
}
