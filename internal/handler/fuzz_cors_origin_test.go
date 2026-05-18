package handler

import "testing"

func FuzzCorsOriginMatch(f *testing.F) {
	f.Add("*", "http://example.com")
	f.Add("http://example.com", "http://example.com")
	f.Add("http://*.example.com", "http://sub.example.com")
	f.Add("http://example.com", "http://other.com")
	f.Add("", "")
	f.Add("http://[::1]", "http://[::1]")
	f.Add("http://localhost:*", "http://localhost:3000")
	f.Add("https://*", "https://anything.com")
	f.Add("http://?.example.com", "http://a.example.com")
	f.Add("[invalid-pattern", "anything")

	f.Fuzz(func(t *testing.T, pattern, origin string) {
		_ = corsOriginMatch(pattern, origin)
	})
}
