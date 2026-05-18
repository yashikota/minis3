package backend

import "testing"

func FuzzParseVersioningStatus(f *testing.F) {
	f.Add("Enabled")
	f.Add("Suspended")
	f.Add("")
	f.Add("enabled")
	f.Add("ENABLED")
	f.Add(" Enabled ")

	f.Fuzz(func(t *testing.T, s string) {
		_ = ParseVersioningStatus(s)
	})
}

func FuzzParseMFADeleteStatus(f *testing.F) {
	f.Add("Enabled")
	f.Add("Disabled")
	f.Add("")
	f.Add("enabled")

	f.Fuzz(func(t *testing.T, s string) {
		_ = ParseMFADeleteStatus(s)
	})
}
