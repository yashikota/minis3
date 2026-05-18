package handler

import "testing"

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

	f.Fuzz(func(t *testing.T, rangeHeader string) {
		_, _, _ = parseByteRange(rangeHeader)
	})
}
