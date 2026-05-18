package handler

import "testing"

func FuzzParseCORSRequestHeaders(f *testing.F) {
	f.Add("Content-Type, Authorization")
	f.Add("")
	f.Add("x-amz-date")
	f.Add("  ,  ,  ")
	f.Add("a,b,c,d,e,f,g")
	f.Add("Content-Type")
	f.Add("X-Amz-Date, X-Amz-Security-Token, Authorization")
	f.Add(",,,,,")
	f.Add(" ")
	f.Add("Accept-Encoding, Accept-Language, Content-Language, Content-Type")

	f.Fuzz(func(t *testing.T, value string) {
		_ = parseCORSRequestHeaders(value)
	})
}

func FuzzCorsHeaderMatch(f *testing.F) {
	f.Add("*", "Content-Type")
	f.Add("x-amz-*", "x-amz-date")
	f.Add("exact", "exact")
	f.Add("", "")
	f.Add("*a*b*c*", "xaxbxcx")
	f.Add("x-amz-*", "x-amz-server-side-encryption")
	f.Add("content-*", "content-type")
	f.Add("*-type", "content-type")
	f.Add("x-*-meta-*", "x-amz-meta-custom")
	f.Add("*", "")

	f.Fuzz(func(t *testing.T, pattern, header string) {
		_ = corsHeaderMatch(pattern, header)
	})
}

func FuzzCorsRequestHeadersAllowed(f *testing.F) {
	f.Add("Content-Type, x-amz-date")
	f.Add("")
	f.Add("Authorization")
	f.Add("a, b, c, d, e")
	f.Add("X-Amz-Date, X-Amz-Security-Token, Authorization, Content-Type")
	f.Add("x-amz-meta-custom-header")

	f.Fuzz(func(t *testing.T, requestHeaders string) {
		allowed := []string{"*"}
		_ = corsRequestHeadersAllowed(requestHeaders, allowed)
	})
}
