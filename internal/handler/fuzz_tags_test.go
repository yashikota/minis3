package handler

import (
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzValidateTags(f *testing.F) {
	f.Add("key1=value1&key2=value2")
	f.Add("")
	f.Add("k=v&k2=v2&k3=v3&k4=v4&k5=v5&k6=v6&k7=v7&k8=v8&k9=v9&k10=v10&k11=v11")
	f.Add(strings.Repeat("k", 129) + "=v")
	f.Add("k=" + strings.Repeat("v", 257))
	f.Add("a=b")

	f.Fuzz(func(t *testing.T, tagStr string) {
		tags := parseTaggingHeader(tagStr)
		if tags != nil {
			_, _ = validateTags(tags)
		}
	})
}

func FuzzValidateTagSet(f *testing.F) {
	f.Add("key", "value")
	f.Add("", "")
	f.Add(strings.Repeat("k", 129), "v")
	f.Add("k", strings.Repeat("v", 257))

	f.Fuzz(func(t *testing.T, key, value string) {
		tagSet := []backend.Tag{{Key: key, Value: value}}
		_, _ = validateTagSet(tagSet)
	})
}

func FuzzParsePostTaggingXML(f *testing.F) {
	f.Add(`<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>`)
	f.Add(`<Tagging><TagSet></TagSet></Tagging>`)
	f.Add("")
	f.Add("not xml")
	f.Add(`<Tagging><TagSet><Tag><Key></Key><Value></Value></Tag></TagSet></Tagging>`)
	f.Add(
		`<Tagging><TagSet><Tag><Key>` + strings.Repeat(
			"k",
			200,
		) + `</Key><Value>v</Value></Tag></TagSet></Tagging>`,
	)

	f.Fuzz(func(t *testing.T, xml string) {
		_, _, _ = parsePostTaggingXML(xml)
	})
}
