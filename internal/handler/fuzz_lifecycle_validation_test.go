package handler

import (
	"encoding/xml"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzValidateLifecycleConfiguration(f *testing.F) {
	f.Add(
		[]byte(
			`<LifecycleConfiguration><Rule><ID>rule1</ID><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`,
		),
	)
	f.Add(
		[]byte(
			`<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><Date>2024-01-01T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>`,
		),
	)
	f.Add(
		[]byte(
			`<LifecycleConfiguration><Rule><Status>Invalid</Status></Rule></LifecycleConfiguration>`,
		),
	)
	f.Add(
		[]byte(
			`<LifecycleConfiguration><Rule><ID>rule1</ID><Status>Enabled</Status></Rule><Rule><ID>rule1</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>`,
		),
	)
	f.Add(
		[]byte(
			`<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><Days>30</Days><Date>2024-01-01T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>`,
		),
	)
	f.Add(
		[]byte(
			`<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule></LifecycleConfiguration>`,
		),
	)
	f.Add(
		[]byte(
			`<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><Days>-1</Days></Expiration></Rule></LifecycleConfiguration>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var config backend.LifecycleConfiguration
		if err := xml.Unmarshal(data, &config); err != nil {
			return
		}
		_, _, _ = validateLifecycleConfiguration(&config)
	})
}

func FuzzNormalizeLoggingType(f *testing.F) {
	f.Add("Standard")
	f.Add("Journal")
	f.Add("JOURNAL")
	f.Add("journal")
	f.Add("")
	f.Add("invalid")
	f.Add("standard")

	f.Fuzz(func(t *testing.T, loggingType string) {
		_ = normalizeLoggingType(loggingType)
	})
}
