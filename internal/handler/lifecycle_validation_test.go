package handler

import (
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestValidateLifecycleConfiguration(t *testing.T) {
	t.Run("rejects invalid status", func(t *testing.T) {
		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:     "rule1",
					Status: "enabled",
					Expiration: &backend.LifecycleExpiration{
						Days: 1,
					},
				},
			},
		}
		code, _, ok := validateLifecycleConfiguration(cfg)
		if ok || code != "MalformedXML" {
			t.Fatalf("expected MalformedXML, got ok=%v code=%q", ok, code)
		}
	})

	t.Run("rejects duplicate rule ID", func(t *testing.T) {
		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:     "rule1",
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						Days: 1,
					},
				},
				{
					ID:     "rule1",
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						Days: 2,
					},
				},
			},
		}
		code, _, ok := validateLifecycleConfiguration(cfg)
		if ok || code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got ok=%v code=%q", ok, code)
		}
	})

	t.Run("rejects too long rule ID", func(t *testing.T) {
		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:     strings.Repeat("a", 256),
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						Days: 1,
					},
				},
			},
		}
		code, _, ok := validateLifecycleConfiguration(cfg)
		if ok || code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got ok=%v code=%q", ok, code)
		}
	})

	t.Run("rejects days 0 expiration", func(t *testing.T) {
		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:     "rule1",
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						Days: 0,
					},
				},
			},
		}
		code, _, ok := validateLifecycleConfiguration(cfg)
		if ok || code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got ok=%v code=%q", ok, code)
		}
	})

	t.Run("accepts expired object delete marker rule", func(t *testing.T) {
		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:     "rule1",
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						ExpiredObjectDeleteMarker: true,
					},
				},
			},
		}
		_, _, ok := validateLifecycleConfiguration(cfg)
		if !ok {
			t.Fatal("expected ExpiredObjectDeleteMarker-only rule to be valid")
		}
	})

	t.Run("accepts valid date", func(t *testing.T) {
		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:     "rule1",
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						Date: "2017-09-27",
					},
				},
			},
		}
		_, _, ok := validateLifecycleConfiguration(cfg)
		if !ok {
			t.Fatal("expected lifecycle configuration with date to be valid")
		}
	})

	t.Run("accepts valid RFC3339 date", func(t *testing.T) {
		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:     "rule1",
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						Date: "2017-09-27T00:00:00Z",
					},
				},
			},
		}
		_, _, ok := validateLifecycleConfiguration(cfg)
		if !ok {
			t.Fatal("expected lifecycle configuration with RFC3339 date to be valid")
		}
	})

	t.Run("rejects invalid date format", func(t *testing.T) {
		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:     "rule1",
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						Date: "20200101",
					},
				},
			},
		}
		code, _, ok := validateLifecycleConfiguration(cfg)
		if ok || code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got ok=%v code=%q", ok, code)
		}
	})
}
