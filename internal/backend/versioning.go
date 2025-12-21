package backend

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"time"
)

// NullVersionId is the version ID used for objects in unversioned or suspended buckets.
const NullVersionId = "null"

// GenerateVersionId generates a unique version ID in AWS S3 format.
// Format: Base64URL encoded string of timestamp (8 bytes) + random (16 bytes).
// Example output: "3_L4kqtJl40Nr8X8gdRQBpUMLUo" (32 characters).
func GenerateVersionId() string {
	buf := make([]byte, 24)

	// First 8 bytes: timestamp in nanoseconds (provides ordering)
	binary.BigEndian.PutUint64(buf[:8], uint64(time.Now().UnixNano()))

	// Next 16 bytes: random data (provides uniqueness)
	_, _ = rand.Read(buf[8:])

	return base64.RawURLEncoding.EncodeToString(buf)
}

// VersioningStatus represents the versioning state of a bucket.
type VersioningStatus int

const (
	// VersioningUnset indicates versioning has never been enabled (default).
	VersioningUnset VersioningStatus = iota
	// VersioningEnabled indicates versioning is enabled.
	VersioningEnabled
	// VersioningSuspended indicates versioning is suspended.
	VersioningSuspended
)

// String returns the AWS API string representation.
func (v VersioningStatus) String() string {
	switch v {
	case VersioningEnabled:
		return "Enabled"
	case VersioningSuspended:
		return "Suspended"
	default:
		return ""
	}
}

// ParseVersioningStatus parses a string to VersioningStatus.
func ParseVersioningStatus(s string) VersioningStatus {
	switch s {
	case "Enabled":
		return VersioningEnabled
	case "Suspended":
		return VersioningSuspended
	default:
		return VersioningUnset
	}
}

// IsVersioningEnabled returns true if versioning is enabled.
func (v VersioningStatus) IsVersioningEnabled() bool {
	return v == VersioningEnabled
}

// MFADeleteStatus represents MFA Delete configuration.
type MFADeleteStatus int

const (
	// MFADeleteDisabled indicates MFA Delete is disabled (default).
	MFADeleteDisabled MFADeleteStatus = iota
	// MFADeleteEnabled indicates MFA Delete is enabled.
	MFADeleteEnabled
)

// String returns the AWS API string representation.
func (m MFADeleteStatus) String() string {
	if m == MFADeleteEnabled {
		return "Enabled"
	}
	return "Disabled"
}

// ParseMFADeleteStatus parses a string to MFADeleteStatus.
func ParseMFADeleteStatus(s string) MFADeleteStatus {
	if s == "Enabled" {
		return MFADeleteEnabled
	}
	return MFADeleteDisabled
}
