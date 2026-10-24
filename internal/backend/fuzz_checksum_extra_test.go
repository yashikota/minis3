package backend

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func FuzzComputeChecksumBase64(f *testing.F) {
	f.Add("CRC32", []byte("hello world"))
	f.Add("CRC32C", []byte("hello world"))
	f.Add("CRC64NVME", []byte("test data"))
	f.Add("SHA1", []byte("content"))
	f.Add("SHA256", []byte("data"))
	f.Add("unknown", []byte("x"))
	f.Add("", []byte{})
	f.Add("CRC32", []byte{0, 1, 2, 3, 255})

	f.Fuzz(func(t *testing.T, algorithm string, data []byte) {
		got, ok := ComputeChecksumBase64(algorithm, data)
		wantLen, known := map[string]int{
			"CRC32": 4, "CRC32C": 4, "CRC64NVME": 8, "SHA1": 20, "SHA256": 32,
		}[strings.ToUpper(strings.TrimSpace(algorithm))]
		if ok != known {
			t.Fatalf("ComputeChecksumBase64(%q) ok = %v, want %v", algorithm, ok, known)
		}
		if !ok {
			return
		}
		raw, err := base64.StdEncoding.DecodeString(got)
		if err != nil || len(raw) != wantLen {
			t.Fatalf("checksum %q is not %d base64 bytes: %v", got, wantLen, err)
		}
		if strings.EqualFold(strings.TrimSpace(algorithm), "CRC64NVME") &&
			binary.BigEndian.Uint64(raw) != referenceCRC64NVME(data) {
			t.Fatalf("CRC64NVME(%x) = %x, reference %x", data, raw, referenceCRC64NVME(data))
		}
	})
}

func FuzzChecksumCRC64NVMEBase64(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte("a longer string with various bytes"))

	f.Fuzz(func(t *testing.T, data []byte) {
		raw, err := base64.StdEncoding.DecodeString(checksumCRC64NVMEBase64(data))
		if err != nil || len(raw) != 8 || binary.BigEndian.Uint64(raw) != referenceCRC64NVME(data) {
			t.Fatalf("checksumCRC64NVMEBase64(%x) disagrees with the bitwise reference", data)
		}
	})
}

// referenceCRC64NVME is a bit-at-a-time CRC-64/NVME (reflected polynomial
// 0x9a6c9329ac4bc9b5, initial value and final XOR all ones), independent
// of the table-driven implementation.
func referenceCRC64NVME(data []byte) uint64 {
	crc := ^uint64(0)
	for _, b := range data {
		crc ^= uint64(b)
		for range 8 {
			if crc&1 == 1 {
				crc = crc>>1 ^ 0x9a6c9329ac4bc9b5
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

func TestReferenceCRC64NVMECheckValue(t *testing.T) {
	t.Parallel()
	// The CRC catalogue's check value for CRC-64/NVME.
	if got := referenceCRC64NVME([]byte("123456789")); got != 0xae8b14860a799888 {
		t.Fatalf("reference CRC-64/NVME check = %x, want ae8b14860a799888", got)
	}
}

func FuzzGenerateRandomID(f *testing.F) {
	f.Add(1)
	f.Add(10)
	f.Add(32)
	f.Add(64)

	f.Fuzz(func(t *testing.T, n int) {
		if n <= 0 || n > 1024 {
			return
		}
		result := generateRandomID(n)
		if len(result) != 2*n {
			t.Errorf("expected length %d, got %d", 2*n, len(result))
		}
	})
}
