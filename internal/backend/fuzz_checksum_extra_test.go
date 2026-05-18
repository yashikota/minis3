package backend

import "testing"

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
		_, _ = ComputeChecksumBase64(algorithm, data)
	})
}

func FuzzChecksumCRC64NVMEBase64(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte("a longer string with various bytes"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = checksumCRC64NVMEBase64(data)
	})
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
