package backend

import (
	"sync"
)

// Backend holds the state of the S3 world.
type Backend struct {
	mu      sync.RWMutex
	buckets map[string]*Bucket
}

// New creates a new Backend.
func New() *Backend {
	return &Backend{
		buckets: make(map[string]*Bucket),
	}
}

// ListObjectsV2Result holds the result of ListObjectsV2
type ListObjectsV2Result struct {
	Objects        []*Object
	CommonPrefixes []string
	IsTruncated    bool
	KeyCount       int
}
