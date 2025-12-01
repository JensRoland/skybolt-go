// Package skybolt provides high-performance asset caching for multi-page applications.
package skybolt

import (
	"encoding/base64"
	"strings"
)

// Cuckoo filter constants
const (
	FingerprintBits = 12
	BucketSize      = 4
)

// CacheDigest represents a Cuckoo filter for cache state tracking.
// This is a read-only parser for digests created by the JavaScript client.
type CacheDigest struct {
	valid      bool
	numBuckets int
	buckets    []uint16
}

// NewCacheDigest creates a CacheDigest from a base64-encoded string.
func NewCacheDigest(digest string) *CacheDigest {
	cd := &CacheDigest{
		valid:      false,
		numBuckets: 0,
		buckets:    nil,
	}
	cd.parseDigest(digest)
	return cd
}

// IsValid returns whether the digest was parsed successfully.
func (cd *CacheDigest) IsValid() bool {
	return cd.valid
}

// Lookup checks if an item exists in the digest.
// Returns true if item might be in the filter (may have false positives).
func (cd *CacheDigest) Lookup(item string) bool {
	if !cd.valid {
		return false
	}

	fp := Fingerprint(item)
	i1 := PrimaryBucket(item, cd.numBuckets)
	i2 := ComputeAlternateBucket(i1, fp, cd.numBuckets)
	return cd.bucketContains(i1, fp) || cd.bucketContains(i2, fp)
}

func (cd *CacheDigest) parseDigest(digest string) {
	if digest == "" {
		return
	}

	// Handle URL-safe base64
	normalized := strings.ReplaceAll(digest, "-", "+")
	normalized = strings.ReplaceAll(normalized, "_", "/")

	// Add padding if needed
	for len(normalized)%4 != 0 {
		normalized += "="
	}

	data, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return
	}

	if len(data) < 5 {
		return
	}

	// Check version (must be 1)
	if data[0] != 1 {
		return
	}

	cd.numBuckets = int(data[1])<<8 | int(data[2])
	numFingerprints := cd.numBuckets * BucketSize

	cd.buckets = make([]uint16, numFingerprints)
	for i := 0; i < numFingerprints; i++ {
		offset := 5 + i*2
		if offset+1 < len(data) {
			cd.buckets[i] = uint16(data[offset])<<8 | uint16(data[offset+1])
		}
	}

	cd.valid = true
}

func (cd *CacheDigest) bucketContains(bucketIndex, fp int) bool {
	offset := bucketIndex * BucketSize
	for i := 0; i < BucketSize; i++ {
		if int(cd.buckets[offset+i]) == fp {
			return true
		}
	}
	return false
}

// Fnv1a computes the FNV-1a hash of a string (32-bit).
func Fnv1a(str string) uint32 {
	hash := uint32(2166136261)
	for i := 0; i < len(str); i++ {
		hash ^= uint32(str[i])
		hash *= 16777619
	}
	return hash
}

// Fingerprint computes the fingerprint for a Cuckoo filter.
// Returns a value in range [1, 4095].
func Fingerprint(str string) int {
	hash := Fnv1a(str)
	fp := int(hash & ((1 << FingerprintBits) - 1))
	if fp == 0 {
		return 1
	}
	return fp
}

// PrimaryBucket computes the primary bucket index for a Cuckoo filter.
func PrimaryBucket(str string, numBuckets int) int {
	return int(Fnv1a(str)) % numBuckets
}

// ComputeAlternateBucket computes the alternate bucket index for a Cuckoo filter.
func ComputeAlternateBucket(bucket, fp, numBuckets int) int {
	fpHash := Fnv1a(itoa(fp))
	bucketMask := numBuckets - 1
	offset := (int(fpHash) | 1) & bucketMask
	return (bucket ^ offset) & bucketMask
}

// itoa converts an integer to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	negative := n < 0
	if negative {
		n = -n
	}

	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}

	if negative {
		digits = append([]byte{'-'}, digits...)
	}

	return string(digits)
}
