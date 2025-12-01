package skybolt

import (
	"encoding/base64"
	"testing"
)

// This digest was created by the JavaScript implementation with these assets:
// - src/css/critical.css:B20ictSB
// - src/css/main.css:DfFbFQk_
// - src/js/app.js:DW873Fox
// - skybolt-launcher:ptJmv_9y
const validDigest = "AQAEAAQAAAAAAAAAAAXNB-UAAAAACT4NhgAAAAAAAAAAAAAAAA"

// TestFnv1aMatchesJavaScript verifies FNV-1a hash matches cross-language test vectors.
func TestFnv1aMatchesJavaScript(t *testing.T) {
	testCases := []struct {
		input    string
		expected uint32
	}{
		{"src/css/critical.css:abc123", 821208812},
		{"src/css/main.css:def456", 26790494},
		{"skybolt-launcher:xyz789", 452074441},
		{"123", 1916298011},
		{"", 2166136261}, // Empty string returns offset basis
		{"a", 3826002220},
		{"test", 2949673445},
	}

	for _, tc := range testCases {
		got := Fnv1a(tc.input)
		if got != tc.expected {
			t.Errorf("Fnv1a(%q) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}

// TestFingerprintInValidRange verifies fingerprint is in range [1, 4095].
func TestFingerprintInValidRange(t *testing.T) {
	testCases := []string{
		"src/css/critical.css:abc123",
		"src/css/main.css:def456",
		"skybolt-launcher:xyz789",
	}

	for _, input := range testCases {
		fp := Fingerprint(input)
		if fp < 1 || fp > 4095 {
			t.Errorf("Fingerprint(%q) = %d, want value in [1, 4095]", input, fp)
		}
	}
}

// TestFingerprintNeverZero verifies fingerprint never returns 0.
func TestFingerprintNeverZero(t *testing.T) {
	for i := 0; i < 1000; i++ {
		fp := Fingerprint(itoa(i))
		if fp == 0 {
			t.Errorf("Fingerprint returned 0 for input %d", i)
		}
	}
}

// TestAlternateBucketReversible verifies alternate bucket calculation is reversible.
func TestAlternateBucketReversible(t *testing.T) {
	numBuckets := 16 // Power of 2

	for bucket := 0; bucket < numBuckets; bucket++ {
		for fp := 1; fp <= 100; fp++ {
			alt := ComputeAlternateBucket(bucket, fp, numBuckets)
			original := ComputeAlternateBucket(alt, fp, numBuckets)

			if original != bucket {
				t.Errorf("Alternate bucket not reversible: bucket=%d, fp=%d, alt=%d, got=%d",
					bucket, fp, alt, original)
			}
		}
	}
}

// TestParseValidDigest verifies parsing a valid digest from JavaScript.
func TestParseValidDigest(t *testing.T) {
	cd := NewCacheDigest(validDigest)

	if !cd.IsValid() {
		t.Fatal("Expected valid digest")
	}

	// These should be found
	shouldBeFound := []string{
		"src/css/critical.css:B20ictSB",
		"src/css/main.css:DfFbFQk_",
		"src/js/app.js:DW873Fox",
		"skybolt-launcher:ptJmv_9y",
	}

	for _, item := range shouldBeFound {
		if !cd.Lookup(item) {
			t.Errorf("Expected to find %q in digest", item)
		}
	}

	// These should NOT be found (different hashes)
	shouldNotBeFound := []string{
		"src/css/critical.css:DIFFERENT",
		"src/css/main.css:DIFFERENT",
		"nonexistent:asset",
	}

	for _, item := range shouldNotBeFound {
		if cd.Lookup(item) {
			t.Errorf("Did not expect to find %q in digest", item)
		}
	}
}

// TestParseEmptyDigest verifies handling of empty digest.
func TestParseEmptyDigest(t *testing.T) {
	cd := NewCacheDigest("")
	if cd.IsValid() {
		t.Error("Empty digest should not be valid")
	}
	if cd.Lookup("anything") {
		t.Error("Lookup on empty digest should return false")
	}
}

// TestParseInvalidBase64 verifies handling of invalid base64.
func TestParseInvalidBase64(t *testing.T) {
	cd := NewCacheDigest("not-valid-base64!!!")
	if cd.IsValid() {
		t.Error("Invalid base64 should not be valid")
	}
}

// TestParseWrongVersion verifies rejecting wrong version.
func TestParseWrongVersion(t *testing.T) {
	// Version 2 header (invalid)
	data := []byte{0x02, 0x00, 0x04, 0x00, 0x00}
	cd := NewCacheDigest(base64.StdEncoding.EncodeToString(data))
	if cd.IsValid() {
		t.Error("Wrong version should not be valid")
	}
}

// TestParseTruncatedDigest verifies handling of truncated digest.
func TestParseTruncatedDigest(t *testing.T) {
	// Too short
	data := []byte{0x01, 0x00}
	cd := NewCacheDigest(base64.StdEncoding.EncodeToString(data))
	if cd.IsValid() {
		t.Error("Truncated digest should not be valid")
	}
}

// TestUrlSafeBase64 verifies URL-safe base64 handling.
func TestUrlSafeBase64(t *testing.T) {
	// The validDigest already contains URL-safe characters (- and _)
	cd := NewCacheDigest(validDigest)

	if !cd.IsValid() {
		t.Fatal("Expected valid digest with URL-safe base64")
	}
	if !cd.Lookup("src/css/critical.css:B20ictSB") {
		t.Error("Expected to find asset in digest with URL-safe base64")
	}
}

// TestConstants verifies the constants are correct.
func TestConstants(t *testing.T) {
	if FingerprintBits != 12 {
		t.Errorf("FingerprintBits = %d, want 12", FingerprintBits)
	}
	if BucketSize != 4 {
		t.Errorf("BucketSize = %d, want 4", BucketSize)
	}
}
