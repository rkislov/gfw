package certs

import "testing"

func TestGenerateAndParseSelfSigned(t *testing.T) {
	cert, key, info, err := GenerateSelfSigned([]string{"example.com", "www.example.com"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if got.FingerprintSHA256 != info.FingerprintSHA256 {
		t.Fatalf("fingerprint mismatch")
	}
	if len(got.DNSNames) < 1 || got.DNSNames[0] != "example.com" {
		t.Fatalf("dns names: %+v", got.DNSNames)
	}
}

func TestParsePairRejectsMismatch(t *testing.T) {
	c1, k1, _, err := GenerateSelfSigned([]string{"a.example"}, 7)
	if err != nil {
		t.Fatal(err)
	}
	_, k2, _, err := GenerateSelfSigned([]string{"b.example"}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePair(c1, k2); err == nil {
		t.Fatal("expected mismatch error")
	}
	if _, err := ParsePair(c1, k1); err != nil {
		t.Fatal(err)
	}
}
