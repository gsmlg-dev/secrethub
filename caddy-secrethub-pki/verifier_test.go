package secrethubpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type testHarness struct {
	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
	caPEM      []byte
	tmpDir     string
	currentDir string
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "caddy-pki-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	currentDir := filepath.Join(tmpDir, "current")
	if err := os.MkdirAll(currentDir, 0755); err != nil {
		t.Fatalf("failed to create current dir: %v", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SecretHub Client Authentication"},
			CommonName:   "SecretHub Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(filepath.Join(currentDir, "ca.crt"), caPEM, 0644); err != nil {
		t.Fatalf("failed to write ca.crt: %v", err)
	}

	return &testHarness{
		caKey:      caKey,
		caCert:     caCert,
		caPEM:      caPEM,
		tmpDir:     tmpDir,
		currentDir: currentDir,
	}
}

func (h *testHarness) issueClientCert(t *testing.T, identityID string, serial int64) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	clientURI, err := url.Parse("urn:secrethub:client:" + identityID)
	if err != nil {
		t.Fatalf("invalid uri: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			Organization: []string{"SecretHub Client Authentication"},
			CommonName:   identityID,
		},
		URIs:                  []*url.URL{clientURI},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Critical: false, // Standard non-critical BasicConstraints CA:FALSE as produced by Elixir Issuer
				Value:    []byte{0x30, 0x00},
			},
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
				Critical: true,
				Value:    []byte{0x03, 0x02, 0x07, 0x80}, // KeyUsage digitalSignature
			},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, h.caCert, &clientKey.PublicKey, h.caKey)
	if err != nil {
		t.Fatalf("failed to create client cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse client cert: %v", err)
	}

	return cert, clientKey
}

func (h *testHarness) writeBundle(t *testing.T, generation, crlNumber int64, revokedSerials []*big.Int, nextUpdate time.Time) {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range revokedSerials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   s,
			RevocationTime: time.Now().Add(-10 * time.Minute),
		})
	}

	thisUpdate := time.Now().Add(-1 * time.Hour)
	if nextUpdate.Before(thisUpdate) {
		thisUpdate = nextUpdate.Add(-24 * time.Hour)
	}

	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm:        x509.ECDSAWithSHA384,
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(crlNumber),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, h.caCert, h.caKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	if err := os.WriteFile(filepath.Join(h.currentDir, "crl.pem"), crlPEM, 0644); err != nil {
		t.Fatalf("failed to write crl.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.currentDir, "ca.crt"), h.caPEM, 0644); err != nil {
		t.Fatalf("failed to write ca.crt: %v", err)
	}

	caDERHash := sha256.Sum256(h.caCert.Raw)
	caFingerprint := hex.EncodeToString(caDERHash[:])

	crlDERHash := sha256.Sum256(crlDER)
	crlDERHashHex := hex.EncodeToString(crlDERHash[:])

	thisUpdateStr := thisUpdate.UTC().Format(time.RFC3339)
	nextUpdateStr := nextUpdate.UTC().Format(time.RFC3339)

	transcript := fmt.Sprintf("%d|%s|%d|%s|%d|%s|%s|%s|%s|%s",
		1,
		"client-auth",
		generation,
		caFingerprint,
		crlNumber,
		crlDERHashHex,
		thisUpdateStr,
		nextUpdateStr,
		string(h.caPEM),
		string(crlPEM),
	)

	bundleHash := sha256.Sum256([]byte(transcript))
	bundleHashHex := hex.EncodeToString(bundleHash[:])

	manifest := BundleManifest{
		SchemaVersion: 1,
		Authority:     "client-auth",
		Generation:    generation,
		CRLNumber:     crlNumber,
		CAFingerprint: caFingerprint,
		CRLDerSHA256:  crlDERHashHex,
		BundleSHA256:  bundleHashHex,
		ThisUpdate:    thisUpdateStr,
		NextUpdate:    nextUpdateStr,
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}

	if err := os.WriteFile(filepath.Join(h.currentDir, "manifest.json"), manifestBytes, 0644); err != nil {
		t.Fatalf("failed to write manifest.json: %v", err)
	}
}

func TestVerifierValidCertificate(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	identityID := "e57c6bc1-1a3b-4882-9f37-1424e88383e2"
	cert, _ := h.issueClientCert(t, identityID, 1001)

	identity, err := v.VerifyCertificate(cert, time.Now())
	if err != nil {
		t.Fatalf("expected valid verification, got: %v", err)
	}

	if identity.IdentityID != identityID {
		t.Errorf("expected identity %s, got %s", identityID, identity.IdentityID)
	}
	if identity.CommonName != identityID {
		t.Errorf("expected CN %s, got %s", identityID, identity.CommonName)
	}
}

func TestVerifierRevokedCertificate(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	revokedSerial := big.NewInt(2002)
	h.writeBundle(t, 1, 2, []*big.Int{revokedSerial}, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	cert, _ := h.issueClientCert(t, "f47ac10b-58cc-4372-a567-0e02b2c3d479", 2002)

	_, err := v.VerifyCertificate(cert, time.Now())
	if err != ErrCertRevoked {
		t.Fatalf("expected ErrCertRevoked, got: %v", err)
	}
}

func TestVerifierExpiredCRL(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	// Start with a valid Gen 1 bundle
	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	snap1, err := v.LoadFromDisk()
	if err != nil {
		t.Fatalf("failed to load initial valid bundle: %v", err)
	}
	if snap1.Generation != 1 {
		t.Fatalf("expected gen 1, got %d", snap1.Generation)
	}

	// Now publish Gen 2 with an expired CRL (next_update in the past)
	h.writeBundle(t, 2, 2, nil, time.Now().Add(-1*time.Hour))

	// LoadFromDisk must reject the candidate bundle with ErrCRLExpired
	_, err = v.LoadFromDisk()
	if err == nil {
		t.Fatalf("expected LoadFromDisk to fail on expired candidate CRL, got nil")
	}

	// Ensure the in-memory active snapshot is preserved at Gen 1 (not discarded)
	currentSnap := v.snapshot.Load()
	if currentSnap == nil || currentSnap.Generation != 1 {
		t.Fatalf("expected active snapshot to remain Gen 1, got %v", currentSnap)
	}

	// Verify a valid client cert still succeeds against preserved Gen 1 snapshot
	cert, _ := h.issueClientCert(t, "f47ac10b-58cc-4372-a567-0e02b2c3d479", 3003)
	if _, err := v.VerifyCertificate(cert, time.Now()); err != nil {
		t.Fatalf("expected certificate verification to succeed with preserved snapshot, got: %v", err)
	}
}

func TestVerifierForeignCA(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	// Issue cert with another CA
	foreignHarness := newTestHarness(t)
	defer os.RemoveAll(foreignHarness.tmpDir)
	foreignCert, _ := foreignHarness.issueClientCert(t, "f47ac10b-58cc-4372-a567-0e02b2c3d479", 4004)

	_, err := v.VerifyCertificate(foreignCert, time.Now())
	if err == nil {
		t.Fatalf("expected error for foreign cert, got nil")
	}
}

func TestVerifierMonotonicityAndRollbackRejection(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	// Start at Generation 2, CRL number 2
	h.writeBundle(t, 2, 2, nil, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	snap1, err := v.LoadFromDisk()
	if err != nil {
		t.Fatalf("failed to load gen 2: %v", err)
	}
	if snap1.Generation != 2 {
		t.Fatalf("expected gen 2, got %d", snap1.Generation)
	}

	// 1. Re-loading same generation 2 is OK
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("re-loading same generation should succeed: %v", err)
	}

	// 2. Generation downgrade: attempt to switch to Generation 1
	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))
	if _, err := v.LoadFromDisk(); err == nil {
		t.Fatalf("expected error on generation downgrade, got nil")
	}

	// 3. Equivocation: same generation 2 with differing hash
	manifestPath := filepath.Join(h.currentDir, "manifest.json")
	var manifest BundleManifest
	manifestBytes, _ := os.ReadFile(manifestPath)
	json.Unmarshal(manifestBytes, &manifest)
	manifest.Generation = 2
	manifest.BundleSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	corruptedBytes, _ := json.Marshal(manifest)
	os.WriteFile(manifestPath, corruptedBytes, 0644)

	if _, err := v.LoadFromDisk(); err == nil {
		t.Fatalf("expected error on equivocation, got nil")
	}

	// 4. Persistence across Verifier restart:
	// A new Verifier instance starting against h.tmpDir must read watermark.json
	// and reject an older generation 1 even on first load.
	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))
	v2 := NewVerifier(h.tmpDir)
	if _, err := v2.LoadFromDisk(); err == nil {
		t.Fatalf("expected new Verifier instance to reject rollback to Gen 1 due to persistent watermark, got nil")
	}
}

func TestVerifierDynamicRevocationReloadAndRejection(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	serialA := big.NewInt(5001)
	certA, _ := h.issueClientCert(t, "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d", 5001)

	// Step 1: Initial Gen 1 bundle where certA is valid
	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	snap1, err := v.LoadFromDisk()
	if err != nil {
		t.Fatalf("failed to load gen 1: %v", err)
	}
	if snap1.Generation != 1 {
		t.Fatalf("expected gen 1, got %d", snap1.Generation)
	}

	// certA must be verified successfully
	if _, err := v.VerifyCertificate(certA, time.Now()); err != nil {
		t.Fatalf("expected certA to be valid under Gen 1, got: %v", err)
	}

	// Step 2: Publish Gen 2 bundle where certA is revoked
	h.writeBundle(t, 2, 2, []*big.Int{serialA}, time.Now().Add(48*time.Hour))

	// Reload from disk
	snap2, err := v.LoadFromDisk()
	if err != nil {
		t.Fatalf("failed to reload gen 2: %v", err)
	}
	if snap2.Generation != 2 {
		t.Fatalf("expected gen 2, got %d", snap2.Generation)
	}

	// certA must now be rejected as revoked
	if _, err := v.VerifyCertificate(certA, time.Now()); err != ErrCertRevoked {
		t.Fatalf("expected certA to be rejected with ErrCertRevoked under Gen 2, got: %v", err)
	}

	// Step 3: Rollback attempt to Gen 1 must fail and leave Gen 2 active
	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))
	if _, err := v.LoadFromDisk(); err == nil {
		t.Fatalf("expected rollback to Gen 1 to fail, got nil")
	}

	// certA must still be rejected by the active snapshot
	if _, err := v.VerifyCertificate(certA, time.Now()); err != ErrCertRevoked {
		t.Fatalf("expected certA to remain rejected after failed rollback, got: %v", err)
	}
}

func TestVerifierCanonicalProfileNegative(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	// 1. Non-canonical UUID
	nonUUIDCert, _ := h.issueClientCert(t, "invalid-non-uuid-name", 5001)
	if _, err := v.VerifyCertificate(nonUUIDCert, time.Now()); err != ErrInvalidCommonName {
		t.Errorf("expected ErrInvalidCommonName, got: %v", err)
	}

	// 2. Extra Subject RDN (e.g. Country)
	validID := "e57c6bc1-1a3b-4882-9f37-1424e88383e2"
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse("urn:secrethub:client:" + validID)
	extraRDNTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(5002),
		Subject:               pkix.Name{Organization: []string{"SecretHub Client Authentication"}, CommonName: validID, Country: []string{"US"}},
		URIs:                  []*url.URL{uri},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: false, Value: []byte{0x30, 0x00}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x02, 0x07, 0x80}},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, extraRDNTemplate, h.caCert, &clientKey.PublicKey, h.caKey)
	extraRDNCert, _ := x509.ParseCertificate(der)
	if _, err := v.VerifyCertificate(extraRDNCert, time.Now()); err != ErrExtraSubjectAttributes {
		t.Errorf("expected ErrExtraSubjectAttributes, got: %v", err)
	}

	// 3. Extra DNS SAN
	extraSANTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(5003),
		Subject:               pkix.Name{Organization: []string{"SecretHub Client Authentication"}, CommonName: validID},
		URIs:                  []*url.URL{uri},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: false, Value: []byte{0x30, 0x00}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x02, 0x07, 0x80}},
		},
	}
	der, _ = x509.CreateCertificate(rand.Reader, extraSANTemplate, h.caCert, &clientKey.PublicKey, h.caKey)
	extraSANCert, _ := x509.ParseCertificate(der)
	if _, err := v.VerifyCertificate(extraSANCert, time.Now()); err != ErrExtraSANsDisallowed {
		t.Errorf("expected ErrExtraSANsDisallowed, got: %v", err)
	}

	// 4. IsCA = true
	isCATemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(5004),
		Subject:               pkix.Name{Organization: []string{"SecretHub Client Authentication"}, CommonName: validID},
		URIs:                  []*url.URL{uri},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xFF}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x02, 0x07, 0x80}},
		},
	}
	der, _ = x509.CreateCertificate(rand.Reader, isCATemplate, h.caCert, &clientKey.PublicKey, h.caKey)
	isCACert, _ := x509.ParseCertificate(der)
	if _, err := v.VerifyCertificate(isCACert, time.Now()); err == nil {
		t.Errorf("expected error for IsCA=true certificate, got nil")
	}

	// 5. Missing Basic Constraints extension entirely
	missingBCTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(5005),
		Subject:      pkix.Name{Organization: []string{"SecretHub Client Authentication"}, CommonName: validID},
		URIs:         []*url.URL{uri},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x02, 0x07, 0x80}},
		},
	}
	der, _ = x509.CreateCertificate(rand.Reader, missingBCTemplate, h.caCert, &clientKey.PublicKey, h.caKey)
	missingBCCert, _ := x509.ParseCertificate(der)
	if _, err := v.VerifyCertificate(missingBCCert, time.Now()); err != ErrMissingBasicConstraints {
		t.Errorf("expected ErrMissingBasicConstraints, got: %v", err)
	}
}

func TestVerifierCorruptWatermarkFailClosed(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))

	// Corrupt watermark file with invalid JSON
	watermarkPath := filepath.Join(h.tmpDir, "watermark.json")
	if err := os.WriteFile(watermarkPath, []byte("NOT_VALID_JSON{{{"), 0644); err != nil {
		t.Fatalf("failed to write corrupt watermark: %v", err)
	}

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err == nil {
		t.Fatalf("expected LoadFromDisk to fail closed on corrupt watermark.json, got nil")
	}
}

func TestVerifierIncompleteWatermarkFailClosed(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"empty_json", "{}"},
		{"missing_fields", `{"highest_seen_generation": 10}`},
		{"zero_generation", `{"highest_seen_generation": 0, "highest_seen_crl_number": 1, "pinned_ca_fingerprint": "8792bc0fa20e137b26ac4467d91c67926b86edee0352534a5b71f6fd8aa724b5", "last_bundle_sha256": "8792bc0fa20e137b26ac4467d91c67926b86edee0352534a5b71f6fd8aa724b5"}`},
		{"invalid_fingerprint_hex", `{"highest_seen_generation": 1, "highest_seen_crl_number": 1, "pinned_ca_fingerprint": "not-a-valid-hex", "last_bundle_sha256": "8792bc0fa20e137b26ac4467d91c67926b86edee0352534a5b71f6fd8aa724b5"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t)
			defer os.RemoveAll(h.tmpDir)

			h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))
			watermarkPath := filepath.Join(h.tmpDir, "watermark.json")
			if err := os.WriteFile(watermarkPath, []byte(tc.json), 0644); err != nil {
				t.Fatalf("failed to write watermark: %v", err)
			}

			v := NewVerifier(h.tmpDir)
			if _, err := v.LoadFromDisk(); err == nil {
				t.Errorf("expected LoadFromDisk to fail closed on %s, got nil error", tc.name)
			}
		})
	}
}

func TestConcurrentWatermarkWriters(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	h.writeBundle(t, 1, 1, nil, time.Now().Add(48*time.Hour))

	sharedWatermark := filepath.Join(h.tmpDir, "shared-watermark.json")

	// Launch 10 concurrent verifier instances attempting to load and update the same watermark
	const workers = 10
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		go func() {
			v := NewVerifier(h.tmpDir)
			v.SetWatermarkFile(sharedWatermark)
			_, err := v.LoadFromDisk()
			errCh <- err
		}()
	}

	for i := 0; i < workers; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("worker %d failed during concurrent watermark write: %v", i, err)
		}
	}

	// Verify final persisted watermark is valid and intact
	wmBytes, err := os.ReadFile(sharedWatermark)
	if err != nil {
		t.Fatalf("failed to read shared watermark: %v", err)
	}

	var wm PersistentWatermark
	if err := json.Unmarshal(wmBytes, &wm); err != nil {
		t.Fatalf("failed to unmarshal shared watermark: %v", err)
	}

	if err := validateWatermark(&wm); err != nil {
		t.Fatalf("shared watermark failed validation: %v", err)
	}

	if wm.HighestSeenGeneration != 1 {
		t.Errorf("expected generation 1, got %d", wm.HighestSeenGeneration)
	}
}

func TestProvisionFailsOnMissingBundle(t *testing.T) {
	emptyDir, err := os.MkdirTemp("", "empty-bundle-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(emptyDir)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tv := &TLSVerifier{
		BundleDir: emptyDir,
	}

	if err := tv.Provision(ctx); err == nil {
		t.Fatalf("expected Provision to fail on empty bundle directory, got nil error")
	}
}

func TestTLSVerifierRealHandshake(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	revokedSerial := big.NewInt(9999)
	h.writeBundle(t, 1, 1, []*big.Int{revokedSerial}, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	tv := &TLSVerifier{
		verifier: v,
		logger:   zap.NewNop(),
	}

	serverCert, err := tls.X509KeyPair(h.caPEM, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: mustMarshalECKey(h.caKey),
	}))
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}

	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("HANDSHAKE_OK"))
	}))

	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return tv.VerifyClientCertificate(rawCerts, verifiedChains)
		},
	}
	tlsServer.StartTLS()
	defer tlsServer.Close()

	// 1. Client with valid certificate
	validID := "e57c6bc1-1a3b-4882-9f37-1424e88383e2"
	validCert, validKey := h.issueClientCert(t, validID, 1234)
	validClientCert := tls.Certificate{
		Certificate: [][]byte{validCert.Raw},
		PrivateKey:  validKey,
	}

	client := tlsServer.Client()
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // skip server CA check in test
			Certificates:       []tls.Certificate{validClientCert},
		},
	}

	resp, err := client.Get(tlsServer.URL)
	if err != nil {
		t.Fatalf("expected TLS handshake to succeed for valid cert, got error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got: %d", resp.StatusCode)
	}

	// 2. Client with revoked certificate
	revokedCert, revokedKey := h.issueClientCert(t, "f47ac10b-58cc-4372-a567-0e02b2c3d479", 9999)
	revokedClientCert := tls.Certificate{
		Certificate: [][]byte{revokedCert.Raw},
		PrivateKey:  revokedKey,
	}

	clientRevoked := tlsServer.Client()
	clientRevoked.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{revokedClientCert},
		},
	}

	_, err = clientRevoked.Get(tlsServer.URL)
	if err == nil {
		t.Fatalf("expected TLS handshake to fail for revoked cert, got nil error")
	}
}

func mustMarshalECKey(k *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		panic(err)
	}
	return b
}

func TestCaddyMiddlewareIntegration(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	revokedSerial := big.NewInt(9999)
	h.writeBundle(t, 1, 1, []*big.Int{revokedSerial}, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	setHeaders := true
	mw := &SecretHubClientAuth{
		BundleDir:  h.tmpDir,
		SetHeaders: &setHeaders,
		verifier:   v,
		logger:     zap.NewNop(),
	}

	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Echo-Client-ID", r.Header.Get("X-SecretHub-Client-ID"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return nil
	})

	// 1. Missing mTLS cert -> 401
	req1 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec1 := httptest.NewRecorder()
	if err := mw.ServeHTTP(rec1, req1, nextHandler); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if rec1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec1.Code)
	}

	// 2. Valid client cert -> 200 with X-SecretHub-Client-ID header
	validID := "e57c6bc1-1a3b-4882-9f37-1424e88383e2"
	validCert, _ := h.issueClientCert(t, validID, 1234)
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req2.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{validCert},
	}

	rec2 := httptest.NewRecorder()
	if err := mw.ServeHTTP(rec2, req2, nextHandler); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if rec2.Header().Get("X-Echo-Client-ID") != validID {
		t.Errorf("expected header %s, got %s", validID, rec2.Header().Get("X-Echo-Client-ID"))
	}

	// 3. Revoked client cert -> 403
	revokedCert, _ := h.issueClientCert(t, "f47ac10b-58cc-4372-a567-0e02b2c3d479", 9999)
	req3 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req3.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{revokedCert},
	}
	rec3 := httptest.NewRecorder()
	if err := mw.ServeHTTP(rec3, req3, nextHandler); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if rec3.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec3.Code)
	}
}
