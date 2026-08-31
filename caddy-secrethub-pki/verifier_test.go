package secrethubpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

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
			Organization: []string{"SecretHub"},
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

func (h *testHarness) writeCRL(t *testing.T, revokedSerials []*big.Int, crlNumber int64, nextUpdate time.Time) []byte {
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

	return crlPEM
}

func TestVerifierValidCertificate(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	h.writeCRL(t, nil, 1, time.Now().Add(48*time.Hour))

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
	h.writeCRL(t, []*big.Int{revokedSerial}, 2, time.Now().Add(48*time.Hour))

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

	// NextUpdate expired 1 hour ago
	h.writeCRL(t, nil, 1, time.Now().Add(-1*time.Hour))

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	cert, _ := h.issueClientCert(t, "f47ac10b-58cc-4372-a567-0e02b2c3d479", 3003)

	_, err := v.VerifyCertificate(cert, time.Now())
	if err != ErrCRLExpired {
		t.Fatalf("expected ErrCRLExpired, got: %v", err)
	}
}

func TestVerifierForeignCA(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	h.writeCRL(t, nil, 1, time.Now().Add(48*time.Hour))

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

func TestVerifierCanonicalProfileNegative(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	h.writeCRL(t, nil, 1, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	// 1. Non-canonical UUID
	nonUUIDCert, _ := h.issueClientCert(t, "invalid-non-uuid-name", 5001)
	if _, err := v.VerifyCertificate(nonUUIDCert, time.Now()); err != ErrInvalidCommonName {
		t.Errorf("expected ErrInvalidCommonName, got: %v", err)
	}

	// 2. Wrong Organization
	validID := "e57c6bc1-1a3b-4882-9f37-1424e88383e2"
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse("urn:secrethub:client:" + validID)
	wrongOrgTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(5002),
		Subject:               pkix.Name{Organization: []string{"Wrong Org"}, CommonName: validID},
		URIs:                  []*url.URL{uri},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, wrongOrgTemplate, h.caCert, &clientKey.PublicKey, h.caKey)
	wrongOrgCert, _ := x509.ParseCertificate(der)
	if _, err := v.VerifyCertificate(wrongOrgCert, time.Now()); err != ErrInvalidOrganization {
		t.Errorf("expected ErrInvalidOrganization, got: %v", err)
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
	}
	der, _ = x509.CreateCertificate(rand.Reader, isCATemplate, h.caCert, &clientKey.PublicKey, h.caKey)
	isCACert, _ := x509.ParseCertificate(der)
	if _, err := v.VerifyCertificate(isCACert, time.Now()); err != ErrIsCACertificate {
		t.Errorf("expected ErrIsCACertificate, got: %v", err)
	}
}

func TestTLSVerifierRealHandshake(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	revokedSerial := big.NewInt(9999)
	h.writeCRL(t, []*big.Int{revokedSerial}, 1, time.Now().Add(48*time.Hour))

	v := NewVerifier(h.tmpDir)
	if _, err := v.LoadFromDisk(); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	tv := &TLSVerifier{
		verifier: v,
		logger:   zap.NewNop(),
	}

	// Create test server with custom VerifyPeerCertificate
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
	h.writeCRL(t, []*big.Int{revokedSerial}, 1, time.Now().Add(48*time.Hour))

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
