package secrethubpki

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

var (
	ErrNoClientCert         = errors.New("no client certificate provided in TLS handshake")
	ErrCADerivationFailed   = errors.New("failed to load root CA certificate")
	ErrCRLParseFailed       = errors.New("failed to parse certificate revocation list")
	ErrCRLSignatureInvalid  = errors.New("CRL signature does not match CA")
	ErrCRLExpired           = errors.New("CRL nextUpdate has expired")
	ErrCertRevoked          = errors.New("client certificate has been revoked")
	ErrCertInvalidChain     = errors.New("client certificate chain is invalid")
	ErrMissingSAN           = errors.New("client certificate missing valid SecretHub URI SAN")
	ErrCNMismatch           = errors.New("client certificate CN does not match URI SAN identity")
	ErrNoClientAuthEKU      = errors.New("client certificate does not permit clientAuth key usage")
	ErrBundleNotLoaded      = errors.New("trust bundle is not loaded")
)

// ValidatedIdentity contains authenticated client identity info.
type ValidatedIdentity struct {
	IdentityID    string
	CommonName    string
	SerialNumber  string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	RevocationGen int64
}

// BundleSnapshot represents an immutable in-memory snapshot of the trust bundle.
type BundleSnapshot struct {
	Generation int64
	CRLNumber  int64
	CACert     *x509.Certificate
	CAPool     *x509.CertPool
	CRL        *x509.RevocationList
	RevokedMap map[string]struct{} // Hex-encoded serial -> struct{}
	LoadedAt   time.Time
}

// Verifier handles offline validation of client certificates against local trust bundles.
type Verifier struct {
	bundleDir string
	snapshot  atomic.Pointer[BundleSnapshot]
	clockSkew time.Duration
}

// NewVerifier creates a new Verifier configured to read from bundleDir.
func NewVerifier(bundleDir string) *Verifier {
	return &Verifier{
		bundleDir: bundleDir,
		clockSkew: 5 * time.Minute,
	}
}

// LoadFromDisk reads the current trust bundle from disk and atomically updates the snapshot.
func (v *Verifier) LoadFromDisk() (*BundleSnapshot, error) {
	currentDir := filepath.Join(v.bundleDir, "current")
	caPath := filepath.Join(currentDir, "ca.crt")
	crlPath := filepath.Join(currentDir, "crl.pem")

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", caPath, err)
	}

	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", crlPath, err)
	}

	snapshot, err := ParseBundle(caPEM, crlPEM)
	if err != nil {
		return nil, err
	}

	v.snapshot.Store(snapshot)
	return snapshot, nil
}

// ParseBundle parses and cross-verifies CA and CRL PEM buffers.
func ParseBundle(caPEM, crlPEM []byte) (*BundleSnapshot, error) {
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, ErrCADerivationFailed
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCADerivationFailed, err)
	}

	crlBlock, _ := pem.Decode(crlPEM)
	if crlBlock == nil {
		return nil, ErrCRLParseFailed
	}

	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCRLParseFailed, err)
	}

	if err := crl.CheckSignatureFrom(caCert); err != nil {
		return nil, ErrCRLSignatureInvalid
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	revokedMap := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil {
			revokedMap[entry.SerialNumber.Text(16)] = struct{}{}
		}
	}

	crlNumber := int64(0)
	if crl.Number != nil {
		crlNumber = crl.Number.Int64()
	}

	snapshot := &BundleSnapshot{
		CRLNumber:  crlNumber,
		CACert:     caCert,
		CAPool:     caPool,
		CRL:        crl,
		RevokedMap: revokedMap,
		LoadedAt:   time.Now(),
	}

	return snapshot, nil
}

// SetSnapshot manually sets the current in-memory snapshot (useful for testing or dynamic loading).
func (v *Verifier) SetSnapshot(snapshot *BundleSnapshot) {
	v.snapshot.Store(snapshot)
}

// CurrentSnapshot returns the currently loaded bundle snapshot.
func (v *Verifier) CurrentSnapshot() *BundleSnapshot {
	return v.snapshot.Load()
}

// VerifyCertificate verifies a peer certificate according to SecretHub Client Auth PKI rules.
func (v *Verifier) VerifyCertificate(cert *x509.Certificate, now time.Time) (*ValidatedIdentity, error) {
	if cert == nil {
		return nil, ErrNoClientCert
	}

	snapshot := v.snapshot.Load()
	if snapshot == nil {
		return nil, ErrBundleNotLoaded
	}

	// 1. Check CRL expiration (fail-closed if CRL is expired past clock skew)
	if now.After(snapshot.CRL.NextUpdate.Add(v.clockSkew)) {
		return nil, ErrCRLExpired
	}

	// 2. Verify certificate chain against CA pool
	verifyOpts := x509.VerifyOptions{
		Roots:       snapshot.CAPool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(verifyOpts); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertInvalidChain, err)
	}

	// 3. Check revocation status in CRL
	if cert.SerialNumber != nil {
		serialHex := cert.SerialNumber.Text(16)
		if _, revoked := snapshot.RevokedMap[serialHex]; revoked {
			return nil, ErrCertRevoked
		}
	}

	// 4. Verify URI SAN (urn:secrethub:client:<UUID>) and CN matching
	identityID, err := extractClientIdentity(cert)
	if err != nil {
		return nil, err
	}

	if cert.Subject.CommonName != identityID {
		return nil, ErrCNMismatch
	}

	return &ValidatedIdentity{
		IdentityID:    identityID,
		CommonName:    cert.Subject.CommonName,
		SerialNumber:  formatSerial(cert.SerialNumber),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		RevocationGen: snapshot.Generation,
	}, nil
}

func extractClientIdentity(cert *x509.Certificate) (string, error) {
	for _, uri := range cert.URIs {
		if uri != nil && uri.Scheme == "urn" {
			// urn:secrethub:client:<UUID>
			parts := strings.Split(uri.Opaque, ":")
			if len(parts) == 3 && parts[0] == "secrethub" && parts[1] == "client" {
				return parts[2], nil
			}
			// Alternate format if parsed as URI string
			str := uri.String()
			if strings.HasPrefix(str, "urn:secrethub:client:") {
				return strings.TrimPrefix(str, "urn:secrethub:client:"), nil
			}
		}
	}

	// Fallback to checking raw SAN extensions if standard parser parsed differently
	for _, uriStr := range cert.DNSNames {
		if strings.HasPrefix(uriStr, "urn:secrethub:client:") {
			return strings.TrimPrefix(uriStr, "urn:secrethub:client:"), nil
		}
	}

	return "", ErrMissingSAN
}

func formatSerial(s *big.Int) string {
	if s == nil {
		return ""
	}
	hex := s.Text(16)
	if len(hex)%2 != 0 {
		hex = "0" + hex
	}
	var formatted []string
	for i := 0; i < len(hex); i += 2 {
		formatted = append(formatted, hex[i:i+2])
	}
	return strings.Join(formatted, ":")
}
