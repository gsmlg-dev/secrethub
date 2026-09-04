package secrethubpki

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	ErrNoClientCert            = errors.New("no client certificate provided in TLS handshake")
	ErrCorruptWatermark        = errors.New("persistent watermark file is corrupt or invalid")
	ErrCADerivationFailed      = errors.New("failed to load root CA certificate")
	ErrCRLParseFailed          = errors.New("failed to parse certificate revocation list")
	ErrCRLSignatureInvalid     = errors.New("CRL signature does not match CA")
	ErrCRLNotYetValid          = errors.New("CRL thisUpdate is in the future")
	ErrCRLExpired              = errors.New("CRL nextUpdate has expired")
	ErrCertRevoked             = errors.New("client certificate has been revoked")
	ErrCertInvalidChain        = errors.New("client certificate chain is invalid")
	ErrMissingSAN              = errors.New("client certificate must contain exactly one SecretHub URI SAN")
	ErrCNMismatch              = errors.New("client certificate CN does not match URI SAN identity")
	ErrNoClientAuthEKU         = errors.New("client certificate does not permit clientAuth key usage")
	ErrInvalidExtKeyUsage      = errors.New("client certificate contains unauthorized extended key usages")
	ErrInvalidKeyUsage         = errors.New("client certificate key usage must be digitalSignature only and marked critical")
	ErrMissingBasicConstraints = errors.New("client certificate must contain BasicConstraints CA=false")
	ErrInvalidOrganization     = errors.New("client certificate organization must be 'SecretHub Client Authentication'")
	ErrInvalidCommonName       = errors.New("client certificate CN must be a valid canonical UUID")
	ErrExtraSubjectAttributes  = errors.New("client certificate contains unauthorized subject RDN attributes")
	ErrExtraSANsDisallowed     = errors.New("client certificate contains unauthorized SANs (DNS, IP, or Email)")
	ErrIsCACertificate         = errors.New("client certificate cannot have IsCA=true")
	ErrBundleNotLoaded         = errors.New("trust bundle is not loaded")
	ErrManifestMissing         = errors.New("manifest.json missing from trust bundle")
	ErrManifestInvalid         = errors.New("manifest.json is invalid or corrupted")
	ErrTranscriptMismatch      = errors.New("calculated transcript hash does not match bundle_sha256")
	ErrCAFingerprintMismatch   = errors.New("CA certificate fingerprint does not match manifest or pinned CA")
	ErrCRLFingerprintMismatch  = errors.New("CRL DER hash does not match manifest")
	ErrCRLMetadataMismatch     = errors.New("signed CRL number or timestamps do not match manifest")
	ErrGenerationDowngrade     = errors.New("trust bundle generation downgrade rejected")
	ErrEquivocation            = errors.New("equivocation detected: differing bundle hash for same generation")
	ErrCRLNumberDowngrade      = errors.New("CRL number downgrade rejected")
)

var (
	oidBasicConstraints      = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage           = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtKeyUsageClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidCommonName            = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOrganization          = asn1.ObjectIdentifier{2, 5, 4, 10}
)

// BundleManifest represents the manifest.json published with every trust bundle generation.
type BundleManifest struct {
	SchemaVersion int    `json:"schema_version"`
	Authority     string `json:"authority"`
	Generation    int64  `json:"generation"`
	CRLNumber     int64  `json:"crl_number"`
	CAFingerprint string `json:"ca_fingerprint"`
	CRLDerSHA256  string `json:"crl_der_sha256"`
	BundleSHA256  string `json:"bundle_sha256"`
	ThisUpdate    string `json:"this_update"`
	NextUpdate    string `json:"next_update"`
}

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
	Generation    int64
	CRLNumber     int64
	CAFingerprint string
	BundleSHA256  string
	CACert        *x509.Certificate
	CAPool        *x509.CertPool
	CRL           *x509.RevocationList
	RevokedMap    map[string]struct{} // Hex-encoded serial -> struct{}
	LoadedAt      time.Time
}

// Verifier handles offline validation of client certificates against local trust bundles.
type Verifier struct {
	bundleDir             string
	watermarkFile         string
	expectedCAFingerprint string
	snapshot              atomic.Pointer[BundleSnapshot]
	clockSkew             time.Duration
}

// NewVerifier creates a new Verifier configured to read from bundleDir.
func NewVerifier(bundleDir string) *Verifier {
	return &Verifier{
		bundleDir: bundleDir,
		clockSkew: 5 * time.Minute,
	}
}

// SetWatermarkFile overrides the default watermark file location.
func (v *Verifier) SetWatermarkFile(path string) {
	v.watermarkFile = path
}

// SetExpectedCAFingerprint pins an expected CA certificate DER SHA-256 fingerprint.
func (v *Verifier) SetExpectedCAFingerprint(fp string) {
	v.expectedCAFingerprint = strings.ToLower(fp)
}

func (v *Verifier) getWatermarkPath() string {
	if v.watermarkFile != "" {
		return v.watermarkFile
	}
	return filepath.Join(v.bundleDir, "watermark.json")
}

// PersistentWatermark tracks high-water mark state across process restarts.
type PersistentWatermark struct {
	HighestSeenGeneration int64  `json:"highest_seen_generation"`
	HighestSeenCRLNumber  int64  `json:"highest_seen_crl_number"`
	PinnedCAFingerprint   string `json:"pinned_ca_fingerprint"`
	LastBundleSHA256      string `json:"last_bundle_sha256"`
}

var hex64Regex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func validateWatermark(wm *PersistentWatermark) error {
	if wm.HighestSeenGeneration <= 0 {
		return fmt.Errorf("%w: highest_seen_generation must be positive", ErrCorruptWatermark)
	}
	if wm.HighestSeenCRLNumber <= 0 {
		return fmt.Errorf("%w: highest_seen_crl_number must be positive", ErrCorruptWatermark)
	}
	if !hex64Regex.MatchString(wm.PinnedCAFingerprint) {
		return fmt.Errorf("%w: pinned_ca_fingerprint must be a valid 64-char hex string", ErrCorruptWatermark)
	}
	if !hex64Regex.MatchString(wm.LastBundleSHA256) {
		return fmt.Errorf("%w: last_bundle_sha256 must be a valid 64-char hex string", ErrCorruptWatermark)
	}
	return nil
}

// LoadFromDisk reads the trust bundle from disk, enforces full validation, temporal validity,
// monotonicity, persists the watermark fail-closed, and atomically updates the snapshot.
func (v *Verifier) LoadFromDisk() (*BundleSnapshot, error) {
	bundlePath, err := v.resolveBundlePath()
	if err != nil {
		return nil, err
	}

	manifestPath := filepath.Join(bundlePath, "manifest.json")
	caPath := filepath.Join(bundlePath, "ca.crt")
	crlPath := filepath.Join(bundlePath, "crl.pem")

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read %s: %v", ErrManifestMissing, manifestPath, err)
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", caPath, err)
	}

	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", crlPath, err)
	}

	var manifest BundleManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}

	snapshot, err := ParseAndValidateBundle(&manifest, caPEM, crlPEM, time.Now(), v.clockSkew)
	if err != nil {
		return nil, err
	}

	// 1. Operator-configured CA fingerprint check
	if v.expectedCAFingerprint != "" && !strings.EqualFold(snapshot.CAFingerprint, v.expectedCAFingerprint) {
		return nil, fmt.Errorf("%w: candidate CA %s != expected configured CA %s", ErrCAFingerprintMismatch, snapshot.CAFingerprint, v.expectedCAFingerprint)
	}

	// 2. Persistent watermark check across restarts and concurrent instances under file lock
	watermarkPath := v.getWatermarkPath()
	wmDir := filepath.Dir(watermarkPath)
	if err := os.MkdirAll(wmDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create watermark directory: %w", err)
	}

	lockPath := watermarkPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open watermark lock file: %w", err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("failed to acquire watermark file lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	var diskWM PersistentWatermark
	hasDiskWM := false
	if wmBytes, err := os.ReadFile(watermarkPath); err == nil {
		if err := json.Unmarshal(wmBytes, &diskWM); err != nil {
			return nil, fmt.Errorf("%w: failed to parse watermark.json: %v", ErrCorruptWatermark, err)
		}
		if err := validateWatermark(&diskWM); err != nil {
			return nil, err
		}
		hasDiskWM = true

		if snapshot.Generation < diskWM.HighestSeenGeneration {
			return nil, fmt.Errorf("%w: new gen %d < persistent watermark gen %d", ErrGenerationDowngrade, snapshot.Generation, diskWM.HighestSeenGeneration)
		}
		if snapshot.Generation == diskWM.HighestSeenGeneration && !strings.EqualFold(snapshot.BundleSHA256, diskWM.LastBundleSHA256) {
			return nil, fmt.Errorf("%w: gen %d hash mismatch with persistent watermark (%s != %s)", ErrEquivocation, snapshot.Generation, snapshot.BundleSHA256, diskWM.LastBundleSHA256)
		}
		if snapshot.Generation >= diskWM.HighestSeenGeneration && snapshot.CRLNumber < diskWM.HighestSeenCRLNumber {
			return nil, fmt.Errorf("%w: new crl_number %d < persistent watermark crl_number %d", ErrCRLNumberDowngrade, snapshot.CRLNumber, diskWM.HighestSeenCRLNumber)
		}
		if diskWM.PinnedCAFingerprint != "" && !strings.EqualFold(snapshot.CAFingerprint, diskWM.PinnedCAFingerprint) {
			return nil, fmt.Errorf("%w: established CA %s replaced with %s", ErrCAFingerprintMismatch, diskWM.PinnedCAFingerprint, snapshot.CAFingerprint)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read watermark file (fail closed): %w", err)
	}

	// 3. Monotonicity checks against existing in-memory active snapshot
	current := v.snapshot.Load()
	if current != nil {
		if snapshot.Generation < current.Generation {
			return nil, fmt.Errorf("%w: new gen %d < current gen %d", ErrGenerationDowngrade, snapshot.Generation, current.Generation)
		}
		if snapshot.Generation == current.Generation && !strings.EqualFold(snapshot.BundleSHA256, current.BundleSHA256) {
			return nil, fmt.Errorf("%w: gen %d hash mismatch (%s != %s)", ErrEquivocation, snapshot.Generation, snapshot.BundleSHA256, current.BundleSHA256)
		}
		if snapshot.Generation >= current.Generation && snapshot.CRLNumber < current.CRLNumber {
			return nil, fmt.Errorf("%w: new crl_number %d < current crl_number %d", ErrCRLNumberDowngrade, snapshot.CRLNumber, current.CRLNumber)
		}
		if current.CAFingerprint != "" && !strings.EqualFold(snapshot.CAFingerprint, current.CAFingerprint) {
			return nil, fmt.Errorf("%w: established CA %s replaced with %s", ErrCAFingerprintMismatch, current.CAFingerprint, snapshot.CAFingerprint)
		}
	}

	// 4. Atomically persist updated watermark with monotonic maximum
	maxGen := snapshot.Generation
	maxCRL := snapshot.CRLNumber
	if hasDiskWM {
		if diskWM.HighestSeenGeneration > maxGen {
			maxGen = diskWM.HighestSeenGeneration
		}
		if diskWM.HighestSeenCRLNumber > maxCRL {
			maxCRL = diskWM.HighestSeenCRLNumber
		}
	}

	wm := PersistentWatermark{
		HighestSeenGeneration: maxGen,
		HighestSeenCRLNumber:  maxCRL,
		PinnedCAFingerprint:   snapshot.CAFingerprint,
		LastBundleSHA256:      snapshot.BundleSHA256,
	}
	wmBytes, err := json.MarshalIndent(wm, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode watermark: %w", err)
	}

	tmpWMPath := filepath.Join(wmDir, fmt.Sprintf(".watermark.tmp-%d", time.Now().UnixNano()))
	tmpFile, err := os.OpenFile(tmpWMPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to create watermark temp file: %w", err)
	}
	if _, err := tmpFile.Write(wmBytes); err != nil {
		tmpFile.Close()
		os.Remove(tmpWMPath)
		return nil, fmt.Errorf("failed to write watermark temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpWMPath)
		return nil, fmt.Errorf("failed to sync watermark temp file: %w", err)
	}
	tmpFile.Close()

	if err := os.Rename(tmpWMPath, watermarkPath); err != nil {
		_ = os.Remove(tmpWMPath)
		return nil, fmt.Errorf("failed to commit watermark: %w", err)
	}

	if err := syncDir(wmDir); err != nil {
		return nil, fmt.Errorf("failed to sync watermark directory: %w", err)
	}

	v.snapshot.Store(snapshot)
	return snapshot, nil
}

func (v *Verifier) resolveBundlePath() (string, error) {
	currentDir := filepath.Join(v.bundleDir, "current")
	if fi, err := os.Stat(currentDir); err == nil && fi.IsDir() {
		return currentDir, nil
	}

	// If current symlink not yet created, scan generations directory for highest valid generation
	generationsDir := filepath.Join(v.bundleDir, "generations")
	entries, err := os.ReadDir(generationsDir)
	if err != nil {
		return "", fmt.Errorf("bundle directory %s has no current symlink or generations: %w", v.bundleDir, err)
	}

	var highestGen int64 = -1
	var highestPath string
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			gen, err := strconv.ParseInt(entry.Name(), 10, 64)
			if err == nil && gen > highestGen {
				highestGen = gen
				highestPath = filepath.Join(generationsDir, entry.Name())
			}
		}
	}

	if highestPath == "" {
		return "", fmt.Errorf("no valid generations found in %s", generationsDir)
	}
	return highestPath, nil
}

// ParseAndValidateBundle parses CA, CRL and validates against the manifest metadata,
// transcript hash, and temporal validity window.
func ParseAndValidateBundle(manifest *BundleManifest, caPEM, crlPEM []byte, now time.Time, clockSkew time.Duration) (*BundleSnapshot, error) {
	if manifest.SchemaVersion != 1 {
		return nil, fmt.Errorf("%w: unsupported schema_version %d", ErrManifestInvalid, manifest.SchemaVersion)
	}

	// 1. Verify transcript SHA-256 hash
	transcript := fmt.Sprintf("%d|%s|%d|%s|%d|%s|%s|%s|%s|%s",
		manifest.SchemaVersion,
		manifest.Authority,
		manifest.Generation,
		manifest.CAFingerprint,
		manifest.CRLNumber,
		manifest.CRLDerSHA256,
		manifest.ThisUpdate,
		manifest.NextUpdate,
		string(caPEM),
		string(crlPEM),
	)
	calcHash := sha256.Sum256([]byte(transcript))
	calcHashHex := hex.EncodeToString(calcHash[:])

	if strings.ToLower(calcHashHex) != strings.ToLower(manifest.BundleSHA256) {
		return nil, fmt.Errorf("%w: calculated %s != manifest %s", ErrTranscriptMismatch, calcHashHex, manifest.BundleSHA256)
	}

	// 2. Parse CA certificate
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, ErrCADerivationFailed
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCADerivationFailed, err)
	}

	caDERHash := sha256.Sum256(caCert.Raw)
	caFingerprint := hex.EncodeToString(caDERHash[:])
	if strings.ToLower(caFingerprint) != strings.ToLower(manifest.CAFingerprint) {
		return nil, fmt.Errorf("%w: parsed CA %s != manifest %s", ErrCAFingerprintMismatch, caFingerprint, manifest.CAFingerprint)
	}

	// 3. Parse and verify CRL
	crlBlock, _ := pem.Decode(crlPEM)
	if crlBlock == nil {
		return nil, ErrCRLParseFailed
	}
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCRLParseFailed, err)
	}

	crlDERHash := sha256.Sum256(crl.Raw)
	crlDERHashHex := hex.EncodeToString(crlDERHash[:])
	if strings.ToLower(crlDERHashHex) != strings.ToLower(manifest.CRLDerSHA256) {
		return nil, fmt.Errorf("%w: parsed CRL %s != manifest %s", ErrCRLFingerprintMismatch, crlDERHashHex, manifest.CRLDerSHA256)
	}

	if err := crl.CheckSignatureFrom(caCert); err != nil {
		return nil, ErrCRLSignatureInvalid
	}

	// Check CRL Number extension matches manifest
	crlNum := int64(0)
	if crl.Number != nil {
		crlNum = crl.Number.Int64()
	}
	if crlNum != manifest.CRLNumber {
		return nil, fmt.Errorf("%w: signed CRL number %d != manifest %d", ErrCRLMetadataMismatch, crlNum, manifest.CRLNumber)
	}

	// Check CRL Timestamps match manifest
	manifestThisUpdate, err := time.Parse(time.RFC3339, manifest.ThisUpdate)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid manifest this_update: %v", ErrManifestInvalid, err)
	}
	manifestNextUpdate, err := time.Parse(time.RFC3339, manifest.NextUpdate)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid manifest next_update: %v", ErrManifestInvalid, err)
	}

	if !crl.ThisUpdate.UTC().Equal(manifestThisUpdate.UTC()) {
		return nil, fmt.Errorf("%w: signed CRL thisUpdate %v != manifest %v", ErrCRLMetadataMismatch, crl.ThisUpdate, manifestThisUpdate)
	}
	if !crl.NextUpdate.UTC().Equal(manifestNextUpdate.UTC()) {
		return nil, fmt.Errorf("%w: signed CRL nextUpdate %v != manifest %v", ErrCRLMetadataMismatch, crl.NextUpdate, manifestNextUpdate)
	}

	// 4. Validate temporal validity window of CRL
	if now.Add(clockSkew).Before(crl.ThisUpdate) {
		return nil, fmt.Errorf("%w: CRL thisUpdate %v is in the future relative to %v", ErrCRLNotYetValid, crl.ThisUpdate, now)
	}
	if now.After(crl.NextUpdate.Add(clockSkew)) {
		return nil, fmt.Errorf("%w: CRL nextUpdate %v is in the past relative to %v", ErrCRLExpired, crl.NextUpdate, now)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	revokedMap := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil {
			revokedMap[entry.SerialNumber.Text(16)] = struct{}{}
		}
	}

	snapshot := &BundleSnapshot{
		Generation:    manifest.Generation,
		CRLNumber:     crlNum,
		CAFingerprint: caFingerprint,
		BundleSHA256:  manifest.BundleSHA256,
		CACert:        caCert,
		CAPool:        caPool,
		CRL:           crl,
		RevokedMap:    revokedMap,
		LoadedAt:      time.Now(),
	}

	return snapshot, nil
}

// SetSnapshot manually sets the current in-memory snapshot (useful for testing).
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

	// 1. Check CRL temporal window (fail-closed if outside validity + clock skew)
	if now.Before(snapshot.CRL.ThisUpdate.Add(-v.clockSkew)) {
		return nil, ErrCRLNotYetValid
	}
	if now.After(snapshot.CRL.NextUpdate.Add(v.clockSkew)) {
		return nil, ErrCRLExpired
	}

	// 2. Enforce Canonical Profile Constraints
	if cert.IsCA {
		return nil, ErrIsCACertificate
	}

	// Must have exact Subject RDN: Only Organization = "SecretHub Client Authentication" and CommonName = UUID
	if err := validateSubjectRDN(cert.Subject); err != nil {
		return nil, err
	}

	cn := cert.Subject.CommonName
	if !isCanonicalUUID(cn) {
		return nil, ErrInvalidCommonName
	}

	// Exactly one SAN URI: urn:secrethub:client:<UUID>
	if len(cert.URIs) != 1 {
		return nil, ErrMissingSAN
	}
	expectedURI := "urn:secrethub:client:" + cn
	if cert.URIs[0].String() != expectedURI {
		return nil, ErrCNMismatch
	}

	// No extra SANs allowed (no DNS names, IP addresses, email addresses)
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 {
		return nil, ErrExtraSANsDisallowed
	}

	// Check Basic Constraints extension presence and criticality
	if err := validateBasicConstraintsExtension(cert); err != nil {
		return nil, err
	}

	// Key Usage must be present, marked critical, and digitalSignature only
	if err := validateKeyUsageExtension(cert); err != nil {
		return nil, err
	}

	// Extended Key Usage must be present, exactly clientAuth, with no unknown EKUs
	if err := validateExtKeyUsageExtension(cert); err != nil {
		return nil, err
	}

	// 3. Verify certificate chain against CA pool
	verifyOpts := x509.VerifyOptions{
		Roots:       snapshot.CAPool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(verifyOpts); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertInvalidChain, err)
	}

	// 4. Check revocation status in CRL
	if cert.SerialNumber != nil {
		serialHex := cert.SerialNumber.Text(16)
		if _, revoked := snapshot.RevokedMap[serialHex]; revoked {
			return nil, ErrCertRevoked
		}
	}

	return &ValidatedIdentity{
		IdentityID:    cn,
		CommonName:    cn,
		SerialNumber:  formatSerial(cert.SerialNumber),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		RevocationGen: snapshot.Generation,
	}, nil
}

func validateSubjectRDN(subject pkix.Name) error {
	if len(subject.Organization) != 1 || subject.Organization[0] != "SecretHub Client Authentication" {
		return ErrInvalidOrganization
	}
	if len(subject.Country) > 0 || len(subject.Province) > 0 || len(subject.Locality) > 0 ||
		len(subject.StreetAddress) > 0 || len(subject.PostalCode) > 0 || len(subject.OrganizationalUnit) > 0 {
		return ErrExtraSubjectAttributes
	}
	// Verify raw names contain only CN and O
	for _, atv := range subject.Names {
		if !atv.Type.Equal(oidCommonName) && !atv.Type.Equal(oidOrganization) {
			return ErrExtraSubjectAttributes
		}
	}
	return nil
}

func validateBasicConstraintsExtension(cert *x509.Certificate) error {
	found := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidBasicConstraints) {
			found = true
			break
		}
	}
	if !found {
		return ErrMissingBasicConstraints
	}
	if cert.IsCA {
		return errors.New("client certificate must not be a CA (CA:FALSE required)")
	}
	return nil
}

func validateKeyUsageExtension(cert *x509.Certificate) error {
	found := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidKeyUsage) {
			found = true
			if !ext.Critical {
				return errors.New("KeyUsage extension must be marked critical")
			}
			break
		}
	}
	if !found || cert.KeyUsage != x509.KeyUsageDigitalSignature {
		return ErrInvalidKeyUsage
	}
	return nil
}

func validateExtKeyUsageExtension(cert *x509.Certificate) error {
	if len(cert.UnknownExtKeyUsage) > 0 {
		return ErrInvalidExtKeyUsage
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return ErrNoClientAuthEKU
	}
	return nil
}

func isCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
		} else {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
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

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
