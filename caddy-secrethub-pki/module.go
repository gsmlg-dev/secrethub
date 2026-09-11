package secrethubpki

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SecretHubClientAuth{})
	caddy.RegisterModule(TLSVerifier{})
}

// TLSVerifier is a Caddy TLS client authentication verifier that enforces
// SecretHub Client Auth PKI policies during the TLS handshake.
type TLSVerifier struct {
	// BundleDir is the path to the directory containing trust bundles (e.g. /var/lib/secrethub/pki/client-auth)
	BundleDir string `json:"bundle_dir,omitempty"`

	// WatermarkFile is an optional path to an independent monotonic watermark state file
	WatermarkFile string `json:"watermark_file,omitempty"`

	// ExpectedCAFingerprint optionally pins the expected CA certificate DER SHA-256 fingerprint
	ExpectedCAFingerprint string `json:"expected_ca_fingerprint,omitempty"`

	// PollInterval is how often to check for updated trust bundle files on disk (default 5s)
	PollInterval caddy.Duration `json:"poll_interval,omitempty"`

	verifier *Verifier
	loader   *AutoLoader
	ctx      context.Context
	cancel   context.CancelFunc
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (TLSVerifier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.client_auth.verifier.secrethub_client_auth",
		New: func() caddy.Module { return new(TLSVerifier) },
	}
}

// Provision sets up the TLSVerifier.
func (tv *TLSVerifier) Provision(ctx caddy.Context) error {
	tv.logger = ctx.Logger()

	if tv.BundleDir == "" {
		tv.BundleDir = "/var/lib/secrethub/pki/client-auth"
	}

	pollDuration := time.Duration(tv.PollInterval)
	if pollDuration <= 0 {
		pollDuration = 5 * time.Second
	}

	tv.verifier = NewVerifier(tv.BundleDir)
	if tv.WatermarkFile != "" {
		tv.verifier.SetWatermarkFile(tv.WatermarkFile)
	}
	if tv.ExpectedCAFingerprint != "" {
		tv.verifier.SetExpectedCAFingerprint(tv.ExpectedCAFingerprint)
	}

	if _, err := tv.verifier.LoadFromDisk(); err != nil {
		return fmt.Errorf("failed to load initial trust bundle from %s: %w", tv.BundleDir, err)
	}

	tv.loader = NewAutoLoader(tv.verifier, pollDuration, tv.logger)
	tv.ctx, tv.cancel = context.WithCancel(ctx)
	tv.loader.Start(tv.ctx)

	return nil
}

// Cleanup stops the background auto-loader goroutine.
func (tv *TLSVerifier) Cleanup() error {
	if tv.cancel != nil {
		tv.cancel()
	}
	return nil
}

// VerifyClientCertificate verifies the client certificates presented during the TLS handshake.
func (tv *TLSVerifier) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return ErrNoClientCert
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %w", err)
	}

	_, err = tv.verifier.VerifyCertificate(cert, time.Now())
	return err
}

// SecretHubClientAuth is a Caddy HTTP middleware that verifies incoming mTLS
// client certificates against local SecretHub Client Auth PKI trust bundles.
type SecretHubClientAuth struct {
	// BundleDir is the path to the directory containing trust bundles (e.g. /var/lib/secrethub/pki/client-auth)
	BundleDir string `json:"bundle_dir,omitempty"`

	// WatermarkFile is an optional path to an independent monotonic watermark state file
	WatermarkFile string `json:"watermark_file,omitempty"`

	// ExpectedCAFingerprint optionally pins the expected CA certificate DER SHA-256 fingerprint
	ExpectedCAFingerprint string `json:"expected_ca_fingerprint,omitempty"`

	// PollInterval is how often to check for updated trust bundle files on disk (default 5s)
	PollInterval caddy.Duration `json:"poll_interval,omitempty"`

	// SetHeaders controls whether to set identity headers on the downstream request (default true)
	SetHeaders *bool `json:"set_headers,omitempty"`

	verifier *Verifier
	loader   *AutoLoader
	ctx      context.Context
	cancel   context.CancelFunc
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SecretHubClientAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.secrethub_client_auth",
		New: func() caddy.Module { return new(SecretHubClientAuth) },
	}
}

// Provision sets up the middleware.
func (m *SecretHubClientAuth) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if m.BundleDir == "" {
		m.BundleDir = "/var/lib/secrethub/pki/client-auth"
	}

	pollDuration := time.Duration(m.PollInterval)
	if pollDuration <= 0 {
		pollDuration = 5 * time.Second
	}

	m.verifier = NewVerifier(m.BundleDir)
	if m.WatermarkFile != "" {
		m.verifier.SetWatermarkFile(m.WatermarkFile)
	}
	if m.ExpectedCAFingerprint != "" {
		m.verifier.SetExpectedCAFingerprint(m.ExpectedCAFingerprint)
	}

	if _, err := m.verifier.LoadFromDisk(); err != nil {
		return fmt.Errorf("failed to load initial trust bundle from %s: %w", m.BundleDir, err)
	}

	m.loader = NewAutoLoader(m.verifier, pollDuration, m.logger)
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.loader.Start(m.ctx)

	return nil
}

// Cleanup stops the background auto-loader goroutine.
func (m *SecretHubClientAuth) Cleanup() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

// ServeHTTP handles the incoming HTTP request, enforcing client certificate validation.
func (m *SecretHubClientAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		m.logger.Warn("mTLS authentication rejected: no peer certificate provided",
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("path", r.URL.Path),
		)
		w.Header().Set("WWW-Authenticate", "Bearer error=\"mtls_required\"")
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
		return nil
	}

	peerCert := r.TLS.PeerCertificates[0]
	now := time.Now()

	identity, err := m.verifier.VerifyCertificate(peerCert, now)
	if err != nil {
		m.logger.Warn("Client certificate authentication failed",
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("subject", peerCert.Subject.String()),
			zap.Error(err),
		)

		status := http.StatusForbidden
		if err == ErrCRLExpired || err == ErrBundleNotLoaded {
			status = http.StatusServiceUnavailable
		}

		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), status)
		return nil
	}

	// Set authenticated headers for upstream backend
	setHeaders := true
	if m.SetHeaders != nil {
		setHeaders = *m.SetHeaders
	}

	if setHeaders {
		r.Header.Set("X-SecretHub-Client-ID", identity.IdentityID)
		r.Header.Set("X-SecretHub-Client-CN", identity.CommonName)
		r.Header.Set("X-SecretHub-Client-Serial", identity.SerialNumber)
	}

	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner                  = (*TLSVerifier)(nil)
	_ caddy.CleanerUpper                 = (*TLSVerifier)(nil)
	_ caddytls.ClientCertificateVerifier = (*TLSVerifier)(nil)

	_ caddy.Provisioner           = (*SecretHubClientAuth)(nil)
	_ caddy.CleanerUpper          = (*SecretHubClientAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*SecretHubClientAuth)(nil)
)
