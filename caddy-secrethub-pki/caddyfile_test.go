package secrethubpki

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestCaddyfileUnmarshalTLSVerifier(t *testing.T) {
	input := `secrethub_client_auth {
		bundle_dir /var/lib/secrethub/pki/client-auth
		watermark_file /var/lib/caddy/watermark.json
		expected_ca_fingerprint 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
		poll_interval 10s
	}`

	d := caddyfile.NewTestDispenser(input)
	tv := new(TLSVerifier)
	if err := tv.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if tv.BundleDir != "/var/lib/secrethub/pki/client-auth" {
		t.Errorf("expected bundle_dir /var/lib/secrethub/pki/client-auth, got %s", tv.BundleDir)
	}
	if tv.WatermarkFile != "/var/lib/caddy/watermark.json" {
		t.Errorf("expected watermark_file /var/lib/caddy/watermark.json, got %s", tv.WatermarkFile)
	}
	if tv.ExpectedCAFingerprint != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("unexpected expected_ca_fingerprint: %s", tv.ExpectedCAFingerprint)
	}
	if time.Duration(tv.PollInterval) != 10*time.Second {
		t.Errorf("expected poll_interval 10s, got %v", tv.PollInterval)
	}
}

func TestCaddyfileUnmarshalSecretHubClientAuth(t *testing.T) {
	input := `secrethub_client_auth {
		bundle_dir /var/lib/secrethub/pki/client-auth
		watermark_file /var/lib/caddy/watermark.json
		expected_ca_fingerprint 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
		poll_interval 5s
		set_headers true
	}`

	d := caddyfile.NewTestDispenser(input)
	m := new(SecretHubClientAuth)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if m.BundleDir != "/var/lib/secrethub/pki/client-auth" {
		t.Errorf("expected bundle_dir /var/lib/secrethub/pki/client-auth, got %s", m.BundleDir)
	}
	if m.WatermarkFile != "/var/lib/caddy/watermark.json" {
		t.Errorf("expected watermark_file /var/lib/caddy/watermark.json, got %s", m.WatermarkFile)
	}
	if m.ExpectedCAFingerprint != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("unexpected expected_ca_fingerprint: %s", m.ExpectedCAFingerprint)
	}
	if time.Duration(m.PollInterval) != 5*time.Second {
		t.Errorf("expected poll_interval 5s, got %v", m.PollInterval)
	}
	if m.SetHeaders == nil || !*m.SetHeaders {
		t.Errorf("expected set_headers true, got %v", m.SetHeaders)
	}
}

func TestCaddyfileRejectsUnknownSubdirective(t *testing.T) {
	input := `secrethub_client_auth {
		bundle_dir /var/lib/secrethub/pki/client-auth
		unknown_option true
	}`

	d := caddyfile.NewTestDispenser(input)
	tv := new(TLSVerifier)
	if err := tv.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected error on unknown subdirective, got nil")
	}
}

func TestProvisionWithReadOnlyBundleDirAndCustomWatermark(t *testing.T) {
	h := newTestHarness(t)
	defer os.RemoveAll(h.tmpDir)

	// Write valid bundle at generation 1
	h.writeBundle(t, 1, 100, nil, time.Now().Add(24*time.Hour))

	// Create separate watermark directory
	wmDir, err := os.MkdirTemp("", "caddy-pki-wm-*")
	if err != nil {
		t.Fatalf("failed to create temp wm dir: %v", err)
	}
	defer os.RemoveAll(wmDir)

	wmFile := filepath.Join(wmDir, "custom-watermark.json")

	// Set bundle dir permissions to read-only (0555)
	if err := os.Chmod(h.tmpDir, 0555); err != nil {
		t.Fatalf("failed to make bundle dir read-only: %v", err)
	}
	defer os.Chmod(h.tmpDir, 0755) // restore for cleanup

	sum := sha256.Sum256(h.caCert.Raw)
	fingerprint := hex.EncodeToString(sum[:])

	tv := &TLSVerifier{
		BundleDir:             h.tmpDir,
		WatermarkFile:         wmFile,
		ExpectedCAFingerprint: fingerprint,
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	if err := tv.Provision(ctx); err != nil {
		t.Fatalf("Provision failed with read-only bundle dir and custom watermark: %v", err)
	}

	// Verify watermark was written to custom path
	if _, err := os.Stat(wmFile); err != nil {
		t.Fatalf("expected watermark at %s, got error: %v", wmFile, err)
	}
}
