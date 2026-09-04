package secrethubpki

import (
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("secrethub_client_auth", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(SecretHubClientAuth)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (m *SecretHubClientAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "bundle_dir":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.BundleDir = d.Val()

			case "poll_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid poll_interval: %v", err)
				}
				m.PollInterval = caddy.Duration(dur)

			case "set_headers":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("invalid set_headers boolean: %v", err)
				}
				m.SetHeaders = &val

			case "watermark_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.WatermarkFile = d.Val()

			case "expected_ca_fingerprint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ExpectedCAFingerprint = d.Val()

			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// UnmarshalCaddyfile sets up the TLSVerifier module from Caddyfile tokens.
func (tv *TLSVerifier) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "bundle_dir":
				if !d.NextArg() {
					return d.ArgErr()
				}
				tv.BundleDir = d.Val()

			case "poll_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid poll_interval: %v", err)
				}
				tv.PollInterval = caddy.Duration(dur)

			case "watermark_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				tv.WatermarkFile = d.Val()

			case "expected_ca_fingerprint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				tv.ExpectedCAFingerprint = d.Val()

			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*SecretHubClientAuth)(nil)
	_ caddyfile.Unmarshaler = (*TLSVerifier)(nil)
)
