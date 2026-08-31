package secrethubpki

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// AutoLoader periodically checks for trust bundle updates on disk and reloads the verifier.
type AutoLoader struct {
	verifier     *Verifier
	pollInterval time.Duration
	logger       *zap.Logger
	lastTarget   string
	lastModTime  time.Time
}

// NewAutoLoader creates an AutoLoader with the given polling interval.
func NewAutoLoader(verifier *Verifier, pollInterval time.Duration, logger *zap.Logger) *AutoLoader {
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AutoLoader{
		verifier:     verifier,
		pollInterval: pollInterval,
		logger:       logger,
	}
}

// Start begins the periodic reload loop in a background goroutine until ctx is cancelled.
func (a *AutoLoader) Start(ctx context.Context) {
	// Initial load
	if _, err := a.verifier.LoadFromDisk(); err != nil {
		a.logger.Warn("Initial trust bundle load failed, will retry", zap.Error(err))
	} else {
		a.logger.Info("Initial trust bundle loaded successfully")
	}

	ticker := time.NewTicker(a.pollInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.checkAndReload()
			}
		}
	}()
}

func (a *AutoLoader) checkAndReload() {
	currentLink := filepath.Join(a.verifier.bundleDir, "current")

	// Check if symlink target or target directory modification time has changed
	target, err := os.Readlink(currentLink)
	if err != nil {
		// Not a symlink, check directory modtime
		fi, err := os.Stat(currentLink)
		if err != nil {
			return
		}
		if fi.ModTime().Equal(a.lastModTime) {
			return
		}
		a.lastModTime = fi.ModTime()
	} else {
		if target == a.lastTarget {
			// Check if crl.pem mod time changed inside the target
			crlPath := filepath.Join(currentLink, "crl.pem")
			fi, err := os.Stat(crlPath)
			if err == nil && fi.ModTime().Equal(a.lastModTime) {
				return
			}
			if err == nil {
				a.lastModTime = fi.ModTime()
			}
		} else {
			a.lastTarget = target
		}
	}

	snapshot, err := a.verifier.LoadFromDisk()
	if err != nil {
		a.logger.Error("Failed to reload trust bundle from disk", zap.Error(err))
		return
	}

	a.logger.Info("Reloaded trust bundle snapshot",
		zap.Int64("crl_number", snapshot.CRLNumber),
		zap.Int("revoked_count", len(snapshot.RevokedMap)),
		zap.Time("crl_next_update", snapshot.CRL.NextUpdate),
	)
}
