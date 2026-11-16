package unifi

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// validUnifiConfig returns a Config that passes Validate; tests mutate one
// field at a time to exercise each rule.
func validUnifiConfig() Config {
	return Config{
		Host:              testHost,
		APIKey:            testKeyA,
		Site:              testSite,
		RetryAttempts:     3,
		RetryInitialDelay: 500 * time.Millisecond,
		RetryMaxDelay:     10 * time.Second,
		ApplyWorkers:      5,
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid", func(*Config) {}, false},
		{"host missing scheme", func(c *Config) { c.Host = "unifi.local" }, true},
		{"host empty", func(c *Config) { c.Host = "" }, true},
		{"retry attempts zero", func(c *Config) { c.RetryAttempts = 0 }, true},
		{"retry attempts too high", func(c *Config) { c.RetryAttempts = maxRetryAttempts + 1 }, true},
		{"apply workers zero", func(c *Config) { c.ApplyWorkers = 0 }, true},
		{"apply workers too high", func(c *Config) { c.ApplyWorkers = maxApplyWorkers + 1 }, true},
		{"initial delay zero", func(c *Config) { c.RetryInitialDelay = 0 }, true},
		{"initial delay below floor", func(c *Config) { c.RetryInitialDelay = time.Nanosecond }, true},
		{"initial delay at floor", func(c *Config) {
			c.RetryInitialDelay = minRetryInitialDelay
			c.RetryMaxDelay = minRetryInitialDelay
		}, false},
		{"max delay below initial", func(c *Config) { c.RetryMaxDelay = 100 * time.Millisecond }, true},
		{"request timeout negative", func(c *Config) { c.RequestTimeout = -time.Second }, true},
		{"request timeout set", func(c *Config) { c.RequestTimeout = 4 * time.Second }, false},
		{"cloud host without console id", func(c *Config) { c.Host = "https://api.ui.com" }, true},
		{"cloud host with console id", func(c *Config) {
			c.Host = "https://api.ui.com"
			c.ConsoleID = testConsoleID
		}, false},
		{"console id with local host is fine", func(c *Config) { c.ConsoleID = testConsoleID }, false},
		{"site empty", func(c *Config) { c.Site = "" }, true},
		{"site is an Integration API UUID", func(c *Config) { c.Site = testSiteUUID }, true},
		{"site with a dash is fine", func(c *Config) { c.Site = "branch-office" }, false},
		{"api key empty", func(c *Config) { c.APIKey = "" }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validUnifiConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr != (err != nil) {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigResolveAPIKey(t *testing.T) {
	writeKey := func(t *testing.T, contents string) string {
		t.Helper()

		path := filepath.Join(t.TempDir(), "api-key")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("writing API key file: %v", err)
		}

		return path
	}

	t.Run("file supplies the key and trailing newline is trimmed", func(t *testing.T) {
		cfg := validUnifiConfig()
		cfg.APIKey = ""
		cfg.APIKeyFile = writeKey(t, "key-from-file\n")

		if err := cfg.resolveAPIKey(); err != nil {
			t.Fatalf("resolveAPIKey() error = %v", err)
		}
		if cfg.APIKey != "key-from-file" {
			t.Errorf("APIKey = %q, want key-from-file", cfg.APIKey)
		}
	})

	t.Run("env key wins over file", func(t *testing.T) {
		cfg := validUnifiConfig()
		cfg.APIKeyFile = writeKey(t, "key-from-file\n")

		if err := cfg.resolveAPIKey(); err != nil {
			t.Fatalf("resolveAPIKey() error = %v", err)
		}
		if cfg.APIKey != testKeyA {
			t.Errorf("APIKey = %q, want %q", cfg.APIKey, testKeyA)
		}
	})

	t.Run("no file configured leaves the key untouched", func(t *testing.T) {
		cfg := validUnifiConfig()
		cfg.APIKey = ""

		if err := cfg.resolveAPIKey(); err != nil {
			t.Fatalf("resolveAPIKey() error = %v", err)
		}
		if cfg.APIKey != "" {
			t.Errorf("APIKey = %q, want empty", cfg.APIKey)
		}
	})

	t.Run("unreadable file is an error", func(t *testing.T) {
		cfg := validUnifiConfig()
		cfg.APIKey = ""
		cfg.APIKeyFile = filepath.Join(t.TempDir(), "missing")

		if err := cfg.resolveAPIKey(); err == nil {
			t.Fatal("resolveAPIKey() error = nil, want an error")
		}
	})
}

func TestConfigBaseURL(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		consoleID string
		want      string
	}{
		{
			name: "local controller",
			host: "https://unifi.local",
			want: "https://unifi.local",
		},
		{
			name: "local controller trailing slash trimmed",
			host: "https://unifi.local/",
			want: "https://unifi.local",
		},
		{
			name:      "cloud connector",
			host:      "https://api.ui.com",
			consoleID: testConsoleID,
			want:      "https://api.ui.com/v1/connector/consoles/" + testConsoleID,
		},
		{
			name:      "cloud connector trailing slash trimmed",
			host:      "https://api.ui.com/",
			consoleID: testConsoleID,
			want:      "https://api.ui.com/v1/connector/consoles/" + testConsoleID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Host: tt.host, ConsoleID: tt.consoleID}
			if got := cfg.baseURL(); got != tt.want {
				t.Errorf("baseURL() = %q, want %q", got, tt.want)
			}
			if got := cfg.isCloud(); got != (tt.consoleID != "") {
				t.Errorf("isCloud() = %v, want %v", got, tt.consoleID != "")
			}
		})
	}
}
