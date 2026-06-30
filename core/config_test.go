package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConfigAtomicWrite verifies that config mutations are persisted as valid,
// non-truncated JSON and that the atomic temp-file path actually runs (no
// leftover temp files).
func TestConfigAtomicWrite(t *testing.T) {
	dir := t.TempDir()

	cfg, err := NewConfig(dir, "")
	if err != nil {
		t.Fatalf("NewConfig failed: %v", err)
	}

	cfg.SetBlacklistMode("all")

	path := filepath.Join(dir, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading config.json failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("config.json is not valid JSON: %v\ncontent: %s", err, data)
	}

	bl, ok := parsed["blacklist"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected 'blacklist' object in config, got: %v", parsed["blacklist"])
	}
	if bl["mode"] != "all" {
		t.Errorf("expected blacklist.mode == \"all\", got: %v", bl["mode"])
	}

	// The atomic write renames the temp file over config.json; none should remain.
	leftovers, err := filepath.Glob(filepath.Join(dir, "config-*.json"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(leftovers) != 0 {
		t.Errorf("expected no leftover temp files, found: %v", leftovers)
	}
}
