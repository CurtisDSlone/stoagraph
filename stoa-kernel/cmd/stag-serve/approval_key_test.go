package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
)

// The multi-replica contract: when STAG_APPROVAL_KEY is set, every replica signs with that key and
// none of them writes a key file. Env beats file beats generate.

func TestLoadOrGenPrivEnvWinsAndWritesNothing(t *testing.T) {
	_, want, err := egress.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STAG_APPROVAL_KEY", string(bytes.TrimSpace(egress.MarshalPrivate(want))))

	path := filepath.Join(t.TempDir(), "approval.key")
	got, err := loadOrGenPriv(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatal("env key was not the one returned")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("env path must not touch disk; %s exists (err=%v)", path, err)
	}
}

func TestLoadOrGenPrivEnvBeatsFile(t *testing.T) {
	_, onDisk, err := egress.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "approval.key")
	if err := os.WriteFile(path, egress.MarshalPrivate(onDisk), 0o600); err != nil {
		t.Fatal(err)
	}

	_, fromEnv, err := egress.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STAG_APPROVAL_KEY", string(egress.MarshalPrivate(fromEnv)))

	got, err := loadOrGenPriv(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(fromEnv) || got.Equal(onDisk) {
		t.Fatal("env must take precedence over the file")
	}
}

func TestLoadOrGenPrivMalformedEnvFailsClosed(t *testing.T) {
	t.Setenv("STAG_APPROVAL_KEY", "not-a-key")
	if _, err := loadOrGenPriv(filepath.Join(t.TempDir(), "approval.key")); err == nil {
		t.Fatal("malformed STAG_APPROVAL_KEY must be an error, not a silent fallback to generate")
	}
}

func TestLoadOrGenPrivUnsetEnvStillGenerates(t *testing.T) {
	t.Setenv("STAG_APPROVAL_KEY", "")
	path := filepath.Join(t.TempDir(), "approval.key")
	first, err := loadOrGenPriv(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrGenPriv(path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Fatal("generated key must persist and reload identically (single-host default unchanged)")
	}
}
