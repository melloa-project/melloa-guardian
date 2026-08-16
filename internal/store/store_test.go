package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melloa-project/melloa-guardian/internal/protocol"
)

func testPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	return Paths{
		StatusFile:     filepath.Join(root, "state", "status.json"),
		AuditFile:      filepath.Join(root, "state", "audit.jsonl"),
		PrivateKeyFile: filepath.Join(root, "keys", "private.pem"),
		PublicKeyFile:  filepath.Join(root, "keys", "public.pem"),
		LockFile:       filepath.Join(root, "run", "guardian.lock"),
	}
}

func TestInitTransitionAndAuditChain(t *testing.T) {
	paths := testPaths(t)
	guardian := New(paths)
	initial, err := guardian.Init("home-guardian", "guardian.status-v1")
	if err != nil {
		t.Fatal(err)
	}
	if initial.Payload.Mode != protocol.ModeStopped || initial.Payload.Sequence != 1 {
		t.Fatalf("unexpected initial status: %+v", initial.Payload)
	}
	offline, err := guardian.Transition(protocol.ModeOffline, "owner.start_local")
	if err != nil {
		t.Fatal(err)
	}
	if offline.Payload.PreviousReceiptHash != initial.ReceiptHash {
		t.Fatal("transition did not chain to the prior receipt")
	}
	audit, err := os.ReadFile(paths.AuditFile)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(strings.TrimSpace(string(audit)), "\n") + 1; lines != 2 {
		t.Fatalf("expected two audit receipts, got %d", lines)
	}
}

func TestStatusReconcilesProjectionFromAudit(t *testing.T) {
	paths := testPaths(t)
	guardian := New(paths)
	initial, err := guardian.Init("home-guardian", "guardian.status-v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.StatusFile, []byte("corrupt"), 0o640); err != nil {
		t.Fatal(err)
	}
	reconciled, err := guardian.Status()
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.ReceiptHash != initial.ReceiptHash {
		t.Fatal("status was not recovered from the append-only journal")
	}
}

func TestPrivateKeyPermissionsFailClosed(t *testing.T) {
	paths := testPaths(t)
	guardian := New(paths)
	if _, err := guardian.Init("home-guardian", "guardian.status-v1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.PrivateKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := guardian.Transition(protocol.ModeOffline, "owner.start_local"); err == nil {
		t.Fatal("transition accepted an overexposed private key")
	}
}

func TestAuditChainCannotDropGenesisReceipt(t *testing.T) {
	paths := testPaths(t)
	guardian := New(paths)
	if _, err := guardian.Init("home-guardian", "guardian.status-v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := guardian.Transition(protocol.ModeOffline, "owner.start_local"); err != nil {
		t.Fatal(err)
	}
	document, err := os.ReadFile(paths.AuditFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(document)), "\n")
	if err := os.WriteFile(paths.AuditFile, []byte(lines[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := guardian.Status(); err == nil {
		t.Fatal("Guardian accepted an audit journal with its genesis receipt removed")
	}
}
