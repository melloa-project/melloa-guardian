package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignVerifyAndTamper(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := StatusPayload{
		ProtocolVersion: ProtocolVersion,
		InstanceID:      "home-guardian",
		Mode:            ModeStopped,
		Sequence:        1,
		ChangedAt:       "2026-08-16T00:00:00Z",
		ReasonCode:      "guardian.initialized",
	}
	document, err := Sign(privateKey, "guardian.status-v1", payload)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(publicKey, document)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Payload.Mode != ModeStopped {
		t.Fatalf("unexpected mode: %s", verified.Payload.Mode)
	}
	document[len(document)-2] ^= 1
	if _, err := Verify(publicKey, document); err == nil {
		t.Fatal("tampered envelope verified")
	}
}

func TestTransitionGraphRequiresRecoveryExitThroughStopped(t *testing.T) {
	if TransitionAllowed(ModeRecovery, ModeNormal) {
		t.Fatal("recovery must not transition directly to normal")
	}
	if !TransitionAllowed(ModeRecovery, ModeStopped) {
		t.Fatal("recovery must be able to return to stopped")
	}
	if TransitionAllowed(ModeStopped, ModeNormal) {
		t.Fatal("stopped must start through progressively constrained modes")
	}
}
