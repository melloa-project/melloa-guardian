package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	ProtocolVersion = "1.0.0"
	EnvelopeVersion = "1.0.0"
	Algorithm       = "Ed25519"
)

var (
	signingDomain = []byte("MELLOA-GUARDIAN-STATUS-V1\x00")
	receiptDomain = []byte("MELLOA-GUARDIAN-RECEIPT-V1\x00")
	instanceID    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,63}$`)
	qualifiedName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Mode string

const (
	ModeNormal    Mode = "normal"
	ModeNoActions Mode = "no-actions"
	ModeReadOnly  Mode = "read-only"
	ModeOffline   Mode = "offline"
	ModeStopped   Mode = "stopped"
	ModeRecovery  Mode = "recovery"
)

type StatusPayload struct {
	ProtocolVersion     string `json:"protocol_version"`
	InstanceID          string `json:"instance_id"`
	Mode                Mode   `json:"mode"`
	Sequence            uint64 `json:"sequence"`
	ChangedAt           string `json:"changed_at"`
	ReasonCode          string `json:"reason_code"`
	PreviousReceiptHash string `json:"previous_receipt_hash,omitempty"`
}

type SignedStatus struct {
	EnvelopeVersion string `json:"envelope_version"`
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	Payload         string `json:"payload"`
	Signature       string `json:"signature"`
}

type VerifiedStatus struct {
	Envelope    SignedStatus
	Payload     StatusPayload
	PayloadRaw  []byte
	Signature   []byte
	ReceiptHash string
}

func ParseMode(value string) (Mode, error) {
	mode := Mode(value)
	switch mode {
	case ModeNormal, ModeNoActions, ModeReadOnly, ModeOffline, ModeStopped, ModeRecovery:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported Guardian mode: %s", value)
	}
}

func ValidatePayload(payload StatusPayload) error {
	if payload.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version: %s", payload.ProtocolVersion)
	}
	if !instanceID.MatchString(payload.InstanceID) {
		return errors.New("invalid Guardian instance ID")
	}
	if _, err := ParseMode(string(payload.Mode)); err != nil {
		return err
	}
	if payload.Sequence == 0 {
		return errors.New("Guardian sequence must be positive")
	}
	changedAt, err := time.Parse(time.RFC3339Nano, payload.ChangedAt)
	if err != nil || changedAt.Location() != time.UTC {
		return errors.New("changed_at must be an RFC3339 UTC timestamp")
	}
	if !qualifiedName.MatchString(payload.ReasonCode) {
		return errors.New("invalid Guardian reason code")
	}
	if payload.Sequence == 1 && payload.PreviousReceiptHash != "" {
		return errors.New("initial Guardian status cannot have a predecessor")
	}
	if payload.Sequence > 1 && !digestPattern.MatchString(payload.PreviousReceiptHash) {
		return errors.New("later Guardian status requires a predecessor digest")
	}
	return nil
}

func ValidateKeyID(keyID string) error {
	if !qualifiedName.MatchString(keyID) {
		return errors.New("invalid Guardian key ID")
	}
	return nil
}

func Sign(privateKey ed25519.PrivateKey, keyID string, payload StatusPayload) ([]byte, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return nil, err
	}
	if err := ValidatePayload(payload); err != nil {
		return nil, err
	}
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode Guardian payload: %w", err)
	}
	message := append(append([]byte{}, signingDomain...), payloadRaw...)
	signature := ed25519.Sign(privateKey, message)
	envelope := SignedStatus{
		EnvelopeVersion: EnvelopeVersion,
		Algorithm:       Algorithm,
		KeyID:           keyID,
		Payload:         base64.RawURLEncoding.EncodeToString(payloadRaw),
		Signature:       base64.RawURLEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode Guardian envelope: %w", err)
	}
	return encoded, nil
}

func Verify(publicKey ed25519.PublicKey, document []byte) (VerifiedStatus, error) {
	var envelope SignedStatus
	if err := json.Unmarshal(document, &envelope); err != nil {
		return VerifiedStatus{}, fmt.Errorf("decode Guardian envelope: %w", err)
	}
	if envelope.EnvelopeVersion != EnvelopeVersion || envelope.Algorithm != Algorithm {
		return VerifiedStatus{}, errors.New("unsupported Guardian envelope")
	}
	if err := ValidateKeyID(envelope.KeyID); err != nil {
		return VerifiedStatus{}, err
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return VerifiedStatus{}, errors.New("invalid Guardian payload encoding")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return VerifiedStatus{}, errors.New("invalid Guardian signature encoding")
	}
	message := append(append([]byte{}, signingDomain...), payloadRaw...)
	if !ed25519.Verify(publicKey, message, signature) {
		return VerifiedStatus{}, errors.New("invalid Guardian signature")
	}
	var payload StatusPayload
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return VerifiedStatus{}, fmt.Errorf("decode Guardian payload: %w", err)
	}
	if err := ValidatePayload(payload); err != nil {
		return VerifiedStatus{}, err
	}
	return VerifiedStatus{
		Envelope:    envelope,
		Payload:     payload,
		PayloadRaw:  payloadRaw,
		Signature:   signature,
		ReceiptHash: ReceiptHash(payloadRaw, signature, envelope.KeyID),
	}, nil
}

func ReceiptHash(payloadRaw, signature []byte, keyID string) string {
	material := make([]byte, 0, len(receiptDomain)+len(payloadRaw)+len(signature)+len(keyID)+2)
	material = append(material, receiptDomain...)
	material = append(material, payloadRaw...)
	material = append(material, 0)
	material = append(material, signature...)
	material = append(material, 0)
	material = append(material, keyID...)
	digest := sha256.Sum256(material)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TransitionAllowed(from, to Mode) bool {
	allowed := map[Mode]map[Mode]bool{
		ModeStopped: {
			ModeOffline:  true,
			ModeRecovery: true,
		},
		ModeOffline: {
			ModeReadOnly: true,
			ModeStopped:  true,
		},
		ModeReadOnly: {
			ModeNoActions: true,
			ModeStopped:   true,
		},
		ModeNoActions: {
			ModeNormal:   true,
			ModeReadOnly: true,
			ModeOffline:  true,
			ModeStopped:  true,
		},
		ModeNormal: {
			ModeNoActions: true,
			ModeOffline:   true,
			ModeStopped:   true,
		},
		ModeRecovery: {
			ModeStopped: true,
		},
	}
	return allowed[from][to]
}
