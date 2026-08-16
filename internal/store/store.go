package store

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/melloa-project/melloa-guardian/internal/protocol"
)

const maximumDocumentSize = 16 * 1024

type Paths struct {
	StatusFile     string
	AuditFile      string
	PrivateKeyFile string
	PublicKeyFile  string
	LockFile       string
}

type Store struct {
	paths Paths
	now   func() time.Time
}

func New(paths Paths) *Store {
	return &Store{paths: paths, now: time.Now}
}

func (s *Store) Init(instanceID, keyID string) (protocol.VerifiedStatus, error) {
	var result protocol.VerifiedStatus
	err := s.withLock(func() error {
		for _, path := range []string{
			s.paths.StatusFile,
			s.paths.AuditFile,
			s.paths.PrivateKeyFile,
			s.paths.PublicKeyFile,
		} {
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("refusing to replace existing Guardian state: %s", path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("inspect Guardian path %s: %w", path, err)
			}
		}

		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate Guardian signing key: %w", err)
		}
		privateDocument, err := marshalPrivateKey(privateKey)
		if err != nil {
			return err
		}
		publicDocument, err := marshalPublicKey(publicKey)
		if err != nil {
			return err
		}
		if err := writeAtomic(s.paths.PrivateKeyFile, privateDocument, 0o600); err != nil {
			return err
		}
		if err := writeAtomic(s.paths.PublicKeyFile, publicDocument, 0o644); err != nil {
			return err
		}

		payload := protocol.StatusPayload{
			ProtocolVersion: protocol.ProtocolVersion,
			InstanceID:      instanceID,
			Mode:            protocol.ModeStopped,
			Sequence:        1,
			ChangedAt:       s.now().UTC().Format(time.RFC3339Nano),
			ReasonCode:      "guardian.initialized",
		}
		document, err := protocol.Sign(privateKey, keyID, payload)
		if err != nil {
			return err
		}
		result, err = protocol.Verify(publicKey, document)
		if err != nil {
			return err
		}
		if err := appendAudit(s.paths.AuditFile, document); err != nil {
			return err
		}
		return writeAtomic(s.paths.StatusFile, append(document, '\n'), 0o640)
	})
	return result, err
}

func (s *Store) Status() (protocol.VerifiedStatus, error) {
	var status protocol.VerifiedStatus
	err := s.withLock(func() error {
		publicKey, err := readPublicKey(s.paths.PublicKeyFile)
		if err != nil {
			return err
		}
		status, err = s.reconcile(publicKey)
		return err
	})
	return status, err
}

func (s *Store) Transition(mode protocol.Mode, reasonCode string) (protocol.VerifiedStatus, error) {
	var result protocol.VerifiedStatus
	err := s.withLock(func() error {
		publicKey, err := readPublicKey(s.paths.PublicKeyFile)
		if err != nil {
			return err
		}
		current, err := s.reconcile(publicKey)
		if err != nil {
			return err
		}
		if !protocol.TransitionAllowed(current.Payload.Mode, mode) {
			return fmt.Errorf("Guardian transition is not allowed: %s -> %s", current.Payload.Mode, mode)
		}
		privateKey, err := readPrivateKey(s.paths.PrivateKeyFile)
		if err != nil {
			return err
		}
		payload := protocol.StatusPayload{
			ProtocolVersion:     protocol.ProtocolVersion,
			InstanceID:          current.Payload.InstanceID,
			Mode:                mode,
			Sequence:            current.Payload.Sequence + 1,
			ChangedAt:           s.now().UTC().Format(time.RFC3339Nano),
			ReasonCode:          reasonCode,
			PreviousReceiptHash: current.ReceiptHash,
		}
		document, err := protocol.Sign(privateKey, current.Envelope.KeyID, payload)
		if err != nil {
			return err
		}
		result, err = protocol.Verify(publicKey, document)
		if err != nil {
			return err
		}
		if err := appendAudit(s.paths.AuditFile, document); err != nil {
			return err
		}
		return writeAtomic(s.paths.StatusFile, append(document, '\n'), 0o640)
	})
	return result, err
}

func (s *Store) reconcile(publicKey ed25519.PublicKey) (protocol.VerifiedStatus, error) {
	latestDocument, latest, err := auditHead(s.paths.AuditFile, publicKey)
	if err != nil {
		return protocol.VerifiedStatus{}, err
	}
	statusDocument, err := readRegularFile(s.paths.StatusFile, maximumDocumentSize, false)
	if err == nil {
		projected, verifyErr := protocol.Verify(publicKey, statusDocument)
		if verifyErr == nil && projected.ReceiptHash == latest.ReceiptHash {
			return latest, nil
		}
	}
	if err := writeAtomic(s.paths.StatusFile, append(latestDocument, '\n'), 0o640); err != nil {
		return protocol.VerifiedStatus{}, fmt.Errorf("reconcile Guardian status projection: %w", err)
	}
	return latest, nil
}

func (s *Store) withLock(operation func() error) error {
	if err := os.MkdirAll(filepath.Dir(s.paths.LockFile), 0o700); err != nil {
		return fmt.Errorf("create Guardian lock directory: %w", err)
	}
	lock, err := os.OpenFile(s.paths.LockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open Guardian lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock Guardian state: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return operation()
}

func appendAudit(path string, document []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create Guardian audit directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open Guardian audit: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(document, '\n')); err != nil {
		return fmt.Errorf("append Guardian audit: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync Guardian audit: %w", err)
	}
	return nil
}

func auditHead(path string, publicKey ed25519.PublicKey) ([]byte, protocol.VerifiedStatus, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, protocol.VerifiedStatus{}, fmt.Errorf("open Guardian audit: %w", err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var last []byte
	var previous protocol.VerifiedStatus
	recordCount := uint64(0)
	for {
		line, readErr := reader.ReadBytes('\n')
		line = []byte(strings.TrimSpace(string(line)))
		if len(line) > 0 {
			if len(line) > maximumDocumentSize {
				return nil, protocol.VerifiedStatus{}, errors.New("Guardian audit record exceeds size limit")
			}
			verified, verifyErr := protocol.Verify(publicKey, line)
			if verifyErr != nil {
				return nil, protocol.VerifiedStatus{}, fmt.Errorf(
					"verify Guardian audit record %d: %w",
					recordCount+1,
					verifyErr,
				)
			}
			if recordCount == 0 {
				if verified.Payload.Sequence != 1 {
					return nil, protocol.VerifiedStatus{}, errors.New("Guardian audit must begin at sequence 1")
				}
			} else {
				if verified.Payload.Sequence != previous.Payload.Sequence+1 {
					return nil, protocol.VerifiedStatus{}, errors.New("Guardian audit sequence is not contiguous")
				}
				if verified.Payload.PreviousReceiptHash != previous.ReceiptHash {
					return nil, protocol.VerifiedStatus{}, errors.New("Guardian audit receipt chain is broken")
				}
				if verified.Payload.InstanceID != previous.Payload.InstanceID ||
					verified.Envelope.KeyID != previous.Envelope.KeyID {
					return nil, protocol.VerifiedStatus{}, errors.New("Guardian audit identity changed")
				}
			}
			previous = verified
			recordCount++
			last = append(last[:0], line...)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, protocol.VerifiedStatus{}, fmt.Errorf("read Guardian audit: %w", readErr)
		}
	}
	if len(last) == 0 {
		return nil, protocol.VerifiedStatus{}, errors.New("Guardian audit contains no status receipts")
	}
	return last, previous, nil
}

func readRegularFile(path string, maximumSize int64, requirePrivate bool) ([]byte, error) {
	metadata, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !metadata.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular Guardian file: %s", path)
	}
	if requirePrivate && metadata.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("Guardian private key permissions are too broad: %s", path)
	}
	if metadata.Size() > maximumSize {
		return nil, fmt.Errorf("Guardian file exceeds size limit: %s", path)
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return []byte(strings.TrimSpace(string(document))), nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	document, err := readRegularFile(path, 4096, true)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(document)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid Guardian private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Guardian private key: %w", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Guardian private key must be Ed25519")
	}
	return privateKey, nil
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	document, err := readRegularFile(path, 4096, false)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(document)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid Guardian public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Guardian public key: %w", err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Guardian public key must be Ed25519")
	}
	return publicKey, nil
}

func marshalPrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal Guardian private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func marshalPublicKey(key ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal Guardian public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func writeAtomic(path string, document []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create Guardian directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".guardian-*")
	if err != nil {
		return fmt.Errorf("create temporary Guardian file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return fmt.Errorf("set Guardian file permissions: %w", err)
	}
	if _, err := temporary.Write(document); err != nil {
		temporary.Close()
		return fmt.Errorf("write Guardian file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync Guardian file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Guardian file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace Guardian file: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open Guardian directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Guardian directory: %w", err)
	}
	return nil
}
