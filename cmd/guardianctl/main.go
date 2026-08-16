package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/melloa-project/melloa-guardian/internal/protocol"
	"github.com/melloa-project/melloa-guardian/internal/store"
)

var defaultPaths = store.Paths{
	StatusFile:     "/var/lib/melloa-guardian/status.json",
	AuditFile:      "/var/lib/melloa-guardian/audit.jsonl",
	PrivateKeyFile: "/etc/melloa-guardian/status-signing-key.pem",
	PublicKeyFile:  "/etc/melloa-guardian/status-signing-key.pub.pem",
	LockFile:       "/run/lock/melloa-guardian.lock",
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: guardianctl <init|status|transition> [options]")
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "transition":
		err = runTransition(os.Args[2:])
	default:
		fatal("unknown guardianctl command")
	}
	if err != nil {
		fatal(err.Error())
	}
}

func runInit(arguments []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	paths := addPathFlags(flags)
	instanceID := flags.String("instance-id", "", "stable Guardian installation ID")
	keyID := flags.String("key-id", "guardian.status-v1", "public status signing key ID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *instanceID == "" {
		return fmt.Errorf("--instance-id is required")
	}
	status, err := store.New(*paths).Init(*instanceID, *keyID)
	if err != nil {
		return err
	}
	return printStatus(status)
}

func runStatus(arguments []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	paths := addPathFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	status, err := store.New(*paths).Status()
	if err != nil {
		return err
	}
	return printStatus(status)
}

func runTransition(arguments []string) error {
	flags := flag.NewFlagSet("transition", flag.ContinueOnError)
	paths := addPathFlags(flags)
	modeValue := flags.String("mode", "", "target Guardian mode")
	reason := flags.String("reason", "", "auditable qualified reason code")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	mode, err := protocol.ParseMode(*modeValue)
	if err != nil {
		return err
	}
	if *reason == "" {
		return fmt.Errorf("--reason is required")
	}
	status, err := store.New(*paths).Transition(mode, *reason)
	if err != nil {
		return err
	}
	return printStatus(status)
}

func addPathFlags(flags *flag.FlagSet) *store.Paths {
	paths := defaultPaths
	flags.StringVar(&paths.StatusFile, "status-file", paths.StatusFile, "signed status projection")
	flags.StringVar(&paths.AuditFile, "audit-file", paths.AuditFile, "append-only receipt journal")
	flags.StringVar(&paths.PrivateKeyFile, "private-key-file", paths.PrivateKeyFile, "owner-controlled private key")
	flags.StringVar(&paths.PublicKeyFile, "public-key-file", paths.PublicKeyFile, "status verification key")
	flags.StringVar(&paths.LockFile, "lock-file", paths.LockFile, "transition lock file")
	return &paths
}

func printStatus(status protocol.VerifiedStatus) error {
	view := struct {
		ProtocolVersion string        `json:"protocol_version"`
		InstanceID      string        `json:"instance_id"`
		Mode            protocol.Mode `json:"mode"`
		Sequence        uint64        `json:"sequence"`
		ChangedAt       string        `json:"changed_at"`
		ReasonCode      string        `json:"reason_code"`
		ReceiptHash     string        `json:"receipt_hash"`
		KeyID           string        `json:"key_id"`
	}{
		ProtocolVersion: status.Payload.ProtocolVersion,
		InstanceID:      status.Payload.InstanceID,
		Mode:            status.Payload.Mode,
		Sequence:        status.Payload.Sequence,
		ChangedAt:       status.Payload.ChangedAt,
		ReasonCode:      status.Payload.ReasonCode,
		ReceiptHash:     status.ReceiptHash,
		KeyID:           status.Envelope.KeyID,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(view)
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
