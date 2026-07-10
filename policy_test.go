package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicyFile(t *testing.T, directory, body string) string {
	t.Helper()
	path := filepath.Join(directory, "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAndPrepareAuditPolicy(t *testing.T) {
	directory := t.TempDir()
	protected := filepath.Join(directory, "protected")
	if err := os.WriteFile(protected, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := writePolicyFile(t, directory, `
version: 1
policies:
  - id: 42
    name: protected_test_file
    mode: audit
    paths:
      - `+protected+`
    allowed_uids: [0, 1000, 1000]
    expires_after: 5m
`)

	config, err := loadPolicyConfig(configPath)
	if err != nil {
		t.Fatalf("loadPolicyConfig: %v", err)
	}
	prepared, names, err := preparePolicyEntries(config)
	if err != nil {
		t.Fatalf("preparePolicyEntries: %v", err)
	}
	if len(prepared.objects) != 1 {
		t.Fatalf("got %d objects, want 1", len(prepared.objects))
	}
	if prepared.objects[0].value.Mode != policyModeAudit {
		t.Fatalf("mode=%d, want audit", prepared.objects[0].value.Mode)
	}
	if prepared.objects[0].value.ExpiresAtNS == 0 {
		t.Fatal("expected a monotonic expiration")
	}
	if len(prepared.allowedUIDs) != 2 {
		t.Fatalf("got %d unique allowed UIDs, want 2", len(prepared.allowedUIDs))
	}
	if names[42] != "protected_test_file" {
		t.Fatalf("unexpected policy name %q", names[42])
	}
}

func TestKernelDeviceIDUsesKernelDevTEncoding(t *testing.T) {
	// Userspace stat encodes 8:3 as 0x803, while the kernel stores it as
	// major<<20|minor (0x800003).
	device, err := kernelDeviceID(0x803)
	if err != nil {
		t.Fatal(err)
	}
	if device != 0x800003 {
		t.Fatalf("kernel device=%#x, want %#x", device, uint64(0x800003))
	}
}

func TestRejectsInvalidPolicies(t *testing.T) {
	directory := t.TempDir()
	protected := filepath.Join(directory, "protected")
	if err := os.WriteFile(protected, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"unsupported version": "version: 2\npolicies: []\n",
		"invalid expiration": `
version: 1
policies:
  - id: 1
    name: bad
    mode: audit
    paths: [` + protected + `]
    expires_after: tomorrow
`,
		"duplicate ID": `
version: 1
policies:
  - {id: 1, name: one, mode: audit, paths: [` + protected + `]}
  - {id: 1, name: two, mode: audit, paths: [` + protected + `]}
`,
		"invalid mode": `
version: 1
policies:
  - {id: 1, name: bad, mode: block-everything, paths: [` + protected + `]}
`,
		"relative path": `
version: 1
policies:
  - {id: 1, name: bad, mode: audit, paths: [relative/file]}
`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			configPath := writePolicyFile(t, t.TempDir(), body)
			config, err := loadPolicyConfig(configPath)
			if err == nil {
				_, _, err = preparePolicyEntries(config)
			}
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSecurityEventBinaryLayoutAndDecode(t *testing.T) {
	if size := binary.Size(securityEvent{}); size != 88 {
		t.Fatalf("securityEvent size=%d, want 88", size)
	}
	rawEvent := securityEvent{
		TimestampNS: 123,
		PIDTGID:     uint64(55)<<32 | 77,
		CgroupID:    99,
		Inode:       101,
		Device:      202,
		UID:         1000,
		GID:         1001,
		Mask:        2,
		PolicyID:    42,
		Action:      actionDeny,
		Result:      -1,
		Operation:   operationUnlink,
	}
	copy(rawEvent.Comm[:], "writer")
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.LittleEndian, rawEvent); err != nil {
		t.Fatal(err)
	}

	decoded, err := decodeSecurityEvent(
		encoded.Bytes(),
		map[uint32]string{42: "protected_test_file"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PID != 77 || decoded.TGID != 55 {
		t.Fatalf("pid/tgid=%d/%d", decoded.PID, decoded.TGID)
	}
	if decoded.Action != "deny" || decoded.Result != -1 {
		t.Fatalf("action/result=%s/%d", decoded.Action, decoded.Result)
	}
	if decoded.Operation != "unlink" {
		t.Fatalf("operation=%q", decoded.Operation)
	}
	if decoded.PolicyName != "protected_test_file" {
		t.Fatalf("policy name=%q", decoded.PolicyName)
	}
	if strings.TrimSpace(decoded.Command) != "writer" {
		t.Fatalf("command=%q", decoded.Command)
	}
}

func TestDecodeRejectsWrongEventSize(t *testing.T) {
	_, err := decodeSecurityEvent([]byte{1, 2, 3}, nil)
	if err == nil {
		t.Fatal("expected event size error")
	}
}
