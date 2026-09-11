package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestGeneratedObjectIncludesMemoryProtection(t *testing.T) {
	spec, err := loadLsmbpf()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"handle_mmap_file", "handle_file_mprotect"} {
		if spec.Programs[name] == nil {
			t.Errorf("missing BPF program %s; run go generate", name)
		}
	}
}

func TestStrictPolicyInput(t *testing.T) {
	directory := t.TempDir()
	for _, body := range []string{
		"version: 1\npoliciez: []\n",
		"version: 1\npolicies: []\n---\nversion: 1\n",
		"version: 1\npolicies:\n  - {id: 1, name: test, mode: audit, paths: [/tmp/test], allowed_uid: [0]}\n",
	} {
		if _, err := loadPolicyConfig(writePolicyFile(t, directory, body)); err == nil {
			t.Errorf("accepted invalid YAML: %s", body)
		}
	}
	_, _, err := preparePolicyEntries(policyConfig{Version: 1, Policies: []configuredPolicy{
		{ID: 1, Name: "directory", Mode: "enforce", Paths: []string{directory}},
	}})
	if err == nil {
		t.Fatal("accepted directory as a protected file")
	}
}

// Run only in a disposable Linux VM with BPF LSM enabled. All policy objects
// belong to this test's temporary directory; no host configuration is changed.
func TestBPFEnforceIntegration(t *testing.T) {
	if os.Getenv("BPF_LSM_INTEGRATION") != "1" {
		t.Skip("requires explicit BPF_LSM_INTEGRATION=1 in a BPF LSM test VM")
	}
	path := filepath.Join(t.TempDir(), "protected")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(4096); err != nil {
		t.Fatal(err)
	}
	before, err := unix.Mmap(int(file.Fd()), 0, 4096, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(before)
	permittedPolicies := []configuredPolicy{
		{ID: 43, Name: "audit", Mode: "audit"},
		{ID: 44, Name: "allowed_uid", Mode: "enforce", AllowedUIDs: []uint32{uint32(os.Getuid())}},
	}
	for i := range permittedPolicies {
		policy := &permittedPolicies[i]
		policy.Paths = []string{filepath.Join(filepath.Dir(path), policy.Name)}
		if err := os.WriteFile(policy.Paths[0], make([]byte, 4096), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var objects lsmbpfObjects
	if err := loadLsmbpfObjects(&objects, nil); err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	policies := append([]configuredPolicy{
		{ID: 42, Name: "integration", Mode: "enforce", Paths: []string{path}},
	}, permittedPolicies...)
	prepared, _, err := preparePolicyEntries(policyConfig{Version: 1, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	if err := populatePolicyMaps(&objects, prepared); err != nil {
		t.Fatal(err)
	}
	links, err := attachLSMPrograms(&objects)
	if err != nil {
		t.Fatal(err)
	}
	defer closeLinks(links)

	expectDenied := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, unix.EPERM) {
			t.Errorf("%s: got %v, want EPERM", name, err)
		}
	}
	_, err = file.Write([]byte("blocked"))
	expectDenied("write", err)
	for _, flags := range []int{unix.MAP_SHARED, unix.MAP_SHARED_VALIDATE} {
		mapped, err := unix.Mmap(int(file.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, flags)
		if err == nil {
			unix.Munmap(mapped)
		}
		expectDenied("shared mmap", err)
	}
	expectDenied("mprotect upgrade", unix.Mprotect(before, unix.PROT_READ|unix.PROT_WRITE))
	expectDenied("truncate", file.Truncate(0))
	expectDenied("unlink", os.Remove(path))
	expectDenied("rename", os.Rename(path, path+".renamed"))
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, []byte("unrelated"), 0600); err != nil {
		t.Fatalf("unprotected file should remain writable: %v", err)
	}
	expectDenied("rename over protected target", os.Rename(replacement, path))
	private, err := unix.Mmap(int(file.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("private copy-on-write mapping should be allowed: %v", err)
	}
	private[0] = 42
	unix.Munmap(private)
	var unchanged [1]byte
	if _, err := file.ReadAt(unchanged[:], 0); err != nil || unchanged[0] != 0 {
		t.Fatalf("private mapping changed protected file: byte=%d err=%v", unchanged[0], err)
	}

	for _, policy := range permittedPolicies {
		t.Run(policy.Name, func(t *testing.T) {
			file, err := os.OpenFile(policy.Paths[0], os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := file.Write([]byte("allowed")); err != nil {
				t.Fatalf("write should be allowed: %v", err)
			}
			for _, flags := range []int{unix.MAP_SHARED, unix.MAP_SHARED_VALIDATE} {
				mapped, err := unix.Mmap(int(file.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, flags)
				if err != nil {
					t.Fatalf("shared mmap should be allowed: %v", err)
				}
				mapped[0] = 1
				unix.Munmap(mapped)
			}
			mapped, err := unix.Mmap(int(file.Fd()), 0, 4096, unix.PROT_READ, unix.MAP_SHARED)
			if err != nil {
				t.Fatal(err)
			}
			err = unix.Mprotect(mapped, unix.PROT_READ|unix.PROT_WRITE)
			unix.Munmap(mapped)
			if err != nil {
				t.Fatalf("mprotect should be allowed: %v", err)
			}
			if err := file.Truncate(0); err != nil {
				t.Fatalf("truncate should be allowed: %v", err)
			}
			renamed := policy.Paths[0] + ".renamed"
			if err := os.Rename(policy.Paths[0], renamed); err != nil {
				t.Fatalf("rename should be allowed: %v", err)
			}
			if err := os.Remove(renamed); err != nil {
				t.Fatalf("unlink should be allowed: %v", err)
			}
		})
	}
}
