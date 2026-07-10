package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	policyModeAudit   uint32 = 1
	policyModeEnforce uint32 = 2

	actionAudit uint32 = 1
	actionDeny  uint32 = 2

	operationWrite        uint32 = 1
	operationUnlink       uint32 = 2
	operationRenameSource uint32 = 3
	operationRenameTarget uint32 = 4
	operationSetattr      uint32 = 5
)

type policyConfig struct {
	Version     int                `yaml:"version"`
	Diagnostics bool               `yaml:"diagnostics"`
	Policies    []configuredPolicy `yaml:"policies"`
}

type configuredPolicy struct {
	ID           uint32        `yaml:"id"`
	Name         string        `yaml:"name"`
	Mode         string        `yaml:"mode"`
	Paths        []string      `yaml:"paths"`
	AllowedUIDs  []uint32      `yaml:"allowed_uids"`
	ExpiresAfter time.Duration `yaml:"-"`
	ExpiresRaw   string        `yaml:"expires_after"`
}

type objectKey struct {
	Device uint64
	Inode  uint64
}

type policyValue struct {
	PolicyID    uint32
	Mode        uint32
	ExpiresAtNS uint64
}

type allowedUIDKey struct {
	PolicyID uint32
	UID      uint32
}

type controllerSettings struct {
	DiagnosticsEnabled uint32
}

type securityEvent struct {
	TimestampNS uint64
	PIDTGID     uint64
	CgroupID    uint64
	Inode       uint64
	Device      uint64
	UID         uint32
	GID         uint32
	Mask        uint32
	PolicyID    uint32
	Action      uint32
	Result      int32
	Operation   uint32
	Reserved    uint32
	Comm        [16]byte
}

type preparedObject struct {
	key   objectKey
	value policyValue
	path  string
}

type preparedPolicies struct {
	objects     []preparedObject
	allowedUIDs []allowedUIDKey
}

func loadPolicyConfig(path string) (policyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policyConfig{}, err
	}
	var config policyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return policyConfig{}, err
	}
	if config.Version != 1 {
		return policyConfig{}, fmt.Errorf("unsupported policy version %d", config.Version)
	}
	for index := range config.Policies {
		raw := strings.TrimSpace(config.Policies[index].ExpiresRaw)
		if raw == "" {
			continue
		}
		duration, err := time.ParseDuration(raw)
		if err != nil || duration <= 0 {
			return policyConfig{}, fmt.Errorf(
				"policy %q has invalid expires_after %q",
				config.Policies[index].Name,
				raw,
			)
		}
		config.Policies[index].ExpiresAfter = duration
	}
	return config, nil
}

func monotonicNowNS() (uint64, error) {
	var current unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &current); err != nil {
		return 0, err
	}
	return uint64(current.Sec)*1_000_000_000 + uint64(current.Nsec), nil
}

func kernelDeviceID(userspaceDevice uint64) (uint64, error) {
	major := uint64(unix.Major(userspaceDevice))
	minor := uint64(unix.Minor(userspaceDevice))
	if major >= 1<<12 || minor >= 1<<20 {
		return 0, fmt.Errorf(
			"device major/minor out of Linux dev_t range: %d:%d",
			major,
			minor,
		)
	}
	// The kernel's dev_t uses 12 major bits followed by 20 minor bits.
	// glibc's st_dev uses a different userspace encoding, so stat.Dev cannot
	// be compared directly with super_block.s_dev in BPF.
	return major<<20 | minor, nil
}

func preparePolicyEntries(
	config policyConfig,
) (preparedPolicies, map[uint32]string, error) {
	now, err := monotonicNowNS()
	if err != nil {
		return preparedPolicies{}, nil, err
	}

	var prepared preparedPolicies
	names := make(map[uint32]string)
	objects := make(map[objectKey]uint32)
	allowed := make(map[allowedUIDKey]struct{})

	for _, policy := range config.Policies {
		if policy.ID == 0 {
			return preparedPolicies{}, nil, fmt.Errorf("policy ID 0 is reserved")
		}
		if strings.TrimSpace(policy.Name) == "" {
			return preparedPolicies{}, nil, fmt.Errorf("policy %d has no name", policy.ID)
		}
		if _, exists := names[policy.ID]; exists {
			return preparedPolicies{}, nil, fmt.Errorf("duplicate policy ID %d", policy.ID)
		}
		if len(policy.Paths) == 0 {
			return preparedPolicies{}, nil, fmt.Errorf("policy %q has no paths", policy.Name)
		}

		var mode uint32
		switch strings.ToLower(strings.TrimSpace(policy.Mode)) {
		case "audit":
			mode = policyModeAudit
		case "enforce":
			mode = policyModeEnforce
		default:
			return preparedPolicies{}, nil, fmt.Errorf(
				"policy %q has invalid mode %q",
				policy.Name,
				policy.Mode,
			)
		}

		var expiresAt uint64
		if policy.ExpiresAfter > 0 {
			expiresAt = now + uint64(policy.ExpiresAfter)
			if expiresAt < now {
				return preparedPolicies{}, nil, fmt.Errorf(
					"policy %q expiration overflows monotonic time",
					policy.Name,
				)
			}
		}

		names[policy.ID] = policy.Name
		for _, configuredPath := range policy.Paths {
			cleanPath := filepath.Clean(configuredPath)
			if !filepath.IsAbs(cleanPath) {
				return preparedPolicies{}, nil, fmt.Errorf(
					"policy %q path must be absolute: %s",
					policy.Name,
					configuredPath,
				)
			}
			info, err := os.Stat(cleanPath)
			if err != nil {
				return preparedPolicies{}, nil, fmt.Errorf(
					"stat policy %q path %s: %w",
					policy.Name,
					cleanPath,
					err,
				)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return preparedPolicies{}, nil, fmt.Errorf(
					"unsupported stat data for %s",
					cleanPath,
				)
			}
			device, err := kernelDeviceID(uint64(stat.Dev))
			if err != nil {
				return preparedPolicies{}, nil, fmt.Errorf(
					"encode policy %q device for %s: %w",
					policy.Name,
					cleanPath,
					err,
				)
			}
			key := objectKey{Device: device, Inode: stat.Ino}
			if existing, exists := objects[key]; exists && existing != policy.ID {
				return preparedPolicies{}, nil, fmt.Errorf(
					"object %s is assigned to policies %d and %d",
					cleanPath,
					existing,
					policy.ID,
				)
			}
			objects[key] = policy.ID
			prepared.objects = append(prepared.objects, preparedObject{
				key: key,
				value: policyValue{
					PolicyID:    policy.ID,
					Mode:        mode,
					ExpiresAtNS: expiresAt,
				},
				path: cleanPath,
			})
		}

		for _, uid := range policy.AllowedUIDs {
			key := allowedUIDKey{PolicyID: policy.ID, UID: uid}
			if _, exists := allowed[key]; !exists {
				allowed[key] = struct{}{}
				prepared.allowedUIDs = append(prepared.allowedUIDs, key)
			}
		}
	}
	return prepared, names, nil
}

func populatePolicyMaps(objects *lsmbpfObjects, entries preparedPolicies) error {
	for _, object := range entries.objects {
		if err := objects.ProtectedObjects.Put(object.key, object.value); err != nil {
			return fmt.Errorf("protect %s: %w", object.path, err)
		}
	}
	enabled := uint8(1)
	for _, key := range entries.allowedUIDs {
		if err := objects.AllowedUids.Put(key, enabled); err != nil {
			return fmt.Errorf(
				"allow uid %d for policy %d: %w",
				key.UID,
				key.PolicyID,
				err,
			)
		}
	}
	return nil
}

func populateControllerSettings(objects *lsmbpfObjects, diagnostics bool) error {
	key := uint32(0)
	var enabled uint32
	if diagnostics {
		enabled = 1
	}
	if err := objects.Settings.Put(key, controllerSettings{
		DiagnosticsEnabled: enabled,
	}); err != nil {
		return fmt.Errorf("set controller diagnostics=%t: %w", diagnostics, err)
	}
	return nil
}
