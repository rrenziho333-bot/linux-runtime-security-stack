//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 lsmbpf bpf/lsm_block_write.c -- -I bpf -I/usr/include

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type outputEvent struct {
	ReceivedTime         string `json:"received_time"`
	Source               string `json:"source"`
	PolicyID             uint32 `json:"policy_id"`
	PolicyName           string `json:"policy_name"`
	Action               string `json:"action"`
	Operation            string `json:"operation"`
	Result               int32  `json:"result"`
	PID                  uint32 `json:"pid"`
	TGID                 uint32 `json:"tgid"`
	UID                  uint32 `json:"uid"`
	GID                  uint32 `json:"gid"`
	CgroupID             uint64 `json:"cgroup_id"`
	Device               uint64 `json:"device"`
	Inode                uint64 `json:"inode"`
	Mask                 uint32 `json:"mask"`
	Command              string `json:"command"`
	MonotonicTimestampNS uint64 `json:"monotonic_timestamp_ns"`
}

func main() {
	configPath := flag.String("config", "policy.yaml", "path to the BPF LSM policy YAML")
	outputPath := flag.String("output", "-", "JSONL event output path, or - for stdout")
	checkOnly := flag.Bool("check", false, "validate and resolve policies without loading BPF")
	flag.Parse()

	if err := run(*configPath, *outputPath, *checkOnly); err != nil {
		log.Fatal(err)
	}
}

func run(configPath, outputPath string, checkOnly bool) error {
	config, err := loadPolicyConfig(configPath)
	if err != nil {
		return fmt.Errorf("load policy config: %w", err)
	}
	entries, policyNames, err := preparePolicyEntries(config)
	if err != nil {
		return fmt.Errorf("prepare policies: %w", err)
	}
	if config.Diagnostics {
		for _, object := range entries.objects {
			log.Printf(
				"policy object path=%s device=%d inode=%d policy_id=%d mode=%d",
				object.path,
				object.key.Device,
				object.key.Inode,
				object.value.PolicyID,
				object.value.Mode,
			)
		}
	}
	if checkOnly {
		log.Printf("policy validation successful: %d protected objects", len(entries.objects))
		return nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	var objects lsmbpfObjects
	if err := loadLsmbpfObjects(&objects, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	defer objects.Close()

	if err := populatePolicyMaps(&objects, entries); err != nil {
		return fmt.Errorf("populate policy maps: %w", err)
	}
	if err := populateControllerSettings(&objects, config.Diagnostics); err != nil {
		return fmt.Errorf("populate controller settings: %w", err)
	}

	lsmLinks, err := attachLSMPrograms(&objects)
	if err != nil {
		return err
	}
	defer closeLinks(lsmLinks)

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		return fmt.Errorf("open event ring buffer: %w", err)
	}
	defer reader.Close()
	diagnosticStop := make(chan struct{})
	if config.Diagnostics {
		go logDiagnostics(&objects, diagnosticStop)
	}
	defer close(diagnosticStop)

	output, closeOutput, err := openOutput(outputPath)
	if err != nil {
		return err
	}
	defer closeOutput()
	encoder := json.NewEncoder(output)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	go func() {
		<-stop
		_ = reader.Close()
	}()

	log.Printf(
		"BPF LSM attached with %d protected objects; event output=%s",
		len(entries.objects),
		outputPath,
	)
	for {
		record, err := reader.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read ring buffer: %w", err)
		}

		event, err := decodeSecurityEvent(record.RawSample, policyNames)
		if err != nil {
			log.Printf("discard malformed BPF event: %v", err)
			continue
		}
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("write event output: %w", err)
		}
	}
}

var diagnosticNames = []string{
	"file_permission",
	"inode_unlink",
	"inode_rename",
	"inode_setattr",
	"policy_miss",
	"policy_hit",
	"policy_expired",
	"allowed_uid",
	"audit_event",
	"deny_event",
	"ringbuf_dropped",
}

func logDiagnostics(objects *lsmbpfObjects, stop <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	previous := make([]uint64, len(diagnosticNames))

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			current := make([]uint64, len(diagnosticNames))
			changed := false
			for index := range diagnosticNames {
				key := uint32(index)
				var perCPU []uint64
				if err := objects.Stats.Lookup(key, &perCPU); err != nil {
					log.Printf("read BPF diagnostic %s: %v", diagnosticNames[index], err)
					continue
				}
				for _, value := range perCPU {
					current[index] += value
				}
				if current[index] != previous[index] {
					changed = true
				}
			}
			if changed {
				fields := make([]string, 0, len(diagnosticNames))
				for index, name := range diagnosticNames {
					fields = append(fields, fmt.Sprintf("%s=%d", name, current[index]))
				}
				log.Printf("BPF diagnostics: %s", strings.Join(fields, " "))
				previous = current
			}
		}
	}
}

func decodeSecurityEvent(raw []byte, policyNames map[uint32]string) (outputEvent, error) {
	var event securityEvent
	if len(raw) != binary.Size(event) {
		return outputEvent{}, fmt.Errorf(
			"unexpected event size: got %d want %d",
			len(raw),
			binary.Size(event),
		)
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
		return outputEvent{}, err
	}

	action := "unknown"
	switch event.Action {
	case actionAudit:
		action = "audit"
	case actionDeny:
		action = "deny"
	}
	operation := "unknown"
	switch event.Operation {
	case operationWrite:
		operation = "write"
	case operationUnlink:
		operation = "unlink"
	case operationRenameSource:
		operation = "rename_source"
	case operationRenameTarget:
		operation = "rename_target"
	case operationSetattr:
		operation = "setattr"
	}

	return outputEvent{
		ReceivedTime:         time.Now().UTC().Format(time.RFC3339Nano),
		Source:               "bpf_lsm",
		PolicyID:             event.PolicyID,
		PolicyName:           policyNames[event.PolicyID],
		Action:               action,
		Operation:            operation,
		Result:               event.Result,
		PID:                  uint32(event.PIDTGID),
		TGID:                 uint32(event.PIDTGID >> 32),
		UID:                  event.UID,
		GID:                  event.GID,
		CgroupID:             event.CgroupID,
		Device:               event.Device,
		Inode:                event.Inode,
		Mask:                 event.Mask,
		Command:              strings.TrimRight(string(event.Comm[:]), "\x00"),
		MonotonicTimestampNS: event.TimestampNS,
	}, nil
}

func attachLSMPrograms(objects *lsmbpfObjects) ([]link.Link, error) {
	programs := []struct {
		name    string
		program *ebpf.Program
	}{
		{"file_permission", objects.HandleFilePermission},
		{"inode_unlink", objects.HandleInodeUnlink},
		{"inode_rename", objects.HandleInodeRename},
		{"inode_setattr", objects.HandleInodeSetattr},
	}

	links := make([]link.Link, 0, len(programs))
	for _, item := range programs {
		if item.program == nil {
			closeLinks(links)
			return nil, fmt.Errorf("BPF program %s is unavailable", item.name)
		}
		attached, err := link.AttachLSM(link.LSMOptions{Program: item.program})
		if err != nil {
			closeLinks(links)
			return nil, fmt.Errorf("attach BPF LSM %s: %w", item.name, err)
		}
		links = append(links, attached)
	}
	return links, nil
}

func closeLinks(links []link.Link) {
	for index := len(links) - 1; index >= 0; index-- {
		_ = links[index].Close()
	}
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "-" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open output %s: %w", path, err)
	}
	return file, func() { _ = file.Close() }, nil
}
