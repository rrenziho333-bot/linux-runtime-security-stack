#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAY_WRITE 0x2
#define EPERM 1

#define POLICY_MODE_AUDIT 1
#define POLICY_MODE_ENFORCE 2

#define ACTION_AUDIT 1
#define ACTION_DENY 2

#define OPERATION_WRITE 1
#define OPERATION_UNLINK 2
#define OPERATION_RENAME_SOURCE 3
#define OPERATION_RENAME_TARGET 4
#define OPERATION_SETATTR 5

#define STAT_FILE_PERMISSION 0
#define STAT_INODE_UNLINK 1
#define STAT_INODE_RENAME 2
#define STAT_INODE_SETATTR 3
#define STAT_POLICY_MISS 4
#define STAT_POLICY_HIT 5
#define STAT_POLICY_EXPIRED 6
#define STAT_ALLOWED_UID 7
#define STAT_AUDIT_EVENT 8
#define STAT_DENY_EVENT 9
#define STAT_RINGBUF_DROPPED 10
#define STAT_MAX 11

struct object_key {
    __u64 device;
    __u64 inode;
};

struct policy_value {
    __u32 policy_id;
    __u32 mode;
    __u64 expires_at_ns;
};

struct allowed_uid_key {
    __u32 policy_id;
    __u32 uid;
};

struct security_event {
    __u64 timestamp_ns;
    __u64 pid_tgid;
    __u64 cgroup_id;
    __u64 inode;
    __u64 device;
    __u32 uid;
    __u32 gid;
    __u32 mask;
    __u32 policy_id;
    __u32 action;
    __s32 result;
    __u32 operation;
    __u32 reserved;
    char comm[16];
};

struct controller_settings {
    __u32 diagnostics_enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct object_key);
    __type(value, struct policy_value);
} protected_objects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct allowed_uid_key);
    __type(value, __u8);
} allowed_uids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct controller_settings);
} settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline void increment_stat(__u32 index)
{
    struct controller_settings *config;
    __u64 *counter;
    __u32 zero = 0;

    config = bpf_map_lookup_elem(&settings, &zero);
    if (!config || !config->diagnostics_enabled)
        return;
    counter = bpf_map_lookup_elem(&stats, &index);
    if (counter)
        *counter += 1;
}

static __always_inline void emit_event(
    const struct object_key *object,
    const struct policy_value *policy,
    int mask,
    __u32 operation,
    __u32 action,
    int result)
{
    struct security_event *event;
    __u64 uid_gid;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat(STAT_RINGBUF_DROPPED);
        return;
    }

    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid_tgid = bpf_get_current_pid_tgid();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->inode = object->inode;
    event->device = object->device;
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);
    event->mask = (__u32)mask;
    event->policy_id = policy->policy_id;
    event->action = action;
    event->result = result;
    event->operation = operation;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    increment_stat(
        action == ACTION_DENY ? STAT_DENY_EVENT : STAT_AUDIT_EVENT);
}

static __always_inline int evaluate_inode(
    struct inode *inode,
    int mask,
    __u32 operation)
{
    struct policy_value *policy;
    struct allowed_uid_key uid_key;
    struct object_key object;
    __u64 uid_gid;

    if (!inode)
        return 0;

    object.inode = BPF_CORE_READ(inode, i_ino);
    object.device = BPF_CORE_READ(inode, i_sb, s_dev);
    policy = bpf_map_lookup_elem(&protected_objects, &object);
    if (!policy) {
        increment_stat(STAT_POLICY_MISS);
        return 0;
    }
    increment_stat(STAT_POLICY_HIT);

    if (policy->expires_at_ns != 0 &&
        bpf_ktime_get_ns() >= policy->expires_at_ns) {
        increment_stat(STAT_POLICY_EXPIRED);
        return 0;
    }

    uid_gid = bpf_get_current_uid_gid();
    uid_key.policy_id = policy->policy_id;
    uid_key.uid = (__u32)uid_gid;
    if (bpf_map_lookup_elem(&allowed_uids, &uid_key)) {
        increment_stat(STAT_ALLOWED_UID);
        return 0;
    }

    if (policy->mode == POLICY_MODE_AUDIT) {
        emit_event(&object, policy, mask, operation, ACTION_AUDIT, 0);
        return 0;
    }

    if (policy->mode == POLICY_MODE_ENFORCE) {
        emit_event(&object, policy, mask, operation, ACTION_DENY, -EPERM);
        return -EPERM;
    }

    /* Unknown modes fail open and are rejected by the userspace controller. */
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(handle_file_permission, struct file *file, int mask, int ret)
{
    struct inode *inode;

    /* Preserve an earlier BPF LSM denial in a multi-program attachment chain. */
    if (ret != 0)
        return ret;
    if (!(mask & MAY_WRITE))
        return 0;

    increment_stat(STAT_FILE_PERMISSION);
    inode = BPF_CORE_READ(file, f_inode);
    return evaluate_inode(inode, mask, OPERATION_WRITE);
}

SEC("lsm/inode_unlink")
int BPF_PROG(
    handle_inode_unlink,
    struct inode *dir,
    struct dentry *dentry,
    int ret)
{
    struct inode *inode;

    if (ret != 0)
        return ret;
    increment_stat(STAT_INODE_UNLINK);
    inode = BPF_CORE_READ(dentry, d_inode);
    return evaluate_inode(inode, 0, OPERATION_UNLINK);
}

SEC("lsm/inode_rename")
int BPF_PROG(
    handle_inode_rename,
    struct inode *old_dir,
    struct dentry *old_dentry,
    struct inode *new_dir,
    struct dentry *new_dentry,
    int ret)
{
    struct inode *inode;
    int result;

    if (ret != 0)
        return ret;

    increment_stat(STAT_INODE_RENAME);
    inode = BPF_CORE_READ(old_dentry, d_inode);
    result = evaluate_inode(inode, 0, OPERATION_RENAME_SOURCE);
    if (result != 0)
        return result;

    /* A non-null target inode means an existing protected file is replaced. */
    inode = BPF_CORE_READ(new_dentry, d_inode);
    return evaluate_inode(inode, 0, OPERATION_RENAME_TARGET);
}

SEC("lsm/inode_setattr")
int BPF_PROG(
    handle_inode_setattr,
    struct dentry *dentry,
    struct iattr *attr,
    int ret)
{
    struct inode *inode;

    if (ret != 0)
        return ret;
    increment_stat(STAT_INODE_SETATTR);
    inode = BPF_CORE_READ(dentry, d_inode);
    return evaluate_inode(inode, 0, OPERATION_SETATTR);
}
