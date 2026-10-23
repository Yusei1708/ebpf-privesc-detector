/*
 * Linux Privilege Escalation Detector - eBPF Probe Program
 *
 * Observability Boundaries & Disclaimer:
 * 1. tracepoint/syscalls/sys_enter_execve:
 *    - Observes invocation ATTEMPTS of execve with arguments and caller credentials.
 *    - Does NOT conclude whether execve succeeded or failed (e.g., -ENOENT, -EACCES).
 * 2. kprobe/commit_creds:
 *    - Observes the installation of new struct cred for the current task.
 * 3. kprobe/cap_capable:
 *    - Observes when the kernel audits a specific capability for an operation.
 *    - Does NOT determine whether the permission was ultimately granted or denied.
 * 4. tracepoint/syscalls/sys_enter_openat:
 *    - Observes the intent/attempt to open a specific path.
 *    - Does NOT mean the file was successfully opened or read (e.g. may return -EACCES).
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#include <linux/ns_common.h>

#define EVENT_EXECVE        1
#define EVENT_COMMIT_CREDS  2
#define EVENT_CAP_CHECK     3
#define EVENT_OPENAT        4

#define TASK_COMM_LEN       16
#define PATH_MAX_LEN        128

/*
 * Struct transferred from Kernel eBPF probe to User Space Agent.
 * Explicitly aligned to 8-byte boundary to avoid architecture/compiler padding discrepancies.
 * Total size: 8 * 4 (32) + 3 * 8 (24) + 16 + 128 = 200 bytes.
 */
struct event_t {
    u32 event_type;             /* EVENT_EXECVE, EVENT_COMMIT_CREDS, ... */
    u32 pid;                    /* Thread ID */
    u32 tgid;                   /* Process ID */
    u32 ppid;                   /* Parent Process ID */
    u32 uid;                    /* Real UID (from task credentials) */
    u32 euid;                   /* Effective UID (from task credentials) */
    u32 cap;                    /* Capability checked (if CAP_CHECK) */
    u32 _pad;                   /* Explicit padding for 8-byte alignment */
    u64 cgroup_id;              /* Cgroup v2 ID (distinguishes containers) */
    u64 mntns_id;               /* Mount namespace inode number */
    u64 timestamp_ns;           /* Kernel monotonic timestamp in nanoseconds */
    char comm[TASK_COMM_LEN];   /* Executable name */
    char filename[PATH_MAX_LEN];/* Executed binary or accessed file path */
} __attribute__((aligned(8)));

BPF_PERF_OUTPUT(events);

/* Helper to safely retrieve PPID from task_struct */
static inline u32 get_ppid(struct task_struct *task) {
    u32 ppid = 0;
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    }
    return ppid;
}

/* Helper to safely retrieve Mount Namespace Inode Number */
static inline u64 get_mntns_id(struct task_struct *task) {
    u64 mntns_id = 0;
    struct nsproxy *nsproxy = NULL;
    struct mnt_namespace *mnt_ns = NULL;

    bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (nsproxy) {
        bpf_probe_read_kernel(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns);
        if (mnt_ns) {
            bpf_probe_read_kernel(&mntns_id, sizeof(mntns_id), &mnt_ns->ns.inum);
        }
    }
    return mntns_id;
}

/*
 * Helper to safely extract both Real UID and Effective UID from task_struct->cred.
 * NOTE: bpf_get_current_uid_gid() returns (GID << 32) | UID. It does NOT provide EUID!
 * We must read cred->euid.val directly from kernel memory.
 */
static inline void fill_task_uids(struct task_struct *task, u32 *out_uid, u32 *out_euid) {
    const struct cred *cred = NULL;
    bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred);
    if (cred) {
        bpf_probe_read_kernel(out_uid, sizeof(*out_uid), &cred->uid.val);
        bpf_probe_read_kernel(out_euid, sizeof(*out_euid), &cred->euid.val);
    } else {
        u64 uid_gid = bpf_get_current_uid_gid();
        *out_uid = (u32)uid_gid;
        *out_euid = (u32)uid_gid; // Fallback if cred pointer cannot be dereferenced
    }
}

/*
 * 1. Hook sys_enter_execve
 * Observes process execution attempt, requested binary path, and namespaces.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u64 id = bpf_get_current_pid_tgid();
    event.pid = (u32)id;
    event.tgid = (u32)(id >> 32);
    event.ppid = get_ppid(task);

    fill_task_uids(task, &event.uid, &event.euid);

    event.event_type = EVENT_EXECVE;
    event.cgroup_id = bpf_get_current_cgroup_id();
    event.mntns_id = get_mntns_id(task);
    event.timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/*
 * 2. Hook commit_creds
 * Observes credential transition (e.g. non-root task becoming root EUID=0).
 */
int kprobe__commit_creds(struct pt_regs *ctx, struct cred *new) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 current_uid = 0;
    u32 current_euid = 0;
    fill_task_uids(task, &current_uid, &current_euid);

    u32 new_uid = 0;
    u32 new_euid = 0;
    bpf_probe_read_kernel(&new_uid, sizeof(new_uid), &new->uid.val);
    bpf_probe_read_kernel(&new_euid, sizeof(new_euid), &new->euid.val);

    // Trigger event when EUID transitions or UID transitions
    if (new_euid != current_euid || new_uid != current_uid) {
        struct event_t event = {};
        u64 id = bpf_get_current_pid_tgid();
        event.pid = (u32)id;
        event.tgid = (u32)(id >> 32);
        event.ppid = get_ppid(task);

        event.uid = current_uid;
        event.euid = new_euid; // Target EUID after commit
        event.event_type = EVENT_COMMIT_CREDS;
        event.cgroup_id = bpf_get_current_cgroup_id();
        event.mntns_id = get_mntns_id(task);
        event.timestamp_ns = bpf_ktime_get_ns();

        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

/*
 * 3. Hook cap_capable
 * Audits critical Linux capability inspections:
 * CAP_DAC_OVERRIDE (1), CAP_SETGID (6), CAP_SETUID (10), CAP_NET_ADMIN (12),
 * CAP_SYS_PTRACE (19), CAP_SYS_ADMIN (21)
 */
int kprobe__cap_capable(struct pt_regs *ctx, const struct cred *cred, struct user_namespace *targ_ns, int cap, unsigned int opts) {
    if (cap == 1 || cap == 6 || cap == 10 || cap == 12 || cap == 19 || cap == 21) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct event_t event = {};
        u64 id = bpf_get_current_pid_tgid();
        event.pid = (u32)id;
        event.tgid = (u32)(id >> 32);
        event.ppid = get_ppid(task);

        fill_task_uids(task, &event.uid, &event.euid);

        event.cap = (u32)cap;
        event.event_type = EVENT_CAP_CHECK;
        event.cgroup_id = bpf_get_current_cgroup_id();
        event.mntns_id = get_mntns_id(task);
        event.timestamp_ns = bpf_ktime_get_ns();

        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

/*
 * 4. Hook sys_enter_openat
 * Observes attempts to open sensitive configuration/shadow files.
 * NOTE: This is entry only; permission checks in VFS happen later in kernel.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char path[PATH_MAX_LEN] = {};
    bpf_probe_read_user_str(&path, sizeof(path), args->filename);

    // Fast path filter: check for prefix "/etc/"
    if (path[0] == '/' && path[1] == 'e' && path[2] == 't' && path[3] == 'c' && path[4] == '/') {
        bool match = false;
        // /etc/shadow
        if (path[5] == 's' && path[6] == 'h' && path[7] == 'a' && path[8] == 'd' && path[9] == 'o' && path[10] == 'w') {
            match = true;
        // /etc/sudoers
        } else if (path[5] == 's' && path[6] == 'u' && path[7] == 'd' && path[8] == 'o' && path[9] == 'e' && path[10] == 'r') {
            match = true;
        // /etc/passwd
        } else if (path[5] == 'p' && path[6] == 'a' && path[7] == 's' && path[8] == 's' && path[9] == 'w' && path[10] == 'd') {
            match = true;
        }

        if (match) {
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            struct event_t event = {};
            u64 id = bpf_get_current_pid_tgid();
            event.pid = (u32)id;
            event.tgid = (u32)(id >> 32);
            event.ppid = get_ppid(task);

            fill_task_uids(task, &event.uid, &event.euid);

            event.event_type = EVENT_OPENAT;
            event.cgroup_id = bpf_get_current_cgroup_id();
            event.mntns_id = get_mntns_id(task);
            event.timestamp_ns = bpf_ktime_get_ns();

            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            __builtin_memcpy(event.filename, path, sizeof(event.filename));

            events.perf_submit(args, &event, sizeof(event));
        }
    }
    return 0;
}
