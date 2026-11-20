/*
 * Linux Privilege Escalation Detector - eBPF Probe Program
 *
 * Observability Boundaries & Disclaimer:
 * 1. tracepoint/syscalls/sys_enter_execve & sys_enter_execveat:
 *    - Observes invocation ATTEMPTS of execve/execveat with arguments and caller credentials.
 *    - Does NOT conclude whether execve/execveat succeeded or failed (e.g., -ENOENT, -EACCES).
 * 2. kprobe/commit_creds:
 *    - Observes the installation of new struct cred for the current task.
 * 3. kprobe/cap_capable:
 *    - Observes when the kernel audits a specific capability for an operation.
 *    - Does NOT determine whether the permission was ultimately granted or denied.
 * 4. tracepoint/syscalls/sys_enter_openat:
 *    - Observes the intent/attempt to open a specific sensitive path.
 *    - Does NOT mean the file was successfully opened or read (e.g. may return -EACCES).
 * 5. tracepoint/sched/sched_process_exit:
 *    - Observes thread-group leader exit for tracked processes to resolve PID reuse accurately.
 */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/capability.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ns_common.h>

#define EVENT_EXECVE        1
#define EVENT_COMMIT_CREDS  2
#define EVENT_CAP_CHECK     3
#define EVENT_OPENAT        4
#define EVENT_PROCESS_EXIT  5

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
    u64 pidns_id;               /* PID namespace inode number (portable across Linux 5.8-6.x) */
    u64 timestamp_ns;           /* Kernel monotonic timestamp in nanoseconds */
    char comm[TASK_COMM_LEN];   /* Executable name */
    char filename[PATH_MAX_LEN];/* Executed binary or accessed file path */
} __attribute__((aligned(8)));

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_scratch, struct event_t, 1);
BPF_HASH(tracked_tgids, u32, u8, 65536);

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

/*
 * Helper to safely retrieve PID Namespace Inode Number.
 * Reads u32 (sizeof(ns.inum) == 4) to avoid 4-byte out-of-field read into ns.count.
 */
static inline u64 get_pidns_id(struct task_struct *task) {
    u32 inum = 0;
    struct nsproxy *nsproxy = NULL;
    struct pid_namespace *pid_ns = NULL;

    bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (nsproxy) {
        bpf_probe_read_kernel(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children);
        if (pid_ns) {
            bpf_probe_read_kernel(&inum, sizeof(inum), &pid_ns->ns.inum);
        }
    }
    return (u64)inum;
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
 * Helper to obtain and populate a per-CPU scratch event_t buffer (avoids 200B stack allocation).
 */
static inline struct event_t *init_event(u32 event_type, struct task_struct *task) {
    u32 zero = 0;
    struct event_t *event = event_scratch.lookup(&zero);
    if (!event) {
        return NULL;
    }

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);

    event->event_type = event_type;
    event->pid = pid;
    event->tgid = tgid;
    event->ppid = get_ppid(task);
    event->uid = 0;
    event->euid = 0;
    event->cap = 0;
    event->_pad = 0;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pidns_id = get_pidns_id(task);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->comm[0] = '\0';
    event->filename[0] = '\0';

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    if (event_type != EVENT_PROCESS_EXIT && tgid > 0) {
        u8 one = 1;
        tracked_tgids.update(&tgid, &one);
    }

    return event;
}

/*
 * 1. Hook sys_enter_execve
 * Observes process execution attempt, requested binary path, and namespaces.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *event = init_event(EVENT_EXECVE, task);
    if (!event) {
        return 0;
    }

    fill_task_uids(task, &event->uid, &event->euid);
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args->filename);

    events.perf_submit(args, event, sizeof(*event));
    return 0;
}

/*
 * 1b. Hook sys_enter_execveat
 * Catches fileless execution (memfd_create + execveat AT_EMPTY_PATH) and dfd-relative exec.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *event = init_event(EVENT_EXECVE, task);
    if (!event) {
        return 0;
    }

    fill_task_uids(task, &event->uid, &event->euid);
    int n = bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args->filename);
    if (n <= 1) {
        __builtin_memcpy(event->filename, "(execveat:fd)", 14);
    }

    events.perf_submit(args, event, sizeof(*event));
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
        struct event_t *event = init_event(EVENT_COMMIT_CREDS, task);
        if (!event) {
            return 0;
        }
        event->uid = current_uid;
        event->euid = new_euid; // Target EUID after commit
        events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

/*
 * 3. Hook cap_capable
 * Audits critical Linux capability inspections using UAPI constants:
 * CAP_DAC_OVERRIDE (1), CAP_SETGID (6), CAP_SETUID (7), CAP_NET_ADMIN (12),
 * CAP_SYS_MODULE (16), CAP_SYS_PTRACE (19), CAP_SYS_ADMIN (21)
 */
int kprobe__cap_capable(struct pt_regs *ctx, const struct cred *cred, struct user_namespace *targ_ns, int cap, unsigned int opts) {
    if (cap == CAP_DAC_OVERRIDE || cap == CAP_SETGID || cap == CAP_SETUID ||
        cap == CAP_NET_ADMIN || cap == CAP_SYS_MODULE || cap == CAP_SYS_PTRACE ||
        cap == CAP_SYS_ADMIN) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct event_t *event = init_event(EVENT_CAP_CHECK, task);
        if (!event) {
            return 0;
        }

        fill_task_uids(task, &event->uid, &event->euid);
        event->cap = (u32)cap;

        events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

/*
 * 4. Hook sys_enter_openat
 * Observes attempts to open sensitive configuration/shadow/preload files.
 * NOTE: This is entry only; permission checks in VFS happen later in kernel.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char path[32] = {};
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
        // /etc/gshadow
        } else if (path[5] == 'g' && path[6] == 's' && path[7] == 'h' && path[8] == 'a' && path[9] == 'd' && path[10] == 'o' && path[11] == 'w') {
            match = true;
        // /etc/ld.so.preload
        } else if (path[5] == 'l' && path[6] == 'd' && path[7] == '.' && path[8] == 's' && path[9] == 'o' &&
                   path[10] == '.' && path[11] == 'p' && path[12] == 'r' && path[13] == 'e' && path[14] == 'l' &&
                   path[15] == 'o' && path[16] == 'a' && path[17] == 'd') {
            match = true;
        }

        if (match) {
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            struct event_t *event = init_event(EVENT_OPENAT, task);
            if (!event) {
                return 0;
            }

            fill_task_uids(task, &event->uid, &event->euid);
            bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args->filename);

            events.perf_submit(args, event, sizeof(*event));
        }
    }
    return 0;
}

/*
 * 5. Hook sched_process_exit
 * Emits EVENT_PROCESS_EXIT for tracked thread-group leaders to handle PID reuse cleanly.
 */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);

    if (pid != tgid || tgid == 0) {
        return 0;
    }

    u8 *seen = tracked_tgids.lookup(&tgid);
    if (!seen) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *event = init_event(EVENT_PROCESS_EXIT, task);
    if (event) {
        fill_task_uids(task, &event->uid, &event->euid);
        events.perf_submit(args, event, sizeof(*event));
    }
    tracked_tgids.delete(&tgid);
    return 0;
}
