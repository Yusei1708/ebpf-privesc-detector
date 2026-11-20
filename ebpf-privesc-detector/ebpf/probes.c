/*
 * Linux Privilege Escalation Detector - eBPF Probe Program
 *
 * Observability Boundaries & Portability (Linux 5.8 - 6.14):
 * 1. tracepoint/syscalls/sys_enter_execve & sys_enter_execveat (+ sys_exit_*):
 *    - Observes execution attempts at syscall entry and reverts failed execs on ret < 0 (FLAG_EXEC_FAILED).
 * 2. kprobe/commit_creds:
 *    - Observes installation of new struct cred for UID/EUID/FSUID/EGID or capability gains.
 * 3. kprobe/cap_capable:
 *    - Observes audited capability inspections (filtering CAP_OPT_NOAUDIT and tagging userns checks).
 * 4. tracepoint/syscalls/sys_enter_openat:
 *    - Observes attempts to open sensitive paths with exact boundary checks and write-intent filtering
 *      for /etc/passwd and /etc/ld.so.preload.
 * 5. tracepoint/sched/sched_process_fork & sched_process_exit:
 *    - Tracks process fork lineage for monitored processes and detects true thread-group exit
 *      (signal->live.counter == 0) to handle PID reuse cleanly.
 */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/capability.h>
#include <uapi/linux/fcntl.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/nsproxy.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/ns_common.h>

#define EVENT_EXECVE        1
#define EVENT_COMMIT_CREDS  2
#define EVENT_CAP_CHECK     3
#define EVENT_OPENAT        4
#define EVENT_PROCESS_EXIT  5
#define EVENT_PROCESS_FORK  6

#define FLAG_OPEN_WRITE     (1U << 0)
#define FLAG_CRED_UID_GAIN  (1U << 1)
#define FLAG_CRED_CAP_GAIN  (1U << 2)
#define FLAG_CAP_USERNS     (1U << 4)
#define FLAG_EXEC_FAILED    (1U << 5)

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN       16
#endif
#define PATH_MAX_LEN        128

#ifndef RINGBUF_PAGES
#define RINGBUF_PAGES       256
#endif

#ifndef CAP_OPT_NOAUDIT
#define CAP_OPT_NOAUDIT     (1U << 1)
#endif

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
    u32 flags;                  /* Event flags (FLAG_OPEN_WRITE, FLAG_CRED_*, etc.) */
    u64 cgroup_id;              /* Cgroup v2 ID (distinguishes containers) */
    u64 pidns_id;               /* Active PID namespace inode number (Linux 5.8-6.14) */
    u64 timestamp_ns;           /* Kernel monotonic timestamp in nanoseconds */
    char comm[TASK_COMM_LEN];   /* Executable name */
    char filename[PATH_MAX_LEN];/* Executed binary or accessed file path */
} __attribute__((aligned(8)));

BPF_RINGBUF_OUTPUT(events, RINGBUF_PAGES);
BPF_PERCPU_ARRAY(dropped_events, u64, 1);
BPF_LRU_HASH(tracked_tgids, u32, u8, 65536);

/* Helper to track dropped ringbuf events per-CPU */
static inline void record_dropped_event(void) {
    u32 zero = 0;
    u64 *cnt = dropped_events.lookup(&zero);
    if (cnt) {
        (*cnt)++;
    }
}

/* Helper to insert tgid into LRU map only if not already present (avoids hot-path write lock) */
static inline void mark_tgid_tracked(u32 tgid) {
    if (tgid == 0) {
        return;
    }
    if (!tracked_tgids.lookup(&tgid)) {
        u8 one = 1;
        tracked_tgids.update(&tgid, &one);
    }
}

/* Helper to safely retrieve PPID from task_struct */
static inline u32 get_ppid(struct task_struct *task) {
    u32 ppid = 0;
    struct task_struct *parent = NULL;
    if (task && bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) == 0 && parent) {
        if (bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid) != 0) {
            ppid = 0;
        }
    }
    return ppid;
}

/*
 * Helper to retrieve active PID Namespace inode via task->thread_pid (level < 32),
 * falling back to nsproxy->pid_ns_for_children if thread_pid is unavailable.
 * Avoids redeclaring private kernel structs (portable across Linux 5.8-6.14).
 */
static inline u64 get_pidns_id(struct task_struct *task) {
    u32 inum = 0;
    if (!task) {
        return 0;
    }

    struct pid *tpid = NULL;
    if (bpf_probe_read_kernel(&tpid, sizeof(tpid), &task->thread_pid) == 0 && tpid) {
        u32 level = 0;
        if (bpf_probe_read_kernel(&level, sizeof(level), &tpid->level) == 0 && level < 32) {
            struct upid upid = {};
            if (bpf_probe_read_kernel(&upid, sizeof(upid), &tpid->numbers[level]) == 0 && upid.ns) {
                if (bpf_probe_read_kernel(&inum, sizeof(inum), &upid.ns->ns.inum) != 0) {
                    inum = 0;
                }
            }
        }
    }

    if (inum == 0) {
        struct nsproxy *nsproxy = NULL;
        struct pid_namespace *pid_ns = NULL;
        if (bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy) == 0 && nsproxy) {
            if (bpf_probe_read_kernel(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children) == 0 && pid_ns) {
                if (bpf_probe_read_kernel(&inum, sizeof(inum), &pid_ns->ns.inum) != 0) {
                    inum = 0;
                }
            }
        }
    }
    return (u64)inum;
}

/*
 * Helper to safely extract Real UID and Effective UID from task->real_cred
 * (avoiding temporary OverlayFS task->cred overrides), with fallback to task->cred
 * and bpf_get_current_uid_gid().
 */
static inline void fill_task_uids(struct task_struct *task, u32 *out_uid, u32 *out_euid) {
    const struct cred *cred = NULL;
    u32 uid_val = 0;
    u32 euid_val = 0;

    if (task && bpf_probe_read_kernel(&cred, sizeof(cred), &task->real_cred) == 0 && cred) {
        if (bpf_probe_read_kernel(&uid_val, sizeof(uid_val), &cred->uid.val) == 0 &&
            bpf_probe_read_kernel(&euid_val, sizeof(euid_val), &cred->euid.val) == 0) {
            *out_uid = uid_val;
            *out_euid = euid_val;
            return;
        }
    }

    cred = NULL;
    if (task && bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred) == 0 && cred) {
        if (bpf_probe_read_kernel(&uid_val, sizeof(uid_val), &cred->uid.val) == 0 &&
            bpf_probe_read_kernel(&euid_val, sizeof(euid_val), &cred->euid.val) == 0) {
            *out_uid = uid_val;
            *out_euid = euid_val;
            return;
        }
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    *out_uid = (u32)uid_gid;
    *out_euid = (u32)uid_gid;
}

/*
 * Reserve and zero-initialize an event_t directly on the BPF Ring Buffer.
 * Every non-NULL return MUST be followed by either ringbuf_submit or ringbuf_discard.
 */
static inline struct event_t *reserve_event(u32 event_type, struct task_struct *task, u32 pid, u32 tgid, u32 ppid) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) {
        record_dropped_event();
        return NULL;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = event_type;
    event->pid = pid;
    event->tgid = tgid;
    event->ppid = ppid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pidns_id = get_pidns_id(task);
    event->timestamp_ns = bpf_ktime_get_ns();

    return event;
}

/*
 * 1a. Hook sys_enter_execve
 * Observes execution attempt so exe_path is available before commit_creds fires.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);
    mark_tgid_tracked(tgid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *event = reserve_event(EVENT_EXECVE, task, pid, tgid, get_ppid(task));
    if (!event) {
        return 0;
    }

    fill_task_uids(task, &event->uid, &event->euid);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args->filename);

    events.ringbuf_submit(event, 0);
    return 0;
}

/*
 * 1b. Hook sys_exit_execve
 * Emits EVENT_EXECVE with FLAG_EXEC_FAILED on failure (args->ret < 0) to revert speculative exe_path.
 */
TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    if (args->ret >= 0) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);
    mark_tgid_tracked(tgid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *event = reserve_event(EVENT_EXECVE, task, pid, tgid, get_ppid(task));
    if (!event) {
        return 0;
    }

    fill_task_uids(task, &event->uid, &event->euid);
    event->flags = FLAG_EXEC_FAILED;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

/*
 * 1c. Hook sys_enter_execveat
 * Catches fileless execution (memfd_create + execveat AT_EMPTY_PATH) and dfd-relative exec.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);
    mark_tgid_tracked(tgid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *event = reserve_event(EVENT_EXECVE, task, pid, tgid, get_ppid(task));
    if (!event) {
        return 0;
    }

    fill_task_uids(task, &event->uid, &event->euid);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    long n = bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args->filename);
    if (n <= 1) {
        __builtin_memcpy(event->filename, "(execveat:fd)", 14);
    }

    events.ringbuf_submit(event, 0);
    return 0;
}

/*
 * 1d. Hook sys_exit_execveat
 * Emits EVENT_EXECVE with FLAG_EXEC_FAILED on failure (args->ret < 0).
 */
TRACEPOINT_PROBE(syscalls, sys_exit_execveat) {
    if (args->ret >= 0) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);
    mark_tgid_tracked(tgid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *event = reserve_event(EVENT_EXECVE, task, pid, tgid, get_ppid(task));
    if (!event) {
        return 0;
    }

    fill_task_uids(task, &event->uid, &event->euid);
    event->flags = FLAG_EXEC_FAILED;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

/*
 * 2. Hook commit_creds
 * Observes credential privilege gains (UID/EUID/FSUID/EGID gain or new cap_effective bits).
 * Never names kernel_cap_t .val/.cap fields for Linux 5.8-6.14 portability.
 */
int kprobe__commit_creds(struct pt_regs *ctx, struct cred *new) {
    if (!new) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    const struct cred *cur_cred = NULL;
    if (bpf_probe_read_kernel(&cur_cred, sizeof(cur_cred), &task->real_cred) != 0 || !cur_cred) {
        if (bpf_probe_read_kernel(&cur_cred, sizeof(cur_cred), &task->cred) != 0 || !cur_cred) {
            return 0;
        }
    }

    u32 cur_uid = 0, cur_euid = 0, cur_fsuid = 0, cur_egid = 0;
    u32 new_uid = 0, new_euid = 0, new_fsuid = 0, new_egid = 0;

    if (bpf_probe_read_kernel(&cur_uid, sizeof(cur_uid), &cur_cred->uid.val) != 0) return 0;
    if (bpf_probe_read_kernel(&cur_euid, sizeof(cur_euid), &cur_cred->euid.val) != 0) return 0;
    if (bpf_probe_read_kernel(&cur_fsuid, sizeof(cur_fsuid), &cur_cred->fsuid.val) != 0) return 0;
    if (bpf_probe_read_kernel(&cur_egid, sizeof(cur_egid), &cur_cred->egid.val) != 0) return 0;

    if (bpf_probe_read_kernel(&new_uid, sizeof(new_uid), &new->uid.val) != 0) return 0;
    if (bpf_probe_read_kernel(&new_euid, sizeof(new_euid), &new->euid.val) != 0) return 0;
    if (bpf_probe_read_kernel(&new_fsuid, sizeof(new_fsuid), &new->fsuid.val) != 0) return 0;
    if (bpf_probe_read_kernel(&new_egid, sizeof(new_egid), &new->egid.val) != 0) return 0;

    u64 cur_cap = 0, new_cap = 0;
    if (bpf_probe_read_kernel(&cur_cap, sizeof(cur_cap), &cur_cred->cap_effective) != 0) return 0;
    if (bpf_probe_read_kernel(&new_cap, sizeof(new_cap), &new->cap_effective) != 0) return 0;

    bool uid_gain = (new_euid < cur_euid) || (new_uid < cur_uid) ||
                    (new_fsuid < cur_fsuid) || (new_egid < cur_egid);
    bool cap_gain = ((new_cap & ~cur_cap) != 0);

    if (!uid_gain && !cap_gain) {
        return 0;
    }

    u32 ev_flags = 0;
    if (uid_gain) {
        ev_flags |= FLAG_CRED_UID_GAIN;
    }
    if (cap_gain) {
        ev_flags |= FLAG_CRED_CAP_GAIN;
    }

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);
    mark_tgid_tracked(tgid);

    struct event_t *event = reserve_event(EVENT_COMMIT_CREDS, task, pid, tgid, get_ppid(task));
    if (!event) {
        return 0;
    }

    event->uid = cur_uid;
    event->euid = new_euid;
    event->flags = ev_flags;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

/*
 * 3. Hook cap_capable
 * Audits critical Linux capability inspections, skipping CAP_OPT_NOAUDIT and
 * OverlayFS temporary cred overrides, and tagging non-init user namespace checks.
 */
int kprobe__cap_capable(struct pt_regs *ctx, const struct cred *cred, struct user_namespace *targ_ns, int cap, unsigned int opts) {
    if (cap != CAP_DAC_OVERRIDE && cap != CAP_SETGID && cap != CAP_SETUID &&
        cap != CAP_NET_ADMIN && cap != CAP_SYS_MODULE && cap != CAP_SYS_PTRACE &&
        cap != CAP_SYS_ADMIN) {
        return 0;
    }

    if (opts & CAP_OPT_NOAUDIT) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    const struct cred *real_cred = NULL;
    const struct cred *eff_cred = NULL;
    bpf_probe_read_kernel(&real_cred, sizeof(real_cred), &task->real_cred);
    bpf_probe_read_kernel(&eff_cred, sizeof(eff_cred), &task->cred);
    if (real_cred && eff_cred && eff_cred != real_cred && cred == eff_cred) {
        return 0;
    }

    u32 ev_flags = 0;
    int ns_level = 0;
    if (targ_ns && bpf_probe_read_kernel(&ns_level, sizeof(ns_level), &targ_ns->level) == 0 && ns_level > 0) {
        ev_flags |= FLAG_CAP_USERNS;
    }

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);
    mark_tgid_tracked(tgid);

    struct event_t *event = reserve_event(EVENT_CAP_CHECK, task, pid, tgid, get_ppid(task));
    if (!event) {
        return 0;
    }

    u32 uid_val = 0, euid_val = 0;
    if (cred &&
        bpf_probe_read_kernel(&uid_val, sizeof(uid_val), &cred->uid.val) == 0 &&
        bpf_probe_read_kernel(&euid_val, sizeof(euid_val), &cred->euid.val) == 0) {
        event->uid = uid_val;
        event->euid = euid_val;
    } else {
        fill_task_uids(task, &event->uid, &event->euid);
    }

    event->cap = (u32)cap;
    event->flags = ev_flags;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

/*
 * 4. Hook sys_enter_openat
 * Captures attempts (including -EACCES) to open sensitive files.
 * Strips up to 4 leading '/' characters and enforces exact boundary terminators:
 * - Read+Write: /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/sudoers.d/*
 * - Write-only: /etc/passwd, /etc/ld.so.preload (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)
 */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char raw_path[PATH_MAX_LEN] = {};
    long len = bpf_probe_read_user_str(&raw_path, sizeof(raw_path), args->filename);
    if (len <= 1 || raw_path[0] != '/') {
        return 0;
    }

    char p[32] = {};
    if (raw_path[1] == '/' && raw_path[2] == '/' && raw_path[3] == '/') {
        __builtin_memcpy(p, &raw_path[3], 28);
    } else if (raw_path[1] == '/' && raw_path[2] == '/') {
        __builtin_memcpy(p, &raw_path[2], 28);
    } else if (raw_path[1] == '/') {
        __builtin_memcpy(p, &raw_path[1], 28);
    } else {
        __builtin_memcpy(p, &raw_path[0], 28);
    }

    if (!(p[0] == '/' && p[1] == 'e' && p[2] == 't' && p[3] == 'c' && p[4] == '/')) {
        return 0;
    }

    bool is_write = ((args->flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0);
    bool match = false;

    /* /etc/shadow */
    if (p[5] == 's' && p[6] == 'h' && p[7] == 'a' && p[8] == 'd' && p[9] == 'o' && p[10] == 'w' && p[11] == '\0') {
        match = true;
    /* /etc/gshadow */
    } else if (p[5] == 'g' && p[6] == 's' && p[7] == 'h' && p[8] == 'a' && p[9] == 'd' && p[10] == 'o' && p[11] == 'w' && p[12] == '\0') {
        match = true;
    /* /etc/sudoers or /etc/sudoers.d/* */
    } else if (p[5] == 's' && p[6] == 'u' && p[7] == 'd' && p[8] == 'o' && p[9] == 'e' && p[10] == 'r' && p[11] == 's' &&
               (p[12] == '\0' || (p[12] == '.' && p[13] == 'd' && p[14] == '/'))) {
        match = true;
    /* /etc/passwd (write intent only) */
    } else if (is_write &&
               p[5] == 'p' && p[6] == 'a' && p[7] == 's' && p[8] == 's' && p[9] == 'w' && p[10] == 'd' && p[11] == '\0') {
        match = true;
    /* /etc/ld.so.preload (write intent only) */
    } else if (is_write &&
               p[5] == 'l' && p[6] == 'd' && p[7] == '.' && p[8] == 's' && p[9] == 'o' &&
               p[10] == '.' && p[11] == 'p' && p[12] == 'r' && p[13] == 'e' && p[14] == 'l' &&
               p[15] == 'o' && p[16] == 'a' && p[17] == 'd' && p[18] == '\0') {
        match = true;
    }

    if (!match) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);
    mark_tgid_tracked(tgid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *event = reserve_event(EVENT_OPENAT, task, pid, tgid, get_ppid(task));
    if (!event) {
        return 0;
    }

    fill_task_uids(task, &event->uid, &event->euid);
    event->flags = is_write ? FLAG_OPEN_WRITE : 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, raw_path, sizeof(event->filename));

    events.ringbuf_submit(event, 0);
    return 0;
}

/*
 * 5. Hook sched_process_fork
 * Tracks child processes spawned by tracked parents so inherited exe_path/lineage survives fork().
 */
TRACEPOINT_PROBE(sched, sched_process_fork) {
    u64 id = bpf_get_current_pid_tgid();
    u32 parent_tgid = (u32)(id >> 32);
    if (parent_tgid == 0) {
        return 0;
    }

    u8 *seen = tracked_tgids.lookup(&parent_tgid);
    if (!seen) {
        return 0;
    }

    u32 child_pid = (u32)args->child_pid;
    if (child_pid == 0) {
        return 0;
    }
    mark_tgid_tracked(child_pid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *event = reserve_event(EVENT_PROCESS_FORK, task, child_pid, child_pid, parent_tgid);
    if (!event) {
        return 0;
    }

    fill_task_uids(task, &event->uid, &event->euid);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

/*
 * 6. Hook sched_process_exit
 * Emits EVENT_PROCESS_EXIT when the thread group dies (signal->live.counter == 0,
 * fallback pid == tgid) for tracked processes to handle PID reuse cleanly.
 */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = (u32)id;
    u32 tgid = (u32)(id >> 32);

    if (tgid == 0) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bool is_group_exit = false;
    struct signal_struct *sig = NULL;
    if (task && bpf_probe_read_kernel(&sig, sizeof(sig), &task->signal) == 0 && sig) {
        int live = 0;
        if (bpf_probe_read_kernel(&live, sizeof(live), &sig->live.counter) == 0) {
            is_group_exit = (live == 0);
        } else {
            is_group_exit = (pid == tgid);
        }
    } else {
        is_group_exit = (pid == tgid);
    }

    if (!is_group_exit) {
        return 0;
    }

    u8 *seen = tracked_tgids.lookup(&tgid);
    if (!seen) {
        return 0;
    }

    struct event_t *event = reserve_event(EVENT_PROCESS_EXIT, task, pid, tgid, get_ppid(task));
    if (event) {
        fill_task_uids(task, &event->uid, &event->euid);
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        events.ringbuf_submit(event, 0);
    }
    tracked_tgids.delete(&tgid);
    return 0;
}
