//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 512

// Event types - Process Events
#define EVENT_PROCESS_EXEC 1
#define EVENT_PROCESS_EXIT 2
#define EVENT_PROCESS_FORK 3
#define EVENT_PROCESS_SETUID 4
#define EVENT_PROCESS_SETGID 5
#define EVENT_PROCESS_PTRACE 6
#define EVENT_PROCESS_PRCTL 7
#define EVENT_PROCESS_MEMFD 8
#define EVENT_PROCESS_MMAP 9
#define EVENT_PROCESS_MPROTECT 10

// Event types - File Events
#define EVENT_FILE_OPEN 20
#define EVENT_FILE_CREATE 21
#define EVENT_FILE_DELETE 22
#define EVENT_FILE_RENAME 23
#define EVENT_FILE_CHMOD 24
#define EVENT_FILE_CHOWN 25
#define EVENT_FILE_LINK 26
#define EVENT_FILE_SYMLINK 27
#define EVENT_FILE_TRUNCATE 28
#define EVENT_FILE_SETXATTR 29
#define EVENT_FILE_REMOVEXATTR 30

// Event types - Network Events
#define EVENT_NET_CONNECT 40
#define EVENT_NET_BIND 41
#define EVENT_NET_LISTEN 42
#define EVENT_NET_ACCEPT 43
#define EVENT_NET_SENDMSG 44
#define EVENT_NET_RECVMSG 45

// Event types - Module/Driver Events
#define EVENT_MODULE_LOAD 60
#define EVENT_MODULE_UNLOAD 61
#define EVENT_BPF_LOAD 62
#define EVENT_BPF_ATTACH 63

// Process event structure
struct process_event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 euid;
    __u32 egid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS_LEN];
    char cwd[MAX_FILENAME_LEN];
    __u64 timestamp;
    __s64 ret;
};

// File event structure
struct file_event {
    __u32 type;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char target_path[MAX_FILENAME_LEN];
    __u32 mode;
    __u32 flags;
    __u64 timestamp;
    __u64 size;
    __s64 ret;
};

// Network event structure
struct network_event {
    __u32 type;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u8 src_addr[16];
    __u8 dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 family;
    __u64 timestamp;
    __s64 ret;
};

// Module event structure
struct module_event {
    __u32 type;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char name[MAX_FILENAME_LEN];
    __u64 timestamp;
    __s64 ret;
};

// Mmap event structure
struct mmap_event {
    __u32 type;
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u64 addr;
    __u64 length;
    __u32 prot;
    __u32 flags;
    __s32 fd;
    char filename[MAX_FILENAME_LEN];
    __u64 timestamp;
};

// Ptrace event structure
struct ptrace_event {
    __u32 type;
    __u32 pid;
    __u32 target_pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u32 request;
    __u64 timestamp;
    __s64 ret;
};

// Perf event array
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Per-CPU temporary storage for large event structures (to avoid stack overflow)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_event);
} process_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_event);
} file_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct network_event);
} network_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct module_event);
} module_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mmap_event);
} mmap_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ptrace_event);
} ptrace_heap SEC(".maps");

// Helper to read filename from user space
static __always_inline long read_filename(char *dest, const char *filename) {
    long ret = bpf_probe_read_user_str(dest, MAX_FILENAME_LEN, filename);
    if (ret < 0) {
        dest[0] = '\0';
        return ret;
    }
    return 0;
}

// Helper to get credentials
static __always_inline void get_creds(struct process_event *event) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *cred;
    
    BPF_CORE_READ_INTO(&cred, task, real_cred);
    BPF_CORE_READ_INTO(&event->uid, cred, uid.val);
    BPF_CORE_READ_INTO(&event->gid, cred, gid.val);
    BPF_CORE_READ_INTO(&event->euid, cred, euid.val);
    BPF_CORE_READ_INTO(&event->egid, cred, egid.val);
}

// Process: execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct process_event *event = bpf_map_lookup_elem(&process_heap, &key);
    if (!event)
        return 0;
    
    // Per-CPU maps return zeroed memory, but explicitly set key fields
    event->type = EVENT_PROCESS_EXEC;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&event->ppid, task, real_parent, tgid);
    
    get_creds(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename = (const char *)ctx->args[0];
    read_filename(event->filename, filename);
    
    // Try to read first argument
    const char **argv = (const char **)ctx->args[1];
    const char *arg;
    if (bpf_probe_read_user(&arg, sizeof(arg), &argv[0]) == 0) {
        bpf_probe_read_user_str(event->args, MAX_ARGS_LEN, arg);
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Process: exit
SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_exit_group(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct process_event *event = bpf_map_lookup_elem(&process_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_PROCESS_EXIT;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Process: fork/clone
SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct process_event *event = bpf_map_lookup_elem(&process_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_PROCESS_FORK;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&event->ppid, task, tgid);
    
    get_creds(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Process: setuid
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct process_event *event = bpf_map_lookup_elem(&process_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_PROCESS_SETUID;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    get_creds(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->euid = (__u32)ctx->args[0];
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Process: setgid
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct process_event *event = bpf_map_lookup_elem(&process_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_PROCESS_SETGID;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    get_creds(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->egid = (__u32)ctx->args[0];
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Process: ptrace
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct ptrace_event *event = bpf_map_lookup_elem(&ptrace_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_PROCESS_PTRACE;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->target_pid = (__u32)ctx->args[1];
    event->request = (__u32)ctx->args[0];
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Process: prctl
SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct process_event *event = bpf_map_lookup_elem(&process_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_PROCESS_PRCTL;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    get_creds(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Process: memfd_create
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct process_event *event = bpf_map_lookup_elem(&process_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_PROCESS_MEMFD;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    get_creds(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *name = (const char *)ctx->args[0];
    read_filename(event->filename, name);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Process: mmap
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
    __u32 prot = (__u32)ctx->args[2];
    
    // Only report executable mappings
    if (!(prot & 0x4)) // PROT_EXEC
        return 0;
    
    __u32 key = 0;
    struct mmap_event *event = bpf_map_lookup_elem(&mmap_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_PROCESS_MMAP;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->addr = (__u64)ctx->args[0];
    event->length = (__u64)ctx->args[1];
    event->prot = prot;
    event->flags = (__u32)ctx->args[3];
    event->fd = (__s32)ctx->args[4];
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Process: mprotect
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx) {
    __u32 prot = (__u32)ctx->args[2];
    
    // Only report if making memory executable
    if (!(prot & 0x4)) // PROT_EXEC
        return 0;
    
    __u32 key = 0;
    struct process_event *event = bpf_map_lookup_elem(&process_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_PROCESS_MPROTECT;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    get_creds(event);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// File: openat
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_OPEN;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->flags = (__u32)ctx->args[2];
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename = (const char *)ctx->args[1];
    read_filename(event->filename, filename);
    
    // Check if creating file
    if (event->flags & 0x40) // O_CREAT
        event->type = EVENT_FILE_CREATE;
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// File: unlinkat
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_DELETE;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename = (const char *)ctx->args[1];
    read_filename(event->filename, filename);
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// File: renameat2
SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_RENAME;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *oldname = (const char *)ctx->args[1];
    const char *newname = (const char *)ctx->args[3];
    read_filename(event->filename, oldname);
    read_filename(event->target_path, newname);
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// File: fchmodat
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_CHMOD;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->mode = (__u32)ctx->args[2];
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename = (const char *)ctx->args[1];
    read_filename(event->filename, filename);
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// File: fchownat
SEC("tracepoint/syscalls/sys_enter_fchownat")
int trace_fchownat(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_CHOWN;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename = (const char *)ctx->args[1];
    read_filename(event->filename, filename);
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// File: linkat
SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_linkat(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_LINK;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *oldname = (const char *)ctx->args[1];
    const char *newname = (const char *)ctx->args[3];
    read_filename(event->filename, oldname);
    read_filename(event->target_path, newname);
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// File: symlinkat
SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_SYMLINK;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *target = (const char *)ctx->args[0];
    const char *linkpath = (const char *)ctx->args[2];
    read_filename(event->filename, target);
    read_filename(event->target_path, linkpath);
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// File: truncate
SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_truncate(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_TRUNCATE;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->size = (__u64)ctx->args[1];
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename = (const char *)ctx->args[0];
    read_filename(event->filename, filename);
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// File: setxattr
SEC("tracepoint/syscalls/sys_enter_setxattr")
int trace_setxattr(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_SETXATTR;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename = (const char *)ctx->args[0];
    read_filename(event->filename, filename);
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// File: removexattr
SEC("tracepoint/syscalls/sys_enter_removexattr")
int trace_removexattr(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *event = bpf_map_lookup_elem(&file_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_FILE_REMOVEXATTR;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename = (const char *)ctx->args[0];
    read_filename(event->filename, filename);
    
    if (event->filename[0] != '\0') {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// Network: connect
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct network_event *event = bpf_map_lookup_elem(&network_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_NET_CONNECT;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Network: bind
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct network_event *event = bpf_map_lookup_elem(&network_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_NET_BIND;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Network: listen
SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct network_event *event = bpf_map_lookup_elem(&network_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_NET_LISTEN;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Network: accept
SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct network_event *event = bpf_map_lookup_elem(&network_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_NET_ACCEPT;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Network: sendmsg (commented out - high frequency)
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    // High frequency - consider enabling only when needed
    return 0;
}

// Network: recvmsg (commented out - high frequency)
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    // High frequency - consider enabling only when needed
    return 0;
}

// Module: init_module
SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct module_event *event = bpf_map_lookup_elem(&module_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_MODULE_LOAD;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// Module: delete_module
SEC("tracepoint/syscalls/sys_enter_delete_module")
int trace_delete_module(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct module_event *event = bpf_map_lookup_elem(&module_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_MODULE_UNLOAD;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *name = (const char *)ctx->args[0];
    read_filename(event->name, name);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// BPF: bpf() syscall
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx) {
    __u32 cmd = (__u32)ctx->args[0];
    
    // Only monitor BPF_PROG_LOAD (5)
    if (cmd != 5)
        return 0;
    
    __u32 key = 0;
    struct module_event *event = bpf_map_lookup_elem(&module_heap, &key);
    if (!event)
        return 0;
    
    event->type = EVENT_BPF_LOAD;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";