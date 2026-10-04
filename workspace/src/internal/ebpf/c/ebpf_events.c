// internal/ebpf/c/ebpf_events.c
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License
//
// eBPF event collection for Vajra EDR.
// Minimum kernel version: 5.11
// Compiled with: clang -O2 -g -target bpf
//
// Design principles:
//   - All structs have explicit pad fields — no implicit alignment surprises.
//   - Per-CPU heap maps for all structs — eBPF stack is only 512 bytes.
//   - Single perf event array for all output — one reader in Go.
//   - Kernel-side filtering is minimal — complex decisions belong in Go.
//   - Only emit events that have genuine security value at this layer.

// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ============================================================
// Constants
// ============================================================

#define TASK_COMM_LEN 16
#define PATH_MAX 256
#define ARGS_MAX 512
#define DNS_PAYLOAD_MAX 256

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef O_CREAT
#define O_CREAT 0100
#endif

#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif
#ifndef SOCK_PACKET
#define SOCK_PACKET 10
#endif

// ============================================================
// Event type constants.
// These MUST match the constants in internal/ebpf/types.go.
// ============================================================

// Process events
#define EVT_PROCESS_EXEC 1
#define EVT_PROCESS_SETUID 4
#define EVT_PROCESS_SETGID 5
#define EVT_PROCESS_PTRACE 6
#define EVT_PROCESS_MEMFD 8
#define EVT_PROCESS_MMAP 9
#define EVT_PROCESS_MPROTECT 10
#define EVT_PROCESS_CAPSET 11

// File events
#define EVT_FILE_OPEN 20
#define EVT_FILE_DELETE 22
#define EVT_FILE_RENAME 23
#define EVT_FILE_CHMOD 24

// Network events
#define EVT_NET_CONNECT 40
#define EVT_NET_BIND 41
#define EVT_NET_DNS 46
#define EVT_NET_RAW_SOCK 47
#define EVT_NET_PACKET 48

// Module events
#define EVT_MODULE_LOAD 60

// Namespace events
#define EVT_NS_CREATE 70
#define EVT_NS_ENTER 71

// ============================================================
// Structs
//
// Explicit pad fields are named _padN.
// Sizes are chosen so each struct is a multiple of 8 bytes.
// Go's binary.Read with LittleEndian will read these exactly.
// ============================================================

// process_event: exec, setuid, setgid, memfd_create.
// Size: 4+4+4+4+4+4+4+16+256+512+256+4+4+8+8 = 1096 bytes
struct process_event {
  __u32 type;
  __u32 pid;
  __u32 ppid;
  __u32 uid;
  __u32 gid;
  __u32 euid;
  __u32 egid;
  char comm[TASK_COMM_LEN]; // 16 bytes
  char filename[PATH_MAX];  // 256 bytes
  char args[ARGS_MAX];      // 512 bytes
  char cwd[PATH_MAX];       // 256 bytes
  __u32 _pad0;              // explicit pad to align timestamp to 8 bytes
  __u32 flags;              // reused: open flags for memfd, 0 otherwise
  __u64 timestamp;
  __s64 ret;
};

// file_event: openat (O_CREAT only), unlinkat, renameat2, fchmodat.
// Size: 4+4+4+4+16+256+256+4+4+8+8+8 = 580 bytes
struct file_event {
  __u32 type;
  __u32 pid;
  __u32 uid;
  __u32 gid;
  char comm[TASK_COMM_LEN];   // 16 bytes
  char filename[PATH_MAX];    // 256 bytes
  char target_path[PATH_MAX]; // 256 bytes — rename destination, empty otherwise
  __u32 mode;                 // chmod mode, 0 otherwise
  __u32 flags;                // open flags
  __u64 timestamp;
  __u64 size; // file size for truncate, 0 otherwise
  __s64 ret;
};

// network_event: connect, bind, raw/packet socket.
// Size: 4+4+4+4+16+16+16+2+2+1+1+2+8+8 = 88 bytes
struct network_event {
  __u32 type;
  __u32 pid;
  __u32 uid;
  __u32 gid;
  char comm[TASK_COMM_LEN]; // 16 bytes
  __u8 src_addr[16];
  __u8 dst_addr[16];
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol;
  __u8 family;
  __u8 _pad0[2]; // align timestamp to 8 bytes
  __u64 timestamp;
  __s64 ret;
};

// mmap_event: mmap (PROT_EXEC only), mprotect (PROT_EXEC only).
// Size: 4+4+4+16+4+8+8+4+4+4+4+256+8 = 336 bytes
struct mmap_event {
  __u32 type;
  __u32 pid;
  __u32 uid;
  char comm[TASK_COMM_LEN]; // 16 bytes
  __u32 _pad0;              // align addr to 8 bytes
  __u64 addr;
  __u64 length;
  __u32 prot;
  __u32 map_flags;
  __s32 fd;
  __u32 _pad1;             // align filename to natural boundary
  char filename[PATH_MAX]; // 256 bytes
  __u64 timestamp;
};

// ptrace_event: ptrace only.
// Size: 4+4+4+4+16+4+4+8+8 = 56 bytes
struct ptrace_event {
  __u32 type;
  __u32 pid;
  __u32 target_pid;
  __u32 uid;
  char comm[TASK_COMM_LEN]; // 16 bytes
  __u32 request;
  __u32 _pad0; // align timestamp to 8 bytes
  __u64 timestamp;
  __s64 ret;
};

// capset_event: capset only.
// Size: 4+4+4+16+4+8+8+8+8+8 = 72 bytes
struct capset_event {
  __u32 type;
  __u32 pid;
  __u32 uid;
  char comm[TASK_COMM_LEN]; // 16 bytes
  __u32 _pad0;              // align effective to 8 bytes
  __u64 effective;
  __u64 permitted;
  __u64 inheritable;
  __u64 timestamp;
  __s64 ret;
};

// namespace_event: unshare, setns.
// Size: 4+4+4+16+4+4+8+8 = 52, pad to 56
struct namespace_event {
  __u32 type;
  __u32 pid;
  __u32 uid;
  char comm[TASK_COMM_LEN]; // 16 bytes
  __u32 ns_type;
  __u32 flags;
  __u64 timestamp;
  __s64 ret;
};

// module_event: init_module, finit_module.
// Size: 4+4+4+4+16+256+8+8 = 304 bytes
struct module_event {
  __u32 type;
  __u32 pid;
  __u32 uid;
  __u32 gid;
  char comm[TASK_COMM_LEN]; // 16 bytes
  char name[PATH_MAX];      // 256 bytes
  __u64 timestamp;
  __s64 ret;
};

// dns_event_raw: DNS payload captured for gopacket parsing in Go.
// Size: 4+4+8+16+4+4+256 = 296 bytes
struct dns_event_raw {
  __u32 type;
  __u32 pid;
  __u64 timestamp;
  char comm[TASK_COMM_LEN]; // 16 bytes
  __u32 uid;
  __u32 payload_len;
  char payload[DNS_PAYLOAD_MAX]; // 256 bytes
};

// ============================================================
// Compat structs for reading userspace sockaddr.
// We define these ourselves — vmlinux sockaddr internals
// differ across kernel versions and we only need port/addr.
// ============================================================

struct sockaddr_in_compat {
  __u16 sin_family;
  __be16 sin_port;
  __be32 sin_addr;
  __u8 _pad[8];
};

struct sockaddr_in6_compat {
  __u16 sin6_family;
  __be16 sin6_port;
  __u32 sin6_flowinfo;
  __u8 sin6_addr[16];
  __u32 sin6_scope_id;
};

struct msghdr_compat {
  void *msg_name;
  int msg_namelen;
  struct iovec *msg_iov;
  __kernel_size_t msg_iovlen;
  void *msg_control;
  __kernel_size_t msg_controllen;
  unsigned int msg_flags;
};
// ============================================================
// Maps
// ============================================================

// Single output channel to Go userspace.
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Per-CPU scratch space — one map per struct type.
// Index 0 is always used; per-CPU means no locking needed.

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
  __type(value, struct mmap_event);
} mmap_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct ptrace_event);
} ptrace_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct capset_event);
} capset_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct namespace_event);
} namespace_heap SEC(".maps");

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
  __type(value, struct dns_event_raw);
} dns_heap SEC(".maps");

// ============================================================
// Helpers
// ============================================================

// get_creds reads uid/gid/euid/egid from the current task.
// Uses bpf_get_current_task_btf() available since kernel 5.11.
static __always_inline void get_creds(__u32 *uid, __u32 *gid, __u32 *euid,
                                      __u32 *egid) {
  struct task_struct *task = bpf_get_current_task_btf();
  const struct cred *cred = BPF_CORE_READ(task, cred);

  if (uid)
    *uid = BPF_CORE_READ(cred, uid.val);
  if (gid)
    *gid = BPF_CORE_READ(cred, gid.val);
  if (euid)
    *euid = BPF_CORE_READ(cred, euid.val);
  if (egid)
    *egid = BPF_CORE_READ(cred, egid.val);
}

// get_ppid reads the parent process TGID from current task.
static __always_inline __u32 get_ppid(void) {
  struct task_struct *task = bpf_get_current_task_btf();
  struct task_struct *parent = BPF_CORE_READ(task, real_parent);
  return BPF_CORE_READ(parent, tgid);
}

// emit_process_event fills and sends a process_event.
static __always_inline int emit_process_event(void *ctx, __u32 type,
                                              __u32 flags,
                                              const char *filename_ptr,
                                              const char *args_ptr) {
  __u32 zero = 0;
  struct process_event *e = bpf_map_lookup_elem(&process_heap, &zero);
  if (!e)
    return 0;

  e->type = type;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->ppid = get_ppid();
  e->timestamp = bpf_ktime_get_ns();
  e->flags = flags;
  e->_pad0 = 0;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, &e->euid, &e->egid);

  if (filename_ptr)
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
  else
    e->filename[0] = '\0';

  if (args_ptr)
    bpf_probe_read_user_str(e->args, sizeof(e->args), args_ptr);
  else
    e->args[0] = '\0';

  // cwd: read from task fs struct
  struct task_struct *task = bpf_get_current_task_btf();
  struct fs_struct *fs = BPF_CORE_READ(task, fs);
  struct dentry *dentry = BPF_CORE_READ(fs, pwd.dentry);
  const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
  bpf_probe_read_kernel_str(e->cwd, sizeof(e->cwd), name);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

// handle_dns_traffic captures raw DNS payload for gopacket parsing.
static __always_inline int handle_dns_traffic(void *ctx, const char *buf,
                                              __u32 len) {
  if (len < 12)
    return 0;

  __u32 zero = 0;
  struct dns_event_raw *e = bpf_map_lookup_elem(&dns_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_NET_DNS;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp = bpf_ktime_get_ns();
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  __u32 uid, gid;
  get_creds(&uid, &gid, NULL, NULL);
  e->uid = uid;

  __u32 copy_len = len > DNS_PAYLOAD_MAX ? DNS_PAYLOAD_MAX : len;
  e->payload_len = copy_len;
  bpf_probe_read_user(e->payload, copy_len, buf);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

// ============================================================
// Tracepoints — Process
// ============================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
  const char *filename = (const char *)ctx->args[0];
  // args[1] is argv — we read the first element only for space reasons
  const char *const *argv = (const char *const *)ctx->args[1];
  const char *first_arg = NULL;
  bpf_probe_read_user(&first_arg, sizeof(first_arg), &argv[1]);

  return emit_process_event(ctx, EVT_PROCESS_EXEC, 0, filename, first_arg);
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx) {
  return emit_process_event(ctx, EVT_PROCESS_SETUID, 0, NULL, NULL);
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx) {
  return emit_process_event(ctx, EVT_PROCESS_SETGID, 0, NULL, NULL);
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx) {
  const char *name = (const char *)ctx->args[0];
  __u32 flags = (__u32)ctx->args[1];
  return emit_process_event(ctx, EVT_PROCESS_MEMFD, flags, name, NULL);
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct ptrace_event *e = bpf_map_lookup_elem(&ptrace_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_PROCESS_PTRACE;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->target_pid = (__u32)ctx->args[1];
  e->request = (__u32)ctx->args[0];
  e->timestamp = bpf_ktime_get_ns();
  e->_pad0 = 0;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, NULL, NULL, NULL);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
  __u32 prot = (__u32)ctx->args[2];
  if (!(prot & PROT_EXEC))
    return 0; // only executable mappings

  __u32 zero = 0;
  struct mmap_event *e = bpf_map_lookup_elem(&mmap_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_PROCESS_MMAP;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp = bpf_ktime_get_ns();
  e->addr = (__u64)ctx->args[0];
  e->length = (__u64)ctx->args[1];
  e->prot = prot;
  e->map_flags = (__u32)ctx->args[3];
  e->fd = (__s32)ctx->args[4];
  e->_pad0 = 0;
  e->_pad1 = 0;
  e->filename[0] = '\0';

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, NULL, NULL, NULL);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx) {
  __u32 prot = (__u32)ctx->args[2];
  if (!(prot & PROT_EXEC))
    return 0; // only when adding execute permission

  __u32 zero = 0;
  struct mmap_event *e = bpf_map_lookup_elem(&mmap_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_PROCESS_MPROTECT;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp = bpf_ktime_get_ns();
  e->addr = (__u64)ctx->args[0];
  e->length = (__u64)ctx->args[1];
  e->prot = prot;
  e->map_flags = 0;
  e->fd = -1;
  e->_pad0 = 0;
  e->_pad1 = 0;
  e->filename[0] = '\0';

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, NULL, NULL, NULL);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct capset_event *e = bpf_map_lookup_elem(&capset_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_PROCESS_CAPSET;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp = bpf_ktime_get_ns();
  e->_pad0 = 0;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, NULL, NULL, NULL);

  // kernel_cap_t on kernels >= 6.3 is a plain __u64, not a
  // struct with a cap[] array. Read the whole value directly.
  struct task_struct *task = bpf_get_current_task_btf();
  const struct cred *cred = BPF_CORE_READ(task, cred);

  kernel_cap_t eff, perm, inh;
  BPF_CORE_READ_INTO(&eff, cred, cap_effective);
  BPF_CORE_READ_INTO(&perm, cred, cap_permitted);
  BPF_CORE_READ_INTO(&inh, cred, cap_inheritable);

  // kernel_cap_t is __u64 on modern kernels — cast directly.
  e->effective = *(__u64 *)&eff;
  e->permitted = *(__u64 *)&perm;
  e->inheritable = *(__u64 *)&inh;

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}
// ============================================================
// Tracepoints — File
// ============================================================

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
  __u32 flags = (__u32)ctx->args[2];
  if (!(flags & O_CREAT))
    return 0; // only new file creation

  __u32 zero = 0;
  struct file_event *e = bpf_map_lookup_elem(&file_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_FILE_OPEN;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->flags = flags;
  e->mode = (__u32)ctx->args[3];
  e->timestamp = bpf_ktime_get_ns();
  e->size = 0;
  e->target_path[0] = '\0';

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, NULL, NULL);

  const char *filename = (const char *)ctx->args[1];
  bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct file_event *e = bpf_map_lookup_elem(&file_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_FILE_DELETE;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->flags = 0;
  e->mode = 0;
  e->timestamp = bpf_ktime_get_ns();
  e->size = 0;
  e->target_path[0] = '\0';

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, NULL, NULL);

  const char *filename = (const char *)ctx->args[1];
  bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct file_event *e = bpf_map_lookup_elem(&file_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_FILE_RENAME;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->flags = (__u32)ctx->args[4];
  e->mode = 0;
  e->timestamp = bpf_ktime_get_ns();
  e->size = 0;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, NULL, NULL);

  const char *oldpath = (const char *)ctx->args[1];
  const char *newpath = (const char *)ctx->args[3];
  bpf_probe_read_user_str(e->filename, sizeof(e->filename), oldpath);
  bpf_probe_read_user_str(e->target_path, sizeof(e->target_path), newpath);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct file_event *e = bpf_map_lookup_elem(&file_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_FILE_CHMOD;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->flags = 0;
  e->mode = (__u32)ctx->args[2];
  e->timestamp = bpf_ktime_get_ns();
  e->size = 0;
  e->target_path[0] = '\0';

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, NULL, NULL);

  const char *filename = (const char *)ctx->args[1];
  bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

// ============================================================
// Tracepoints — Network
// ============================================================

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct network_event *e = bpf_map_lookup_elem(&network_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_NET_CONNECT;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp = bpf_ktime_get_ns();
  e->_pad0[0] = 0;
  e->_pad0[1] = 0;
  e->src_port = 0;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, NULL, NULL);

  struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
  if (!addr)
    return 0;

  __u16 family = 0;
  bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
  e->family = (__u8)family;

  if (family == AF_INET) {
    struct sockaddr_in_compat a;
    bpf_probe_read_user(&a, sizeof(a), addr);
    e->dst_port = __builtin_bswap16(a.sin_port);
    __builtin_memcpy(e->dst_addr, &a.sin_addr, 4);
  } else if (family == AF_INET6) {
    struct sockaddr_in6_compat a;
    bpf_probe_read_user(&a, sizeof(a), addr);
    e->dst_port = __builtin_bswap16(a.sin6_port);
    __builtin_memcpy(e->dst_addr, a.sin6_addr, 16);
  } else {
    return 0;
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct network_event *e = bpf_map_lookup_elem(&network_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_NET_BIND;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp = bpf_ktime_get_ns();
  e->_pad0[0] = 0;
  e->_pad0[1] = 0;
  e->dst_port = 0;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, NULL, NULL);

  struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
  if (!addr)
    return 0;

  __u16 family = 0;
  bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
  e->family = (__u8)family;

  if (family == AF_INET) {
    struct sockaddr_in_compat a;
    bpf_probe_read_user(&a, sizeof(a), addr);
    e->src_port = __builtin_bswap16(a.sin_port);
    __builtin_memcpy(e->src_addr, &a.sin_addr, 4);
  } else if (family == AF_INET6) {
    struct sockaddr_in6_compat a;
    bpf_probe_read_user(&a, sizeof(a), addr);
    e->src_port = __builtin_bswap16(a.sin6_port);
    __builtin_memcpy(e->src_addr, a.sin6_addr, 16);
  } else {
    return 0;
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx) {
  int sock_type = (int)ctx->args[1];
  if (sock_type != SOCK_RAW && sock_type != SOCK_PACKET)
    return 0;

  __u32 zero = 0;
  struct network_event *e = bpf_map_lookup_elem(&network_heap, &zero);
  if (!e)
    return 0;

  e->type = (sock_type == SOCK_RAW) ? EVT_NET_RAW_SOCK : EVT_NET_PACKET;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp = bpf_ktime_get_ns();
  e->family = (__u8)ctx->args[0];
  e->protocol = (__u8)ctx->args[2];
  e->src_port = 0;
  e->dst_port = 0;
  e->_pad0[0] = 0;
  e->_pad0[1] = 0;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, NULL, NULL);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
  const void *buf = (const void *)ctx->args[1];
  __u32 len = (__u32)ctx->args[2];

  if (len < 12 || !buf)
    return 0;

  struct sockaddr *dest = (struct sockaddr *)ctx->args[4];
  if (!dest)
    return 0;

  __u16 family = 0;
  bpf_probe_read_user(&family, sizeof(family), &dest->sa_family);

  __u16 port = 0;
  if (family == AF_INET) {
    struct sockaddr_in_compat a;
    bpf_probe_read_user(&a, sizeof(a), dest);
    port = __builtin_bswap16(a.sin_port);
  } else if (family == AF_INET6) {
    struct sockaddr_in6_compat a;
    bpf_probe_read_user(&a, sizeof(a), dest);
    port = __builtin_bswap16(a.sin6_port);
  }

  if (port != 53)
    return 0;
  return handle_dns_traffic(ctx, buf, len);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx) {
  struct msghdr_compat *msg = (struct msghdr_compat *)ctx->args[1];
  if (!msg)
    return 0;

  void *name_ptr = NULL;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &msg->msg_name);
  if (!name_ptr)
    return 0;

  __u16 family = 0;
  bpf_probe_read_user(&family, sizeof(family), name_ptr);

  __u16 port = 0;
  if (family == AF_INET) {
    struct sockaddr_in_compat a;
    bpf_probe_read_user(&a, sizeof(a), name_ptr);
    port = __builtin_bswap16(a.sin_port);
  } else if (family == AF_INET6) {
    struct sockaddr_in6_compat a;
    bpf_probe_read_user(&a, sizeof(a), name_ptr);
    port = __builtin_bswap16(a.sin6_port);
  }

  if (port != 53)
    return 0;

  struct iovec *iov_ptr = NULL;
  bpf_probe_read_kernel(&iov_ptr, sizeof(iov_ptr), &msg->msg_iov);
  if (!iov_ptr)
    return 0;

  struct iovec iov;
  bpf_probe_read_user(&iov, sizeof(iov), iov_ptr);
  if (!iov.iov_base || iov.iov_len < 12)
    return 0;

  return handle_dns_traffic(ctx, iov.iov_base, (__u32)iov.iov_len);
}

// ============================================================
// Tracepoints — Module
// ============================================================

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct module_event *e = bpf_map_lookup_elem(&module_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_MODULE_LOAD;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp = bpf_ktime_get_ns();

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, NULL, NULL);
  e->name[0] = '\0';

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct module_event *e = bpf_map_lookup_elem(&module_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_MODULE_LOAD;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp = bpf_ktime_get_ns();

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, &e->gid, NULL, NULL);
  e->name[0] = '\0';

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

// ============================================================
// Tracepoints — Namespace
// ============================================================

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct namespace_event *e = bpf_map_lookup_elem(&namespace_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_NS_CREATE;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->flags = (__u32)ctx->args[0];
  e->ns_type = 0;
  e->timestamp = bpf_ktime_get_ns();

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, NULL, NULL, NULL);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx) {
  __u32 zero = 0;
  struct namespace_event *e = bpf_map_lookup_elem(&namespace_heap, &zero);
  if (!e)
    return 0;

  e->type = EVT_NS_ENTER;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->ns_type = (__u32)ctx->args[1];
  e->flags = 0;
  e->timestamp = bpf_ktime_get_ns();

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  get_creds(&e->uid, NULL, NULL, NULL);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
