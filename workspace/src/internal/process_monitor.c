//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

struct process_event {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 event_type; // 0=fork, 1=exec, 2=exit
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Helper to get parent PID
static __always_inline u32 get_ppid(struct task_struct *task)
{
    struct task_struct *parent;
    u32 ppid;
    
    parent = BPF_CORE_READ(task, real_parent);
    ppid = BPF_CORE_READ(parent, tgid);
    
    return ppid;
}

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_event event = {};
    struct task_struct *task;
    
    task = (struct task_struct *)bpf_get_current_task();
    
    event.pid = ctx->child_pid;
    event.ppid = BPF_CORE_READ(task, tgid);
    bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), ctx->child_comm);
    event.event_type = 0; // fork
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event event = {};
    struct task_struct *task;
    
    task = (struct task_struct *)bpf_get_current_task();
    
    event.pid = BPF_CORE_READ(task, tgid);
    event.ppid = get_ppid(task);
    bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), task->comm);
    event.event_type = 1; // exec
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char _license[] SEC("license") = "GPL";