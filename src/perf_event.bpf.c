#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct cpu_task
{
  u32 cpu_id;
  char task[16];
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct cpu_task);
  __type(value, u64);
} perf_cpu_instruction_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct cpu_task);
  __type(value, u64);
} perf_cpu_cycle_map SEC(".maps");

static int trace_event(void *map, struct cpu_task *cpu_task, u64 sample_period)
{
  increment_map(map, cpu_task, sample_period);

  return 0;
}

SEC("perf_event/type=0,config=0,frequency=1") // CPU/Task CPU cycle counter
int perf_cpu_cycle_counter(struct bpf_perf_event_data *ctx)
{
  struct cpu_task cpu_task = {.cpu_id = bpf_get_smp_processor_id()};
  bpf_get_current_comm(&cpu_task.task, sizeof(cpu_task.task));
  return trace_event(&perf_cpu_cycle_map, &cpu_task, ctx->sample_period);
}