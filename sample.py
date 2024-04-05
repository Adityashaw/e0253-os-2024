from bcc import BPF
import ctypes as ct

bpf_text = """
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long offset;
};

BPF_PERF_OUTPUT(events);

int kprobe__sys_mmap2(struct pt_regs *ctx, struct file *file, unsigned long addr,
                     unsigned long len, unsigned long prot, unsigned long flags)
{
    struct data_t data = {};

    // Retrieve process information
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.pid = bpf_get_current_pid_tgid();

    // Save mmap details
    data.addr = addr;
    data.len = len;
    data.prot = prot;
    data.flags = flags;

    // Send data to user space
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)


# Define data structure
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("addr", ct.c_ulonglong),
        ("len", ct.c_ulonglong),
        ("prot", ct.c_ulonglong),
        ("flags", ct.c_ulonglong),
        ("fd", ct.c_ulonglong),
        ("offset", ct.c_ulonglong),
    ]


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print(
        "PID: %d, COMM: %s, ADDR: %lx, LEN: %lx, PROT: %lx, FLAGS: %lx"
        % (
            event.pid,
            event.comm.decode(),
            event.addr,
            event.len,
            event.prot,
            event.flags,
        )
    )


# Attach event handler
b["events"].open_perf_buffer(print_event)

# Main loop
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
