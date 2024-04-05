from bcc import BPF
import ctypes as ct

program = r"""
#include <linux/tracepoint.h>
#include <linux/sched.h>

BPF_RINGBUF_OUTPUT(heap, 4096 * 64);

struct data_struct {
    char data[256];
};

struct heap_dump {
  int size;
  int doWrite;
  char data[4096 * 64]; // PAGE_SIZE * 4
};

//BPF_ARRAY(hd, struct heap_dump, 1);
BPF_TABLE_PINNED("array", int, struct heap_dump, hd, 1, "/sys/fs/bpf/my_counter_map");

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char filename[30];
    bpf_probe_read(filename, sizeof(filename), args->filename);

    char target_path[] = "/tmp/ready_to_checkpoint";
    if (__builtin_strcmp(target_path, filename) == 0)
    {
        bpf_trace_printk("openat called with file: %s \n", filename);
        //get tid
        u32 pid = bpf_get_current_pid_tgid();

        //get page table
        struct task_struct *t = (struct task_struct *)bpf_get_current_task();

        //get mm_struct
        struct mm_struct* mm = 0;
        bpf_probe_read_kernel(
        &mm,
        sizeof(mm),
        ((char *)t + offsetof(struct task_struct, mm))
        );

        //get heap (brk start, brk)
        long unsigned int start_brk, brk;
        bpf_probe_read_kernel(&start_brk,
        sizeof(start_brk),
        ((char *)mm + offsetof(struct mm_struct, start_brk))
        );
        bpf_probe_read_kernel(&brk,
        sizeof(brk),
        ((char *)mm + offsetof(struct mm_struct, brk))
        );
        bpf_trace_printk("heap starts at %lx and ends at %lx\n", start_brk, brk);

        //save heap
        int tile = 4096*4;
        int range = 0xFFF; // (brk - start_brk - 127500) & 0x3FFFF; // & 1048576;
        //heap.ringbuf_output(&data, sizeof(data), 0);
        bpf_trace_printk("range: %d\n", range);

        int idx = 0;
        struct heap_dump *ptr = hd.lookup(&idx);
        if(ptr == NULL)
            return -1;
        ptr->size = range;
        ptr->doWrite = 0;
        int i = 0, flag = 0;
        //for(; i<range; i += tile)
        {
            //bpf_trace_printk("reading from %d\n", sizeof(data.data));
            int out = bpf_probe_read(
            ptr->data,
            range,
            (void *)(start_brk + i)
            );
            heap.ringbuf_output(ptr, sizeof(*ptr), 0);
            bpf_trace_printk("read err: %d\n", out);
            /*if(out != 0) {
                if(!flag) {
                bpf_trace_printk("read err: %d\n", out);
                flag = 1;
                }
            }
            else if(flag)
                bpf_trace_printk("found valid data after some error: %d\n", out);
            */
            //bpf_trace_printk("data: %s\n", data.data);
            //if(out < 0)
            //    break;
        }
    }
    else {
        char target_path2[] = "/tmp/ready_to_restore";
        if (__builtin_strcmp(target_path2, filename) == 0)
        {
            bpf_trace_printk("openat called with file: %s \n", filename);
            //get tid
            //get page table
            struct task_struct *t = (struct task_struct *)bpf_get_current_task();

            //get mm_struct
            struct mm_struct* mm = 0;
            bpf_probe_read_kernel(
            &mm,
            sizeof(mm),
            ((char *)t + offsetof(struct task_struct, mm))
            );

            //get heap (brk start, brk)
            long unsigned int start_brk, brk;
            bpf_probe_read_kernel(&start_brk,
            sizeof(start_brk),
            ((char *)mm + offsetof(struct mm_struct, start_brk))
            );
            bpf_probe_read_kernel(&brk,
            sizeof(brk),
            ((char *)mm + offsetof(struct mm_struct, brk))
            );
            bpf_trace_printk("heap starts at %lx and ends at %lx\n", start_brk, brk);

            //write heap
            int range = (brk - start_brk - 127500) & 0x3FFFF; // & 1048576;
            bpf_trace_printk("range: %d\n", range);
            int idx = 0;
            struct heap_dump *ptr = hd.lookup(&idx);
            if(ptr == NULL)
                return -1;
            ptr->size = range;
            ptr->doWrite = 1;
            int out = bpf_probe_write_user(
            (void *)(start_brk),
            ptr->data,
            0xFFF
            );
            heap.ringbuf_output(ptr, sizeof(*ptr), 0);
            bpf_trace_printk("write err: %d\n", out);

        }
    }
    return 0;
}
"""

b = BPF(text=program, debug=0)  # 6
b.attach_tracepoint(
    "syscalls:sys_enter_openat", "tracepoint__syscalls__sys_enter_openat"
)


class HeapDump(ct.Structure):
    _fields_ = [
        ("size", ct.c_int),
        ("doWrite", ct.c_int),
        ("data", ct.c_byte * (4096 * 64)),
    ]


def save_data_to_file(data, filename):
    with open(filename, "wb") as f:
        f.write(data)


def read_data_from_file(filename):
    with open(filename, "rb") as f:
        return f.read()


def process_data(cpu, data, size):
    # event = b["heap"].event(data)
    event = ct.cast(data, ct.POINTER(HeapDump)).contents
    data_size = event.size
    data = bytes(event.data)[:data_size]
    # Process the event data here
    print("Received event:", len(data), data_size)
    if event.doWrite:
        save_data_to_file(b"", "/tmp/restore_complete")
    else:
        save_data_to_file(data, "data.bin")
        save_data_to_file(b"", "/tmp/checkpoint_complete")

        # Read data back from the file
        data_read = read_data_from_file("data.bin")

        # Verify if the data is the same
        print(data == data_read)


# Attach the Python function to the ring buffer
b["heap"].open_ring_buffer(process_data)
# b.trace_print()
while 1:
    try:
        b.ring_buffer_poll(30)
    except KeyboardInterrupt:
        exit()
