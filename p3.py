from bcc import BPF
import ctypes as ct

program = r"""
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/mman.h>

BPF_RINGBUF_OUTPUT(heap, 64);

struct data_struct {
    char data[256];
};

struct heap_dump {
  long addr;
  int size;
  int doWrite;
  char data[4096 * 64]; // PAGE_SIZE * 4
};

//BPF_ARRAY(hd, struct heap_dump, 1);
BPF_TABLE_PINNED("array", int, struct heap_dump, hd, 10, "/sys/fs/bpf/my_counter_map");

static unsigned int last_idx = 0;

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

        if(!mm)
            return 0;

        struct vm_area_struct *vma;
            bpf_probe_read_kernel(&vma,
            sizeof(vma),
            ((char *)mm + offsetof(struct mm_struct, mmap))
            );

        bpf_trace_printk("Process ID: %d\\n", pid);
        long unsigned int vma_start, vma_end, vma_flags;
        int c = 9999, range; //satisfy ebpf verifier
        while (vma && c>0) {
            c--;

            bpf_probe_read_kernel(&vma_start,
            sizeof(vma_start),
            ((char *)vma + offsetof(struct vm_area_struct, vm_start))
            );
            bpf_probe_read_kernel(&vma_end,
            sizeof(vma_end),
            ((char *)vma + offsetof(struct vm_area_struct, vm_end))
            );
            bpf_probe_read_kernel(&vma_flags,
            sizeof(vma_flags),
            ((char *)vma + offsetof(struct vm_area_struct, vm_flags))
            );

            // check if range is valid and vma is writable
            range = vma_end - vma_start;
            if(range > 0 && (vma_flags & PROT_WRITE)) {
                int idx = last_idx;
                if(idx > 999)
                    return -1;
                struct heap_dump *ptr = hd.lookup(&idx);
                if(ptr == NULL)
                    return -1;
                ptr->size = range;
                ptr->doWrite = 0;
                int err = bpf_probe_read(
                ptr->data,
                range,
                (void *)(vma_start)
                );
                bpf_trace_printk("read err code: %d", err);

                if(err>=0)
                    last_idx++;
                bpf_trace_printk("VMA Start: %lx, VMA End: %lx\\n", vma_start, vma_end);
            }

            // go to next vma
            bpf_probe_read_kernel(&vma,
            sizeof(vma),
            ((char *)vma + offsetof(struct vm_area_struct, vm_next))
            );

        }

    }
    else {
        char target_path2[] = "/tmp/ready_to_restore";
        /*if (__builtin_strcmp(target_path2, filename) == 0)
        {
            bpf_trace_printk("openat called with file: %s \n", filename);

            //write vma
            int idx = 0;
            for(; idx < last_idx && idx < 999; ++idx) {
                struct heap_dump *ptr = hd.lookup(&idx);
                if(ptr == NULL)
                    return -1;

            bpf_trace_printk("range: %d\n", range);
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
        */
    }
    return 0;
}
"""

b = BPF(text=program, debug=6)
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
