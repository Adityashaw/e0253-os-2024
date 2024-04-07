from bcc import BPF
import ctypes as ct

program = r"""
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/mman.h>


BPF_RINGBUF_OUTPUT(rb, 4096*64);

struct heap_dump {
  unsigned long addr;
  unsigned int size;
  int doWrite;
  char data[4096 * 64]; // PAGE_SIZE * 4
};

struct task_alert {
    int read_or_write; // 0 => read done,  1 => write done
};

BPF_ARRAY(hd, struct heap_dump, 100);

static unsigned int last_idx = 0;

__always_inline static int string_check(char s1[30], char s2[30]) {
    int len = 30;
    int i = 0;
    if(!s1 || !s2)
        return 1;
    char a, b;
    for(; i<len; ++i) {
        a = *(s1+i);
        b = *(s2+i);
        if(!a && !b)
            return 0;
        //if(!a)
        //    return 1;
        //|| !b)
        //    return 1;
        if(a != b)
            return 1;
    }
    return 0;

}

__always_inline static int write_from_buff(const unsigned int *idx)
{
    if(*idx < 0)
        return 1;
    if(*idx > 99)
        return 1;
    struct heap_dump *ptr = hd.lookup(idx);
    if(!ptr)
        return 1;

    unsigned long size = ((ptr->size > 0) ? ptr->size : 0) & 0xFFFF;
    unsigned long addr = ((ptr->addr>0) ? ptr->addr : 0) & 0xFFFFFFFFFFFFFFFF;

    int doWrite = ptr->doWrite;
    if(!doWrite)
        return 1;
    if(addr >0) {
    if(size > 1) {
        bpf_trace_printk("addr %lx, size: %d\n", addr, size);
        int out = bpf_probe_write_user(
        (void *)(addr),
        ptr->data,
        size
        );
        bpf_trace_printk("write err: %d\n", out);
    }
    }
}

__always_inline static void clean_map() {

}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char filename[30];
    bpf_probe_read(filename, sizeof(filename), args->filename);

    char target_path[30] = "/tmp/ready_to_checkpoint";
    if (string_check(target_path, filename) == 0)
    {
        bpf_trace_printk("openat called with file: %s \n", filename);

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
		long unsigned int start_stack, start_brk;
            bpf_probe_read_kernel(&vma,
            sizeof(vma),
            ((char *)mm + offsetof(struct mm_struct, mmap))
            );
            bpf_probe_read_kernel(&start_stack,
            sizeof(start_stack),
            ((char *)mm + offsetof(struct mm_struct, start_stack))
            );
            bpf_probe_read_kernel(&start_brk,
            sizeof(start_brk),
            ((char *)mm + offsetof(struct mm_struct, start_brk))
            );

        long unsigned int vma_start, vma_end, vma_flags;
	    struct file *vma_file;
        int c = 99; unsigned long int range; //satisfy ebpf verifier
        unsigned int idx = 0;
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
            bpf_probe_read_kernel(&vma_file,
            sizeof(vma_file),
            ((char *)vma + offsetof(struct vm_area_struct, vm_file))
            );
            // go to next vma
            bpf_probe_read_kernel(&vma,
            sizeof(vma),
            ((char *)vma + offsetof(struct vm_area_struct, vm_next))
            );

            bpf_trace_printk("VMA Start: %lx", vma_start);
            // check if range is valid and vma is anon
            range = vma_end - vma_start;
            if(vma_start < start_brk) {
                bpf_trace_printk("%lx below brk %lx", vma_start, start_brk);
                continue;
            }
            if(vma_end > start_stack) {
                bpf_trace_printk("above base");
                continue;
            }
            /*if(vma_file)
                continue;
            */
            if((vma_flags & MAP_ANONYMOUS))
            {
                bpf_trace_printk("anon");
                if(idx > 99)
                    break;
                struct heap_dump *ptr = hd.lookup(&idx);
                if(ptr == NULL)
                    continue;
                ptr->addr = vma_start;
                ptr->doWrite = 0;
                unsigned long size = ((range > 0) ? range : 0) & 0xFFFF;
                ptr->size = size;
                bpf_trace_printk("VMA Start: %lx, VMA End: %lx", vma_start, vma_end);
                bpf_trace_printk("Actual Size: %lu New Size: %lu", range, size);
                int i=0, err_flag = 0;
                unsigned int tile = 0xFFFF;
                //for(; i+tile<size; i+=tile) {
                    //unsigned i_size = i+tile > size ? size - i : tile;
                    int err = bpf_probe_read(
                    ptr->data + i,
                    size,
                    (void *)((char *)(vma_start) + i)
                    );
                    bpf_trace_printk("read err code: %d", err);
                    if(err<0)
                    {
                        err_flag = 1;
                        continue;
                    }
                    else
                    {
                        ptr->doWrite = 1;
                    }

                //}
                //if(i < size) {

                //}
                    
                if(!err_flag)
                    idx +=1;
            }
            else
            {
                bpf_trace_printk("not anon");
            }

        }
        last_idx = idx;
        struct task_alert ta = {0};
        rb.ringbuf_output(&ta, sizeof(ta), 0);

    }
    else {
        char target_path2[30] = "/tmp/ready_to_restore";
        if (string_check(target_path2, filename) == 0)
        {
            bpf_trace_printk("openat called with file: %s \n", filename);
            
            //write vma

            // Iterate over the pinned array map
            //bpf_map_for_each_elem(&hd, ptr)
            int idx = 0;
            write_from_buff(&idx); 
            int c = 99;
            while(c>0) {
            write_from_buff(&idx);
            idx++;
            c = c - 1;
            }/*
            idx = 2;
            write_from_buff(&idx); 
            idx = 3;
            write_from_buff(&idx); 
            idx = 4;
            write_from_buff(&idx); 
            idx = 5;
            write_from_buff(&idx); 
            idx = 6;
            write_from_buff(&idx); 
            idx = 7;
            write_from_buff(&idx); 
            idx = 8;
            write_from_buff(&idx); 
            idx = 9;
            write_from_buff(&idx); 
*/
            struct task_alert ta = {1};
            rb.ringbuf_output(&ta, sizeof(ta), 0);
        }
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
        ("addr", ct.c_long),
        ("size", ct.c_int),
        ("doWrite", ct.c_int),
        ("data", ct.c_byte * (4096)),
    ]


def save_data_to_file(data, filename):
    with open(filename, "wb") as f:
        f.write(data)


def delete_file(file_path):
    try:
        os.remove(file_path)
        print(f"File {file_path} deleted successfully.")
    except OSError as e:
        print(f"Error deleting file {file_path}: {e.strerror}")


def read_data_from_file(filename):
    with open(filename, "rb") as f:
        return f.read()

def process_data2(cpu, data, size):
    event = b["rb"].event(data)
    # Process the event data here
    print("Received event:", event.read_or_write)
    if event.read_or_write:
        save_data_to_file(b"", "/tmp/restore_complete")
    else:
        save_data_to_file(b"", "/tmp/checkpoint_complete")


def process_data(cpu, data, size):
    # event = b["heap"].event(data)
    event = ct.cast(data, ct.POINTER(HeapDump)).contents
    data_size = event.size
    data = bytes(event.data)[:data_size]
    # Process the event data here
    print("Received event:", len(data), data_size)
    if event.doWrite:
        file_path = "/tmp/ready_to_restore"
        delete_file(file_path)
        save_data_to_file(b"", "/tmp/restore_complete")
    else:
        file_path = "/tmp/ready_to_checkpoint"
        delete_file(file_path)
        save_data_to_file(data, "data.bin")
        save_data_to_file(b"", "/tmp/checkpoint_complete")

        # Read data back from the file
        data_read = read_data_from_file("data.bin")

        # Verify if the data is the same
        print(data == data_read)


# Attach the Python function to the ring buffer
b["rb"].open_ring_buffer(process_data2)
# b.trace_print()
while 1:
    try:
        b.ring_buffer_poll(30)
    except KeyboardInterrupt:
        exit()
