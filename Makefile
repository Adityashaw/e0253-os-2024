CC := gcc
CFLAGS := -O3
LDFLAGS := 
ALL := testcase

all: $(ALL)

clean:
	rm -f $(ALL)

something:
	sudo bpftool map create /sys/fs/bpf/my_counter_map type array key 4 value 128 entries 1000 name hd
