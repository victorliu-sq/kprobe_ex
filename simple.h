// transmit an ‘event’ over the ringbuffer whenever our bpf program is called
typedef struct process_info {
    int pid;
    char comm[100];
} proc_info;