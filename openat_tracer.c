#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// define a structure to hold data to be collected
struct data_t 
{
    u32 uid;  // User ID
    char comm[TASK_COMM_LEN];  // The current process name
    char fname[NAME_MAX];  // File name
    int flags;  // Flags indicating mode of file access
};

BPF_PERF_OUTPUT(events);  // Declare a BPF map to transmit data to user space

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    // Get current user ID and group ID
    u32 uid = bpf_get_current_uid_gid();

    // Assign user ID and flags to data structure
    struct data_t data = {};
    data.uid = uid;
    data.flags = flags;

    bpf_get_current_comm(&data.comm, sizeof(data.comm)); // get current proc name and task name
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)filename); // file name
    events.perf_submit(ctx, &data, sizeof(data));  // submit data to events map
    return 0;
}
