# BPF python script to measure runq length and the targetd CPUs chosen for task
# wakeups
#
# @author: parth@linux.ibm.com
# 
# Example:
# ========
# $> python runqstat.py -nr
# Tracing Runqueue Stats for CPU-0... Hit Ctrl-C to end.
# CPUs used for sched_wakeup targets
# 
# CPU = 0
#      target cpus   : count     distribution
#         0          : 59       |****************************************|
# 
# ===========
# 
# Number of running tasks on CPU(s)
# 
# CPU = 0
#      nrstat        : count     distribution
#         0          : 0        |                                        |
#         1          : 32       |****************************************|
#         2          : 27       |*********************************       |
# 

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

examples = """examples
    ./rqstat.py -r 3-9# Stats for CPUs from 3 to 9
    ./rqstat.py -nt   # Don't print target_cpu stats
    ./rqstat.py -nr   # Print nr_running stats per-CPU
    ./rqstat.py -nw   # Don't consider wake_up_new_task stats (scheduler slow path)
"""

parser = argparse.ArgumentParser(
        description="Summarize Runqueue Stats as a histogram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-t", "--time", default=5, help="add timer (default 5sec)")
parser.add_argument("-c", "--cpu",  default=0, help="add CPU (default CPU-0)")
parser.add_argument("-r", "--range",  nargs='?', default=0, help="add CPU range")
parser.add_argument("-a", "--all", default=0, action="store_const", const=1, help="All CPUs")
parser.add_argument("-nt", "--notargetcpustats", default=0, action="store_const", const=1, help="Don't calculate CPUs sleected as target for sched_wakeup")
parser.add_argument("-nr", "--nrstat", default=0, action="store_const", const=1, help="Calculate nr Running statistics")
parser.add_argument("-nw", "--nowakeupnew", default=0, action="store_const", const=1, help="Don't calculate CPUs targeted by wake_up_new_task")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <linux/sched.h>

HEADERS

struct nr_t {
    int cpu;
    int nr_running;
};

struct data_t {
    int cpu;
    int target_cpu;
};

BPF_HISTOGRAM(targetcpu_hist, struct data_t);
BPF_HISTOGRAM(nr_hist, struct nr_t);

struct rq_partial {
    raw_spinlock_t          lock;
    unsigned int            nr_running;
};

/*
 * Finds: task->se.cfs_rq->rq->nr_running
 * Use current CPU to figure out nr_running on its own rq
 */
static void update_nr (int cpu)
{
    struct task_struct *task = NULL;
    struct cfs_rq * cfsrq = NULL;
    struct rq_partial * rq = NULL;
    struct nr_t nr_t = {.cpu = cpu, .nr_running = 0};

    task = (struct task_struct *)bpf_get_current_task();
    cfsrq = (struct cfs_rq *)task->se.cfs_rq;
    rq = (struct rq_partial *)cfsrq->rq;

    nr_t.nr_running = rq->nr_running;

    nr_hist.increment(nr_t);
}

static void update_targetcpu(int cpu, int targetcpu)
{
    struct data_t data_t = {.cpu = 0, .target_cpu = 0};
    
    data_t.cpu = cpu;
    data_t.target_cpu = targetcpu;

    targetcpu_hist.increment(data_t);
}

TRACEPOINT_PROBE(sched, sched_wakeup)
{
    int cpu = bpf_get_smp_processor_id();
    int targetcpu = args->target_cpu;
    
    if ( ALLCPU && FILTER ) return 0;
    
    UPDATE_NR
    update_targetcpu(cpu, targetcpu);

    return 0;
}

#ifdef SCHED_WAKEUP_NEW_STATS
TRACEPOINT_PROBE(sched, sched_wakeup_new)
{
    int cpu = bpf_get_smp_processor_id();
    int targetcpu = args->target_cpu;

    if ( ALLCPU && FILTER ) return 0;

    UPDATE_NR
    update_targetcpu(cpu, targetcpu);

    return 0;
}
#endif

int update_nr_tp()
{
    int cpu = bpf_get_smp_processor_id();

    if ( ALLCPU && FILTER ) return 0;

    update_nr(cpu);
    return 0;
}
"""

fd = open("cur_linux_cfs_rq.h","r")
header = fd.read()
fd.close()
bpf_text = bpf_text.replace('HEADERS', header)

if (not args.nowakeupnew):
    bpf_text = "#define SCHED_WAKEUP_NEW_STATS\n" + bpf_text

if (args.nrstat):
    bpf_text = bpf_text.replace('UPDATE_NR', 'update_nr(cpu);')
else:
    bpf_text = bpf_text.replace('UPDATE_NR', '')

range_filter = False
all_cpus = False

cpu_filter = 'cpu != '+str(args.cpu)
if(args.range):
    rstart = args.range.split('-')
    if (len(rstart)==1):
        rstart = args.range.split(',')
    rend = int(rstart[-1])
    rstart = int(rstart[0])

    if (rstart <= rend):
        range_filter = True
        cpu_filter = '(cpu < '+str(rstart)+' || cpu > '+str(rend)+')'

bpf_text = bpf_text.replace('FILTER', cpu_filter)


if (args.all == 0 ):
    bpf_text = bpf_text.replace('ALLCPU', '1')
else:
    bpf_text = bpf_text.replace('ALLCPU', '0')
    all_cpus = True

b = BPF(text=bpf_text)
if (not args.notargetcpustats):
    b.attach_tracepoint("sched:sched_switch", "update_nr_tp");
if (args.nrstat):
    b.attach_tracepoint("sched:sched_process_exit", "update_nr_tp");

if(all_cpus):
    print("Tracing Runqueue Stats for all CPUs... Hit Ctrl-C to end.")
elif(range_filter):
    print("Tracing Runqueue Stats for CPU-["+str(rstart)+"-"+str(rend)+"]... Hit Ctrl-C to end.")
else:
    print("Tracing Runqueue Stats for CPU-"+ str(args.cpu)+"... Hit Ctrl-C to end.")

# output
targetcpustat = b.get_table("targetcpu_hist")
nrstat = b.get_table("nr_hist")

if (1):
    try:
        sleep(int(args.time))
    except KeyboardInterrupt:
        pass

    if(not args.notargetcpustats):
        print("CPUs used for sched_wakeup targets")
        targetcpustat.print_linear_hist("target cpus", "CPU")
    if (args.nrstat):
        if (not args.notargetcpustats):
            print("\n===========\n")
        print("Number of running tasks on CPU(s)")
        nrstat.print_linear_hist("nrstat", "CPU")
