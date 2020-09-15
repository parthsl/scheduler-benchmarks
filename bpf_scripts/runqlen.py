# BCC script to measure runq length during sched_switches
#
# Example:
# $> taskset -c 0-3 schbench -m 10 -t 1 -r 10 &
# python runqlen.py -r 0-3 -t 15
# Tracing Runqueue length for CPU-[0-3]... Hit Ctrl-C to end.
# nr_running    : count     distribution
#    0          : 1832     |**********************                  |
#    1          : 3255     |****************************************|
#    2          : 2471     |******************************          |
#    3          : 1281     |***************                         |
#    4          : 226      |**                                      |
#    5          : 8        |                                        |
#
# @author: parth@linux.ibm.com

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

examples = """examples
    ./runqlen.py -r 3-9# Find rq length for CPUs from 3 to 9
    ./runqlen.py -a    # Find rq length for all CPUs
    ./runqlen.py -t 5  # Set 5sec time limit (default is 10000)
    ./runqlen.py -F "schbench" # Filter by comm==schbench dueint sched_switch
"""

parser = argparse.ArgumentParser(
        description="Summarize Runqueue length as a histogram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-t", "--time", default=10000, help="add timer (default 10000sec)")
parser.add_argument("-c", "--cpu",  default=0, help="add CPU (default CPU-0)")
parser.add_argument("-r", "--range",  nargs='?', default=0, help="add CPU range")
parser.add_argument("-a", "--all", default=0, action="store_const", const=1, help="All CPUs")
parser.add_argument("-F", "--comm", default='', help="Filter by command")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <linux/sched.h>

HEADERS

DEFINE_FILTER_COMM

BPF_HISTOGRAM(nr_running, unsigned int);

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
    unsigned int nrr = 0;

    task = (struct task_struct *)bpf_get_current_task();
    cfsrq = (struct cfs_rq *)task->se.cfs_rq;
    rq = (struct rq_partial *)cfsrq->rq;

    nrr = rq->nr_running;
    nr_running.increment(nrr);
}

TRACEPOINT_PROBE(sched, sched_switch)
{
    int cpu = bpf_get_smp_processor_id();

#ifdef DEFINED_FILTER
    char comm[TASK_COMM_LEN];
    char comparand[] = FILTER_COMMAND;
    int limit=COMM_LENGTH;

    bpf_get_current_comm(&comm, sizeof(comm));
    while(limit--)
        if(comm[limit] != comparand[limit]) return 0;
#endif

    if ( ALLCPU && CPU_FILTER ) return 0;

    update_nr(cpu);
    return 0;
}

"""

fd = open("cur_linux_cfs_rq.h","r")
header = fd.read()
fd.close()
bpf_text = bpf_text.replace('HEADERS', header)

if (args.comm):
    bpf_text = bpf_text.replace('FILTER_COMMAND', '"'+args.comm+'"')
    bpf_text = bpf_text.replace('COMM_LENGTH', str(len(args.comm)))
    bpf_text = bpf_text.replace('DEFINE_FILTER_COMM', '#define DEFINED_FILTER')
else:
    bpf_text = bpf_text.replace('FILTER_COMMAND', '')
    bpf_text = bpf_text.replace('COMM_LENGTH', '0')
    bpf_text = bpf_text.replace('DEFINE_FILTER_COMM', '')


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

bpf_text = bpf_text.replace('CPU_FILTER', cpu_filter)


if (args.all == 0 ):
    bpf_text = bpf_text.replace('ALLCPU', '1')
else:
    bpf_text = bpf_text.replace('ALLCPU', '0')
    all_cpus = True

b = BPF(text=bpf_text)

if(all_cpus):
    print("Tracing Runqueue length for all CPUs... Hit Ctrl-C to end.")
elif(range_filter):
    print("Tracing Runqueue length for CPU-["+str(rstart)+"-"+str(rend)+"]... Hit Ctrl-C to end.")
else:
    print("Tracing Runqueue length for CPU-"+ str(args.cpu)+"... Hit Ctrl-C to end.")

# output
nr_running = b.get_table("nr_running")

if (1):
    try:
        sleep(int(args.time))
    except KeyboardInterrupt:
        pass

    nr_running.print_linear_hist("nr_running")

