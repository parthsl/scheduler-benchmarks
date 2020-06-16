# BPF python script to generate trace file required to animate scheduler
# behavior patterns
#
# @author: parth@linux.ibm.com
# 
# Example:
# ========
# $> python nrstats.py -r 0-4 > trace.log
#
# The trace file generated can then be passed on to the 
# general/nrstat_visualize.ipynb
# to visualize the scheduler wakeup/migration pattern

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import ctypes

cpu_nrstat = []
cpumask = []
per_cpu_nrstat = dict()

examples = """examples
    ./nrstats.py -r 3-9# Stats for CPUs from 3 to 9
    ./nrstats.py -nt   # Don't print target_cpu stats
    ./nrstats.py -nr   # Print nr_running stats per-CPU
    ./nrstats.py -nw   # Don't consider wake_up_new_task stats (scheduler slow path)
"""

parser = argparse.ArgumentParser(
        description="Summarize Runqueue Stats as a histogram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-t", "--time", default=5, help="add timer (default 5sec)")
parser.add_argument("-c", "--cpu",  default=0, help="add CPU (default CPU-0)")
parser.add_argument("-r", "--range",  nargs='?', default=0, help="add CPU range")
parser.add_argument("-a", "--all", default=0, action="store_const", const=1, help="All CPUs")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <linux/sched.h>

HEADERS

enum event_type {
    WAKEUP,
    WAKEUP_NEW,
    MIGRATE_TASK,
    TASK_EXIT,
    SCHED_SWITCH
};

struct data_t {
    enum event_type et;
    int this_cpu;
    int orig_cpu;
    int target_cpu;
    int nr_running;
};

BPF_PERF_OUTPUT(events);

struct rq_partial {
    raw_spinlock_t          lock;
    unsigned int            nr_running;
};

/*
 * Finds: task->se.cfs_rq->rq->nr_running
 * Use current CPU to figure out nr_running on its own rq
 */
static int get_nr_running ()
{
    struct task_struct *task = NULL;
    struct cfs_rq * cfsrq = NULL;
    struct rq_partial * rq = NULL;
    task = (struct task_struct *)bpf_get_current_task();
    cfsrq = (struct cfs_rq *)task->se.cfs_rq;
    rq = (struct rq_partial *)cfsrq->rq;

    return rq->nr_running;
}

TRACEPOINT_PROBE(sched, sched_wakeup)
{
    int cpu = bpf_get_smp_processor_id();
    struct data_t event = {};

    if ( FILTER ){
        cpu = args->target_cpu;
        if ( FILTER ) return 0;
    }

    event.et = WAKEUP;
    event.target_cpu = args->target_cpu;
    event.nr_running = get_nr_running();
    event.this_cpu = bpf_get_smp_processor_id();

    events.perf_submit(args, &event, sizeof(event));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_wakeup_new)
{
    int cpu = bpf_get_smp_processor_id();
    int nr_running = 0;
    struct data_t event = {};

    if ( FILTER ){
        cpu = args->target_cpu;
        if ( FILTER ) return 0;
    }

    event.et = WAKEUP_NEW;
    event.target_cpu = args->target_cpu;
    event.nr_running = get_nr_running();
    event.this_cpu = bpf_get_smp_processor_id();

    events.perf_submit(args, &event, sizeof(event));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_migrate_task)
{
    int cpu = bpf_get_smp_processor_id();
    int nr_running = 0;
    struct data_t event = {};

    if ( FILTER ) {
        cpu = args->orig_cpu;
        if (FILTER ) {
            cpu = args->dest_cpu;
            if ( FILTER ) return 0;
        }
    }

    event.et = MIGRATE_TASK;
    event.target_cpu = args->dest_cpu;
    event.orig_cpu = args->orig_cpu;
    event.nr_running = get_nr_running();
    event.this_cpu = bpf_get_smp_processor_id();

    events.perf_submit(args, &event, sizeof(event));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    int cpu = bpf_get_smp_processor_id();
    int nr_running = 0;
    struct data_t event = {};

    if ( FILTER ) return 0;

    event.et = TASK_EXIT;
    event.nr_running = get_nr_running();
    event.this_cpu = cpu;

    events.perf_submit(args, &event, sizeof(event));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_switch)
{
    int cpu = bpf_get_smp_processor_id();
    struct data_t event = {};

    if ( FILTER ) return 0;

    event.et = SCHED_SWITCH;
    event.nr_running = get_nr_running();
    event.this_cpu = cpu;

    events.perf_submit(args, &event, sizeof(event));

    return 0;
}
"""

fd = open("cur_linux_cfs_rq.h","r")
header = fd.read()
fd.close()
bpf_text = bpf_text.replace('HEADERS', header)

range_filter = False
all_cpus = False

cpu_filter = 'cpu != '+str(args.cpu)
cpumask.extend([int(args.cpu)])
if(args.range):
    rstart = args.range.split('-')
    if (len(rstart)==1):
        rstart = args.range.split(',')
    rend = int(rstart[-1])
    rstart = int(rstart[0])

    if (rstart <= rend):
        range_filter = True
        cpu_filter = 'cpu < '+str(rstart)+' || cpu > '+str(rend)
        cpumask = range(rstart, rend+1)

if (args.all):
    cpu_filter = 'cpu < 0 || cpu > 1024'
    all_cpus = True
    cpumask = range(0, 176)

bpf_text = bpf_text.replace('FILTER', cpu_filter)

print (cpumask)
b = BPF(text=bpf_text)

if(all_cpus):
    print("Tracing Runqueue Stats for all CPUs... Hit Ctrl-C to end.")
elif(range_filter):
    print("Tracing Runqueue Stats for CPU-["+str(rstart)+"-"+str(rend)+"]... Hit Ctrl-C to end.")
else:
    print("Tracing Runqueue Stats for CPU-"+ str(args.cpu)+"... Hit Ctrl-C to end.")

# output
class EventType(object):
    WAKEUP = 0
    WAKEUP_NEW = 1
    MIGRATE_TASK = 2
    TASK_EXIT = 3
    SCHED_SWITCH = 4

class Events(ctypes.Structure):
    _fields_ = [('event_type', ctypes.c_int),
            ('this_cpu', ctypes.c_int),
            ('orig_cpu', ctypes.c_int),
            ('target_cpu', ctypes.c_int),
            ("nr_running", ctypes.c_int)]

def get_per_cpu_nr(cpu):
    if cpu in per_cpu_nrstat:
        return per_cpu_nrstat[cpu]
    return 0

def set_per_cpu_nr(cpu, nr):
    per_cpu_nrstat[cpu] = nr

def get_masked_per_cpu_nr(cpumask):
    ret = dict()
    for i in cpumask:
        if i in per_cpu_nrstat.keys():
            ret[i] = per_cpu_nrstat[i]
    return ret

def print_event(cpu, data, size):
    et = ctypes.cast(data, ctypes.POINTER(Events)).contents
    if (et.event_type == EventType.WAKEUP or et.event_type == EventType.WAKEUP_NEW):
        set_per_cpu_nr(et.this_cpu, et.nr_running)
        set_per_cpu_nr(et.target_cpu, get_per_cpu_nr(et.target_cpu)+1)
        cpu_nrstat.append([et.event_type, et.this_cpu, et.nr_running, et.target_cpu, get_masked_per_cpu_nr(cpumask)])

    if (et.event_type == EventType.MIGRATE_TASK):
        set_per_cpu_nr(et.this_cpu, et.nr_running)
        set_per_cpu_nr(et.target_cpu, get_per_cpu_nr(et.target_cpu)+1)
        cpu_nrstat.append([et.event_type, et.orig_cpu, et.target_cpu, get_per_cpu_nr(et.orig_cpu),get_per_cpu_nr(et.target_cpu), get_masked_per_cpu_nr(cpumask)])

    if (et.event_type == EventType.TASK_EXIT):
        set_per_cpu_nr(et.this_cpu, et.nr_running)
        set_per_cpu_nr(et.this_cpu, get_per_cpu_nr(et.this_cpu)-1)
        cpu_nrstat.append([et.event_type, et.this_cpu, et.nr_running, get_masked_per_cpu_nr(cpumask)])

    if (et.event_type == EventType.SCHED_SWITCH):
        set_per_cpu_nr(et.this_cpu, et.nr_running)
        cpu_nrstat.append([et.event_type, et.this_cpu, et.nr_running, get_masked_per_cpu_nr(cpumask)])

b["events"].open_perf_buffer(print_event)
import time
start = time.time()
while time.time()-start < args.time:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

for i in cpu_nrstat:
    print(i)

print(per_cpu_nrstat)
