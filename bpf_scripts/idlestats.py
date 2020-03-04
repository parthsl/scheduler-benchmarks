# BPF python script to trace CPUIDLE events for a givne CPU
#
# @author: parth@linux.ibm.com

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

examples = """examples
    ./idleinfo.py       # Ctrl-C to Quit
    ./idleinfo.py -t 5  # Run for 5 Sec
    ./idleinfo.py -c 1  # Trace CPU-1. Defaults to CPU-0
"""

parser = argparse.ArgumentParser(
        description="Summarize CPUIDLE latency as a histogram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-t", "--time", default=5, help="add timer")
parser.add_argument("-c", "--cpu",  default=0, help="add CPU")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <linux/sched.h>

BPF_HASH(tss, int, u64);
BPF_HASH(latency, int, u64);

BPF_HISTOGRAM(entrycount, int);

struct data_t {
    int cpu_id;
    u64 ts;
};

BPF_HISTOGRAM(idletime, u64);

TRACEPOINT_PROBE(power, cpu_idle)
{
    u32 state = args->state;
    int cpu_id = args->cpu_id;

    if (FILTER) return 0;

    // entering IDLE.
    if (state > 0 && state < 10 ) { //Hack workaround
        entrycount.increment(state);

        u64 ts = bpf_ktime_get_ns() / 1000000;
        tss.update(&cpu_id, &ts);
    }

    // Exiting IDLE
    else {
        u64 *tsp, delta;
        u64 *latencyp = latency.lookup(&cpu_id);
        tsp = tss.lookup(&cpu_id);
        if (tsp == 0) {
            return 0; // missed IDLE enter
        }

        delta = (bpf_ktime_get_ns() / 1000000) - *tsp;

        // Add past latency
        // if ( latencyp) delta = delta + *latencyp;

        latency.update(&cpu_id, &delta);

        idletime.increment(bpf_log2l(delta));

        tss.delete(&cpu_id);
    }
    
    return 0;
}
"""

cpu_filter = 'cpu_id != '+str(args.cpu)
bpf_text = bpf_text.replace('FILTER', cpu_filter)
b = BPF(text=bpf_text)

print("Tracing CPUIDLE latency for CPU-"+ str(args.cpu)+"... Hit Ctrl-C to end.")

# output
entrycount = b.get_table("entrycount")

residency = b.get_table("idletime")

import os
from multiprocessing import Process

def create_small_load():
    '''
    Create 10 milli-seconds of workload
    '''
    import time
    a = time.time()
    while(time.time()-a < 0.01):
        a += 0
    a += 3

# Create small load to invoke at least one power:cpu_idle traces
p = Process(target=create_small_load)
p.start()
os.system("taskset -p -c %d %d 2>&1 >/dev/null" % (int(args.cpu), p.pid) )
p.join()

if (1):
    try:
        sleep(int(args.time))
    except KeyboardInterrupt:
        exiting = 1

    entrycount.print_linear_hist("State entered\t")
    entrycount.clear()

    residency.print_log2_hist("Idle time (in ms) \t")
    residency.clear()
