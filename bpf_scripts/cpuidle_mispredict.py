# BPF python script to trace CPUIDLE miss events for a given CPU
#
# This enables to detected events when CPUIDLE governor failed to
# meet target residency time, useful to compare CPUIDLE governors.
#
# @author: parth@linux.ibm.com
#
# Example:
# =========
# $> python cpuidle_mispredict.py -c 0 -t 2 -o
# Tracing CPUIDLE mis-predictions for CPU-0... Hit Ctrl-C to end.
#      State entered       : count     distribution
#         0          : 0        |                                        |
#         1          : 0        |                                        |
#         2          : 0        |                                        |
#         3          : 0        |                                        |
#         4          : 13       |****************************************|
#         5          : 2        |******                                  |
#         6          : 13       |****************************************|
# Total correct predictions:  27
# Total undershoot mis-predictions:  0
# Total overshoot mis-predictions:  2
#
# Bucket ptr = 4
#      overshooted delta (usec)    : count     distribution
#          0 -> 1          : 0        |                                        |
#          2 -> 3          : 0        |                                        |
#          4 -> 7          : 0        |                                        |
#          8 -> 15         : 0        |                                        |
#         16 -> 31         : 0        |                                        |
#         32 -> 63         : 0        |                                        |
#         64 -> 127        : 0        |                                        |
#        128 -> 255        : 0        |                                        |
#        256 -> 511        : 0        |                                        |
#        512 -> 1023       : 0        |                                        |
#       1024 -> 2047       : 2        |*******                                 |
#       2048 -> 4095       : 11       |****************************************|
#
# Bucket ptr = 5
#      overshooted delta (usec)    : count     distribution
#          0 -> 1          : 0        |                                        |
#          2 -> 3          : 0        |                                        |
#          4 -> 7          : 0        |                                        |
#          8 -> 15         : 0        |                                        |
#         16 -> 31         : 0        |                                        |
#         32 -> 63         : 0        |                                        |
#         64 -> 127        : 0        |                                        |
#        128 -> 255        : 0        |                                        |
#        256 -> 511        : 0        |                                        |
#        512 -> 1023       : 0        |                                        |
#       1024 -> 2047       : 0        |                                        |
#       2048 -> 4095       : 0        |                                        |
#       4096 -> 8191       : 0        |                                        |
#       8192 -> 16383      : 2        |****************************************|
#
# Bucket ptr = 6
#      overshooted delta (usec)    : count     distribution
#          0 -> 1          : 0        |                                        |
#          2 -> 3          : 0        |                                        |
#          4 -> 7          : 0        |                                        |
#          8 -> 15         : 0        |                                        |
#         16 -> 31         : 0        |                                        |
#         32 -> 63         : 0        |                                        |
#         64 -> 127        : 0        |                                        |
#        128 -> 255        : 0        |                                        |
#        256 -> 511        : 0        |                                        |
#        512 -> 1023       : 0        |                                        |
#       1024 -> 2047       : 0        |                                        |
#       2048 -> 4095       : 0        |                                        |
#       4096 -> 8191       : 0        |                                        |
#       8192 -> 16383      : 0        |                                        |
#      16384 -> 32767      : 1        |*****                                   |
#      32768 -> 65535      : 2        |***********                             |
#      65536 -> 131071     : 2        |***********                             |
#     131072 -> 262143     : 7        |****************************************|
#

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

examples = """examples
    ./cpuidle_mispredict.py       # Ctrl-C to Quit
    ./cpuidle_mispredict.py -t 5  # Run for 5 Sec
    ./cpuidle_mispredict.py -c 1  # Trace CPU-1. Defaults to CPU-0
    ./cpuidle_mispredict.py -a    # Stats for all the CPUs
    ./cpuidle_mispredict.py -r 3-9# Stats for CPUs from 3 to 9
"""

parser = argparse.ArgumentParser(
        description="Summarize CPUIDLE latency as a histogram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-t", "--time", default=5, help="add timer")
parser.add_argument("-c", "--cpu",  default=0, help="add CPU")
parser.add_argument("-r", "--range",  nargs='?', default=0, help="add CPU range")
parser.add_argument("-a", "--all", default=0, action="store_const", const=1, help="All CPUs")
parser.add_argument("-o", "--overshoot", default=0, action="store_const", const=1, help="Overshoot statistics")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <linux/sched.h>

BPF_HASH(tss, int, u64);
BPF_HASH(state_entered, int, u32);

BPF_HISTOGRAM(entrycount, int);
BPF_HISTOGRAM(missed_by, u64);

enum pred_type {
    OVERSHOOT = 1,
    UNDERSHOOT,
    OVERSHOOT_HOOKS1
    PT_MAX_STATS
};

BPF_ARRAY(correct_prediction, int, PT_MAX_STATS);

static void cp_increment(int key) {
    int *val = correct_prediction.lookup(&key);
    if (val)
        (*val)++;
}

struct struct_idle_t {
    s32 stated;
    long long int deltad;
};

OVERSHOOT_STORAGE

TRACEPOINT_PROBE(power, cpu_idle)
{
    u32 state = args->state;
    int cpu_id = args->cpu_id;
    int zero = 0;
    int one = 1;


    if (ALLCPU && FILTER) return 0;

    // entering IDLE.
    if ((s32)state > 0) { //Hack workaround
        u64 ts;

        entrycount.increment(state);
        state_entered.update(&cpu_id, &state);

        ts = bpf_ktime_get_ns() / 1000;
        tss.update(&zero, &ts);
    }

    // Exiting IDLE
    else {
        u64 *tsp, delta, missed_time = 0;
        u32 *se = state_entered.lookup(&cpu_id);

        tsp = tss.lookup(&zero);
        if (tsp == 0) {
            return 0; // missed IDLE enter
        }

        delta = (bpf_ktime_get_ns() / 1000) - *tsp;

        if (se != 0) {
            int index = *se;
            u64 expected;
            long long int difftime = 0;
            struct struct_idle_t slot = {.stated = 0, .deltad=0};
            int *var;

            /*
             Since BPF don't allow reading read-only struct with a variable
             i.e., for u64 _TR[10] = {0, 10, 20, 30, 40, 50, 60, 70, 80, 90};
             Accessing like _TR[index] will throw error 108
             Hence use vague method like below to not allow random array access
             */
            switch (index) {
                case 0: expected = TR0; break;
                case 1: expected = TR1; break;
                case 2: expected = TR2; break;
                case 3: expected = TR3; break;
                case 4: expected = TR4; break;
                case 5: expected = TR5; break;
                case 6: expected = TR6; break;
                case 7: expected = TR7; break;
                case 8: expected = TR8; break;
                case 9: expected = TR9; break;
            }
                

            if ( delta < expected ) { // less time spent: undershoot
                missed_time = expected - delta;
                missed_by.increment(bpf_log2l(missed_time));

                cp_increment(UNDERSHOOT);

            }
            else { // more time spent; overshoot
                cp_increment(OVERSHOOT);

                OVERSHOOT_HOOKS0
                OVERSHOOT_HOOKS2
            }
        }

        tss.delete(&zero);
    }

    return 0;
}
"""

overshoot_hooks0 = '''
                difftime = (long long int)((long long int)delta - (long long int)expected);
                slot.stated = index;
                slot.deltad = bpf_log2l(difftime);

                delta_t.increment(slot);
'''
overshoot_hooks1 = '''
    OVERSHOOT_MISPREDICTION,
'''
overshoot_hooks2 = '''
if (index < 6) {
                    int next_state = index + 1;
                    expected = 0;
                    switch (next_state) {
                        case 0: expected = TR0; break;
                        case 1: expected = TR1; break;
                        case 2: expected = TR2; break;
                        case 3: expected = TR3; break;
                        case 4: expected = TR4; break;
                        case 5: expected = TR5; break;
                        case 6: expected = TR6; break;
                        case 7: expected = TR7; break;
                        case 8: expected = TR8; break;
                        case 9: expected = TR9; break;
                    }
                    if ( delta >= expected ) {
                        cp_increment(OVERSHOOT_MISPREDICTION);
                        bpf_trace_printk("state %d diff %ld N_expected = %lld\\n", index, delta, expected);
                    }
                }
'''

range_filter = False
all_cpus = False

cpu_filter = 'cpu_id != '+str(args.cpu)
if(args.range):
    rstart = args.range.split('-')
    if (len(rstart)==1):
        rstart = args.range.split(',')
    rend = int(rstart[-1])
    rstart = int(rstart[0])

    if (rstart <= rend):
        range_filter = True
        cpu_filter = '(cpu_id < '+str(rstart)+' || cpu_id > '+str(rend)+')'

bpf_text = bpf_text.replace('FILTER', cpu_filter)


if (args.all == 0 ):
    bpf_text = bpf_text.replace('ALLCPU', '1')
else:
    bpf_text = bpf_text.replace('ALLCPU', '0')
    all_cpus = True

if (args.overshoot == 0 ):
    bpf_text = bpf_text.replace('OVERSHOOT_HOOKS0', '')
    bpf_text = bpf_text.replace('OVERSHOOT_HOOKS2', '')
    bpf_text = bpf_text.replace('OVERSHOOT_HOOKS1', '')
    bpf_text = bpf_text.replace('OVERSHOOT_STORAGE', '')
else:
    bpf_text  = bpf_text.replace('OVERSHOOT_HOOKS0', overshoot_hooks0)
    bpf_text  = bpf_text.replace('OVERSHOOT_HOOKS2', overshoot_hooks2)
    bpf_text = bpf_text.replace('OVERSHOOT_HOOKS1', overshoot_hooks1)
    bpf_text = bpf_text.replace('OVERSHOOT_STORAGE', 'BPF_HISTOGRAM(delta_t, struct struct_idle_t);')

import os
TR = dict()
TR_dir = os.listdir('/sys/devices/system/cpu/cpu'+str(args.cpu)+'/cpuidle/')
for i in TR_dir:
    state_id = int(i[-1])
    fd = open('/sys/devices/system/cpu/cpu'+str(args.cpu)+'/cpuidle/'+i+'/residency')
    TR[state_id] = int(fd.read())
    fd.close()

# Stupidity require here. Passing value = 0 will result in opcode 108
if (0 in TR.values()):
    for i in TR.keys():
        if (TR[i] == 0):
            TR[i] = 'zero'

for i in range(0,10):
    if (i in TR.keys()):
        bpf_text = bpf_text.replace('TR'+str(i), str(TR[i]))
    else:
        bpf_text = bpf_text.replace('TR'+str(i), '100000') # Default to 10ms

b = BPF(text=bpf_text)

if(all_cpus):
    print("Tracing CPUIDLE mis-predictions for all CPUs... Hit Ctrl-C to end.")
elif(range_filter):
    print("Tracing CPUIDLE mis-predictions for CPU-["+str(rstart)+"-"+str(rend)+"]... Hit Ctrl-C to end.")
else:
    print("Tracing CPUIDLE mis-predictions for CPU-"+ str(args.cpu)+"... Hit Ctrl-C to end.")

# output
entrycount = b.get_table("entrycount")

miss_by_time = b.get_table("missed_by")

correct_prediction_count = b.get_table("correct_prediction")

if (args.overshoot):
    idle_delta = b.get_table("delta_t")

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

from ctypes import c_int
OVERSHOOT = c_int(1)
UNDERSHOOT = c_int(2)
OVERSHOOT_MISPREDICTION = c_int(3)

if (1):
    try:
        sleep(int(args.time))
    except KeyboardInterrupt:
        pass

    entrycount.print_linear_hist("State entered\t")
    entrycount.clear()

    miss_by_time.print_log2_hist("Undershoot delta (usec)\t")
    miss_by_time.clear()

    print("Total correct predictions: ", b["correct_prediction"][OVERSHOOT].value)
    print("Total undershoot mis-predictions: ", b["correct_prediction"][UNDERSHOOT].value)

    if (args.overshoot):
        print("Total overshoot mis-predictions: ", b["correct_prediction"][OVERSHOOT_MISPREDICTION].value)
        idle_delta.print_log2_hist("overshooted delta (usec)\t")

    b["correct_prediction"].clear()
