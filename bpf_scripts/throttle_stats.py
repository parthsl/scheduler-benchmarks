#!/usr/bin/python
#
# This program gives the stats about the frequency throttling.
# On each cpu_frequency update, the program triggers __cpufreq_get()
# to find obtained cpu-frequency. This allows the program to update the
# histogram with the delta of the (Requested - Obtained) frequency on a per CPU
# basis.
#
# Sample:
# ========
# $> python throttle_stats.py -t 10 -r 0-87
# Collecting CPU frequency throttle stats for all CPUs
#      Frequency throttled by (MHz) : count     distribution
#          0 -> 1          : 0        |                                        |
#          2 -> 3          : 0        |                                        |
#          4 -> 7          : 0        |                                        |
#          8 -> 15         : 0        |                                        |
#         16 -> 31         : 8        |******                                  |
#         32 -> 63         : 4        |***                                     |
#         64 -> 127        : 13       |**********                              |
#        128 -> 255        : 31       |***********************                 |
#        256 -> 511        : 52       |****************************************|
#        512 -> 1023       : 25       |*******************                     |
# Total throttle counts = 134


from __future__ import print_function
from bcc import BPF
import os
from multiprocessing import Process
import subprocess
from ctypes import c_int
import argparse
import multiprocessing

examples = """examples
    ./throttle_stats.py       # Ctrl-C to Quit
    ./throttle_stats.py -t 5  # Run for 5 Sec
    ./throttle_stats.py -c 1  # Trace CPU-1. Defaults to CPU-0
    ./throttle_stats.py -a    # Stats for all the CPUs (default)
    ./throttle_stats.py -r 3-9# Stats for CPUs from 3 to 9
"""

parser = argparse.ArgumentParser(
        description="Summarize CPUIDLE latency as a histogram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-t", "--time", default=9999999, help="add timer (default infinte)")
parser.add_argument("-c", "--cpu",  default=-1, help="add CPU filter")
parser.add_argument("-r", "--range",  nargs='?', default=0, help="add CPU range filter")
parser.add_argument("-a", "--all", default=1, action="store_const", const=0, help="All CPUs, don't filter")
parser.add_argument("-d", "--debug", default=0, action="store_const", const=1, help="Debug info using trace_printk")
args = parser.parse_args()


# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 frequency;
    u32 cpu_id;
    u64 ts;
};
BPF_PERF_OUTPUT(events);

BPF_HISTOGRAM(throttlestat, u32);
BPF_ARRAY(last, struct data_t, NR_CPUS);
BPF_ARRAY(total_throttles, int, 1);

RAW_TRACEPOINT_PROBE(cpu_frequency) {
    struct data_t data = {};
    struct data_t *prev = NULL;

    data.cpu_id = (u32)ctx->args[1];
    data.frequency = (u32)ctx->args[0]/1000;
    data.ts = bpf_ktime_get_ns();

    if ( !(FILTER) ) return 0;

    // Dont's update with frequency less than 1 sec
    prev = last.lookup(&data.cpu_id);
    if (prev && (data.ts - prev->ts)/1000000000 < 1)
        return 0;

    last.update(&data.cpu_id, &data);

    if ( DEBUG )
        bpf_trace_printk(" %ull: Updating frequency = %u for CPU-%u\\n",
                        data.ts, data.frequency, data.cpu_id);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int kretprobe____cpufreq_get(struct pt_regs *ctx)
{
    u64 cur_freq = PT_REGS_RC(ctx)/1000;
    u64 now = bpf_ktime_get_ns();
    u32 cpu_id = bpf_get_smp_processor_id();
    struct data_t *prev = last.lookup(&cpu_id);
    int zero = 0;

    if (prev) {
        if (prev->frequency > cur_freq) {
            cur_freq = prev->frequency - cur_freq;
            throttlestat.increment(bpf_log2l(cur_freq));
            total_throttles.increment(zero);

            if ( DEBUG )
                bpf_trace_printk("%ull: Throttled from freq %ull to %ull",
                                now, prev->frequency, cur_freq);
        }
    }
    return 0;
}
"""
if args.debug:
    prog = prog.replace('DEBUG', '1')
else:
    prog = prog.replace('DEBUG', '0')

range_filter = False
all_cpus = False

if int(args.cpu) >= 0:
    prog = prog.replace('FILTER', 'data.cpu_id == %d' % int(args.cpu))

elif args.range:
    rstart = args.range.split('-')
    if (len(rstart)==1):
        rstart = args.range.split(',')
    rend = int(rstart[-1])
    rstart = int(rstart[0])

    if (rstart <= rend):
        range_filter = True
        prog = prog.replace('FILTER', '(data.cpu_id < '+str(rstart)+' || data.cpu_id > '+str(rend)+')')
else:
    prog = prog.replace('FILTER', '1')
    all_cpus = True


# load BPF program
b = BPF(text=prog, cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])

pid_array = []

# process event
def polling_thread(cpu, freq, ts):
    try:
        cmd = "taskset -c %d cat /sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_cur_freq" % (cpu, cpu)
        curfreq = subprocess.check_output(cmd.split(' '))
    except KeyboardInterrupt:
        pass

def print_event(cpu, data, size):
    event = b["events"].event(data)
    p = Process(target=polling_thread, args=(event.cpu_id, event.frequency, event.ts))
    p.start()
    pid_array.append(p)

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
exiting = 0

if all_cpus:
    print("Collecting cpu frequency throttle stats for all CPUs")
elif range_filter:
    print("Collecting cpu frequency throttle stats for %s CPUs" % args.range)
else:
    print("Collecting cpu frequency throttle stats for CPU-%d" % int(args.cpu))

from time import time
start_time = time()
while 1: 
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        b["throttlestat"].print_log2_hist("Frequency throttled by (MHz)")
        print("Total throttle counts = %d" % b.get_table("total_throttles")[c_int(0)].value)
        break
    if (time()-start_time) >= int(args.time):
        b["throttlestat"].print_log2_hist("Frequency throttled by (MHz)")
        print("Total throttle counts = %d" % b.get_table("total_throttles")[c_int(0)].value)
        break
