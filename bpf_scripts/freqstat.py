# BPF python script to trace CPUIDLE events for a givne CPU
#
# @author: parth@linux.ibm.com
#
from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

examples = """examples
    ./idleinfo.py       # Ctrl-C to Quit
    ./idleinfo.py -t 5  # Run for 5 Sec
    ./idleinfo.py -c 1  # Trace CPU-1. Defaults to CPU-0
    ./idleinfo.py -a    # Stats for all the CPUs
    ./idleinfo.py -r 3-9# Stats for CPUs from 3 to 9
"""

parser = argparse.ArgumentParser(
        description="Summarize CPU Frequency as a histogram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-t", "--time", default=5, help="add timer")
parser.add_argument("-c", "--cpu",  default=0, help="add CPU")
parser.add_argument("-r", "--range",  nargs='?', default=0, help="add CPU range")
parser.add_argument("-a", "--all", default=0, action="store_const", const=1, help="All CPUs")
parser.add_argument("-p", "--percpu", default=0, action="store_const", const=1, help="Show per cpu stats")
parser.add_argument("-b", "--bucketcount",  default=5, help="Counts of frequency buckets (>2, default = 5)")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <linux/sched.h>

struct data_t {
    int cpu_id;
    u32 frequency;
};

u32 minstate = MINSTATE;
u32 maxstate = MAXSTATE;
int bucketcount = BUCKETCOUNT;

BPF_HISTOGRAM(freqstat, struct data_t);

static void fs_increment(int cpu, u32 freq)
{
    u32 bucketSize = ((MAXSTATE - MINSTATE)/ BUCKETCOUNT);
    u32 freqBucket = (freq - MINSTATE)/bucketSize;
    bpf_trace_printk("%u %u %u\\n",freqBucket, bucketSize, freq);
    struct data_t slot = {.cpu_id = cpu, .frequency = freqBucket};
    freqstat.increment(slot);
}

TRACEPOINT_PROBE(power, cpu_frequency)
{
    u32 state = args->state;
    int cpu_id = args->cpu_id;
    int zero = 0;

    if (ALLCPU && FILTER) return 0;

    if (!(PERCPU_STATS))
        cpu_id = 0;

    fs_increment(cpu_id, state);

    return 0;
}
"""

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

if (args.percpu == 0):
    bpf_text = bpf_text.replace('PERCPU_STATS', '0')
else:
    bpf_text = bpf_text.replace('PERCPU_STATS', '1')

bpf_text = bpf_text.replace('BUCKETCOUNT', str(int(args.bucketcount)-1))

minfreq = str(int(open("/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_min_freq","r").read()))
maxfreq = str(int(open("/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq","r").read()))
bpf_text = bpf_text.replace('MINSTATE', minfreq)
bpf_text = bpf_text.replace('MAXSTATE', maxfreq)

b = BPF(text=bpf_text)

if(all_cpus):
    print("Tracing CPU Frequency for all CPUs... Hit Ctrl-C to end.")
elif(range_filter):
    print("Tracing CPU Frequency for CPU-["+str(rstart)+"-"+str(rend)+"]... Hit Ctrl-C to end.")
else:
    print("Tracing CPU Frequency for CPU-"+ str(args.cpu)+"... Hit Ctrl-C to end.")

# output
freqstat = b.get_table("freqstat")
print("Max freq=", maxfreq,"\t Min freq=", minfreq, "\t Bucket count=",args.bucketcount)
if (1):
    try:
        sleep(int(args.time))
    except KeyboardInterrupt:
        pass

    if(all_cpus or range_filter):
	freqstat.print_linear_hist("frequency buckets","list")
    else:
	freqstat.print_linear_hist("frequency buckets", "CPU")
