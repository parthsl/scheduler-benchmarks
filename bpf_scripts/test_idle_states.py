# BPF python script to Test if a given CPUIDLE entry is used by the governor or not
#
# @author: parth@linux.ibm.com
#
# Sample:
# =======
# $> python3 test_idle_states.py -s 3 -c 3
# Tracing CPUIDLE states for CPU-3... Hit Ctrl-C to end.
# Testing for CPUIDLE state= 3
# Config param = ALPHA: 1 GAMMA: 1e-05 SLEEPTIME: 0.0001 PERIOD: 0.001 LOOPS: 5000
# Target residency table= {5: 800, 3: 100, 1: 2, 8: 5000, 6: 800, 4: 200, 2: 20, 0: 0, 7: 5000}
# Period =  0.001 , Sleeptime =  0.0001 , States used =  {1: 74, 2: 5431, 3: 1345, 4: 5}
# Found duty cycle: period = 0.001 sleep = 0.0001

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

examples = """examples
    ./test_idle_state.py             # Ctrl-C to Quit
    ./test_idle_state.py -s 3        # Test state-3 on default CPU-0
    ./test_idle_state.py -c 1 -s 2   # Test state-2 on CPU-1
    ./test_idle_state.py -a          # Test on all CPUs
    ./test_idle_state.py -r 3-9      # Test state-1 (default) on CPUs from 3 to 9
"""

parser = argparse.ArgumentParser(
        description="Test if a particular IDLE states is ever used",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-c", "--cpu",  default=0, help="add CPU")
parser.add_argument("-r", "--range",  nargs='?', default=0, help="add CPU range")
parser.add_argument("-a", "--all", default=0, action="store_const", const=1, help="All CPUs")
parser.add_argument("-s", "--state", default=1, help="Test IDLE state")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <linux/sched.h>

BPF_ARRAY(idlestat, int, 10);

static void is_increment(int state)
{
    int *val = idlestat.lookup(&state);
    if (val)
        (*val)++;
}
TRACEPOINT_PROBE(power, cpu_idle)
{
    u32 state = args->state;
    int cpu_id = args->cpu_id;
    int zero = 0;

    if (ALLCPU && FILTER) return 0;

    // entering IDLE.
    if (state > 0 && state < 10 ) { //Hack workaround
        is_increment(state);
    }

    // Exiting IDLE
    else {}
    
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

b = BPF(text=bpf_text)

if(all_cpus):
    print("Tracing CPUIDLE states for all CPUs... Hit Ctrl-C to end.")
elif(range_filter):
    print("Tracing CPUIDLE states for CPU-["+str(rstart)+"-"+str(rend)+"]... Hit Ctrl-C to end.")
else:
    print("Tracing CPUIDLE states for CPU-"+ str(args.cpu)+"... Hit Ctrl-C to end.")

# output
idlestat = b["idlestat"]

import os
from multiprocessing import Process
from time import time
def inject_busy_loop(period, sleeptime, loops):
    '''
    Create duty cycle based workload which sleeps for
    'sleeptime' sec in every period sec.
    '''
    a = 0
    for i in range(loops):
        periodStart = time()
        while (time()-periodStart) < (period - sleeptime):
            pass
        if period > (time() - periodStart):
            sleep(period - (time()-periodStart))

def create_process(period, sleeptime, loops, cpu):
    p = Process(target=inject_busy_loop, args=(period, sleeptime, loops))
    p.start()
    os.system("taskset -p -c %d %d 2>&1 >/dev/null" % (cpu, p.pid) )
    return p

TR = dict()
TR_dir = os.listdir('/sys/devices/system/cpu/cpu'+str(args.cpu)+'/cpuidle/')
for i in TR_dir:
    state_id = int(i[-1])
    fd = open('/sys/devices/system/cpu/cpu'+str(args.cpu)+'/cpuidle/'+i+'/residency')
    TR[state_id] = int(fd.read())
    fd.close()


test_state_id = int(args.state)

# heuristics variables
sleeptime = TR[test_state_id]/1000000 # residency is in usec, convert to sec
period = sleeptime * 10 # Keep distance of 10x to complete in 10 log steps
states_touched = dict()
prev_low_or_high = 0 # 0 for NA, 1 for low, 2 for high
alpha = 1
gamma = sleeptime/10
loops = int(5 / period) # Run for 5 sec

print("Testing for CPUIDLE state=",test_state_id)
print("Config param = ALPHA:", alpha, "GAMMA:", gamma, "SLEEPTIME:", sleeptime, "PERIOD:", period, "LOOPS:", loops)
print("Target residency table=", TR)
if test_state_id+1 in TR.keys():
    upper_bound_sleeptime = (TR[test_state_id+1]*1.1)/1000000 # 10% more  of next state
else:
    upper_bound_sleeptime = sleeptime*1.1

if test_state_id-1 in TR.keys():
    lower_bound_sleeptime = (TR[test_state_id-1]*0.9)/1000000 #10% less of prev state
else:
    lower_bound_sleeptime = sleeptime*0.9

# Process BPF scripts output
exiting = 0
while (1):
    if sleeptime > upper_bound_sleeptime or sleeptime < lower_bound_sleeptime:
        print("Unable to find the duty cycle")
        break
    try:
        if sleeptime < 0:
            sleeptime = 0
        p = create_process(period, sleeptime, loops, int(args.cpu))
        p.join()
    except KeyboardInterrupt:
        exiting = 1

    for k,v in idlestat.items():
        if idlestat[k].value > 0:
            states_touched[k.value] = idlestat[k].value

    print("Period = ",period, ", Sleeptime = ", sleeptime, ", States used = ", states_touched)
    if (test_state_id in states_touched.keys()):
        print("Found duty cycle: period =",period, "sleep =",sleeptime)
        exiting = 1
    else:
        # find any key above test_state_id
        low_keys = False
        high_keys = False
        for i in states_touched.keys():
            if i > test_state_id:
                high_keys = True
            elif i < test_state_id:
                low_keys = True
        if low_keys:
            if prev_low_or_high == 2: # if prev was high then reset alpha
                alpha = 1
            elif prev_low_or_high == 1: # if prev was low then x2 alpha
                alpha *= 2

            prev_low_or_high = 1
            if (sleeptime + alpha*gamma > period):
                alpha = 1
            sleeptime += alpha * gamma # add gamma usec

        elif high_keys:
            if prev_low_or_high == 1: # if previous was low then reset alpha
                alpha = 1
            elif prev_low_or_high == 2: # if prev was high then x2 alpha
                alpha *= 2
            prev_low_or_high = 2

            if (sleeptime - alpha*gamma < 0):
                alpha = 1
            sleeptime -= alpha*gamma # Remove 10 usec
    
    idlestat.clear()

    if exiting:
        break