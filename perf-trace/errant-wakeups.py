# Licensed under the terms of the GNU GPL License version 2
# See the perf-script-python Documentation for the list of available functions.

# This script provides a way to calculate struct rq->nr_running or runqueue
# length from the sched:* traces.
#
# Use sched_update_nr_running trace for 100% accuracy. Use
# https://github.ibm.com/pshah015/tracepoint-modules for loading extra modules
# for the same.

# Example to take sched:* traces:
# ===========
# perf record -e sched:sched_wakeup,\\
#        sched:sched_switch,\\
#        sched:sched_migrate_task,\\
#        power:cpu_idle -aR sleep 5
#
# This script can be used on the captured perf.data file as
# perf script -s errant-wakeups.py
#qemu-system-ppc 108124  164914.828546824 problematic wakeup at cpu=25 target_cpu=26 runqlen=2   comm=qemu-system-ppc 108128
# CPU = 0 --- 8: 0        0       0       0       0       0       0       0       0       
# CPU = 9 --- 17: 0       0       0       0       0       0       0       0       0       
# CPU = 18 --- 26: 0      0       0       0       0       0       0       1       2       
# It could have woken up on idle cpu=25
#
# @author: Parth Shah <parth@linux.ibm.com>

from __future__ import print_function

import os
import sys

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
	'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *

# script specific tunables
NR_CPUS = 176
LLC_CPUMASK_SIZE = 8
LATENCY_THRESHOLD_US = (10**3)*10 # 10ms
VERBOSE = False

# variables
runqlen = [0 for i in range(NR_CPUS)]
confidence = [0 for i in range(NR_CPUS)]
total_wakeup_on_idle_rq = 0
total_wakeup_on_busy_rq = 0
wakeup_runqlen = dict()

class Mark:
    def __init__(self, sec, nsec, runqlen, errant=False):
        self.sec = sec
        self.nsec = nsec
        self.runqlen = runqlen
        self.errant = errant


# Store information like ktime, nr_running, etc. for each pid
wakeup_mark = dict()

# Confidence flags, used for enumeration
NO_CONFIDENCE = 0
DERIVED_CONFIDENCE = 1
ABSOLUTE_CONFIDENCE = 2

def print_runqlen(rows, columns):
    global runqlen
    for i in range(rows):
        print("CPU = "+ str(i*columns) +" --- " + str(columns*(i+1)-1)+": ", end="")
        for j in range(columns):
            if (i*columns + j >= NR_CPUS):
                break
            print(runqlen[i*columns + j], end="\t")
        print()


def pr():
    print_runqlen(20, NR_CPUS/20+1)


def is_idle_cpu(cpu):
    global runqlen

    return runqlen[cpu]


def sd_mask(cpu, cpumask_size):
    '''
    Find domain cpumask for a given cpu
    @cpu: cpu-id number
    @cpumask_size: size of the cpumask for specific domain

    For cpumask_size = 4, sd_mask return first and last cpu of small core
    lly, for size = 8, this returns cpus of big core.
    '''
    first_cpu = (cpu//cpumask_size)*cpumask_size
    return first_cpu,first_cpu+cpumask_size


def trace_begin():
    print("Perf-script for finding if wakeups happen on busy CPUs despite?")

def trace_end():
    print("Final runqlength output")
    print("-----------------------")
    global total_wakeup_on_idle_rq
    global total_wakeup_on_busy_rq
    print("Total wakeups on idle rq=", total_wakeup_on_idle_rq)
    print("Total wakeups on busy rq=", total_wakeup_on_busy_rq)
    global wakeup_runqlen
    print("Histogram of {nr_running: sample} = ",wakeup_runqlen)
    pr()


def sched__sched_migrate_task(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, comm, pid, prio, orig_cpu, 
        dest_cpu, perf_sample_dict):

                global confidence
                # If we have nr_running traces of orig_cpu, we must have for
                # dest_cpu as well.
                if (confidence[orig_cpu] == ABSOLUTE_CONFIDENCE or confidence[dest_cpu] > ABSOLUTE_CONFIDENCE):
                    return

                global runqlen
                runqlen[orig_cpu] -= 1
                runqlen[dest_cpu] += 1

                if (confidence[orig_cpu] > NO_CONFIDENCE and runqlen[orig_cpu] < 0):
                    print("error with -ve runq at orig_cpu=", orig_cpu,
                            str(common_secs)+"."+str(common_nsecs))


def sched__sched_switch(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, prev_comm, prev_pid, prev_prio, prev_state, 
        next_comm, next_pid, next_prio, perf_sample_dict):

                global confidence
                global runqlen
                global wakeup_mark

                if next_pid in wakeup_mark:
                    mark = wakeup_mark[next_pid]
                    tdiff = (common_secs - mark.sec)*(10**9)
                    tdiff += common_nsecs - mark.nsec
                    tdiff /= (10**3) # Convert to usec

                    if tdiff > (LATENCY_THRESHOLD_US):
                        print("Higher latency observed for wakeup at ktime=", mark.sec, mark.nsec)
                        print()
                    del(wakeup_mark[next_pid])

                if confidence [common_cpu]== ABSOLUTE_CONFIDENCE:
                    return
                # TASK_INTERRUPTIBLE = 0x001 => "S"
                # TASK_UNINTERRUPTIBLE = 0x002 => "D"
                if (prev_state == 1 or prev_state == 2):
                        runqlen[common_cpu] -= 1


def sched__sched_wakeup(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, comm, pid, prio, success, 
        target_cpu, perf_sample_dict):

                is_correct_wakeup = 1
                global confidence
                global runqlen
                if confidence[target_cpu] < ABSOLUTE_CONFIDENCE:
                    runqlen[target_cpu] += 1

                # Taking sched trace in middle of workload screws the
                # runqlength count for this script as it won't know the initial
                # runqlength.
                if (confidence[target_cpu] > NO_CONFIDENCE):
                        suggestion_str = ""
                        if (runqlen[target_cpu] > 1):
                                print(str(common_comm) + " " + str(common_pid) + "\t" +
                                str(common_secs) + "." + str(common_nsecs) +
                                " problematic wakeup at cpu=" + str(common_cpu) +
                                " target_cpu="+str(target_cpu) + 
                                " runqlen="+str(runqlen[target_cpu]) + 
                                "\tcomm=" + comm + " " + str(pid))
                                if VERBOSE:
                                    pr()

                                first_cpu,last_cpu = sd_mask(common_cpu, LLC_CPUMASK_SIZE)

                                for i in range(first_cpu, last_cpu):
                                    if (is_idle_cpu(i)==0):
                                        if (suggestion_str == ""):
                                            suggestion_str = "It could have woken up on idle cpu="
                                        suggestion_str += str(i)+", "
                                        is_correct_wakeup = 0

                                print(suggestion_str)

                        
                        global wakeup_mark
                        mark = Mark(common_secs, common_nsecs, runqlen[target_cpu])
                        if (suggestion_str == ""):
                            mark.errant = False
                        else:
                            mark.errant = True
                        wakeup_mark[pid] = mark

                        global total_wakeup_on_idle_rq
                        global total_wakeup_on_busy_rq
                        total_wakeup_on_idle_rq += is_correct_wakeup
                        total_wakeup_on_busy_rq += 1-is_correct_wakeup

                #print_header(event_name, common_cpu, common_secs, common_nsecs, common_pid, common_comm)

def power__cpu_idle(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, state, cpu_id, perf_sample_dict):

                global confidence
                if confidence[cpu_id] == 2:
                    return

                global runqlen
                if (state < 100):
                        if (confidence[cpu_id]==1 and runqlen[cpu_id]>0):
                            print("Runqueue not emptied before this", common_secs, common_nsecs, cpu_id)
                        runqlen[cpu_id] = 0
                        confidence[cpu_id] = DERIVED_CONFIDENCE


def sched__sched_update_nr_running(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, cpu, change, nr_running, perf_sample_dict):

                global runqlen
                runqlen[cpu] = nr_running
                confidence[cpu] = ABSOLUTE_CONFIDENCE
                if nr_running in wakeup_runqlen:
                    wakeup_runqlen[nr_running] += 1
                else:
                    wakeup_runqlen[nr_running] = 1


def trace_unhandled(event_name, context, event_fields_dict, perf_sample_dict):
        print(get_dict_as_string(event_fields_dict))
        print('Sample: {'+get_dict_as_string(perf_sample_dict['sample'], ', ')+'}')

def print_header(event_name, cpu, secs, nsecs, pid, comm):
        print("%-20s %5u %05u.%09u %8u %-20s " % \
            (event_name, cpu, secs, nsecs, pid, comm), end="")

def get_dict_as_string(a_dict, delimiter=' '):
        return delimiter.join(['%s=%s'%(k,str(v))for k,v in sorted(a_dict.items())])
