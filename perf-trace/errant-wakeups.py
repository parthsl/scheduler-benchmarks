# Licensed under the terms of the GNU GPL License version 2
# See the perf-script-python Documentation for the list of available functions.

# This script provides a way to calculate struct rq->nr_running or runqueue
# length from the sched:* traces.
#
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

NR_CPUS = 176
runqlen = [0 for i in range(NR_CPUS)]
confidence = [0 for i in range(NR_CPUS)]
LLC_CPUMASK_SIZE = 8

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
    pr()


def sched__sched_migrate_task(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, comm, pid, prio, orig_cpu, 
        dest_cpu, perf_sample_dict):

                global runqlen
                runqlen[orig_cpu] -= 1
                runqlen[dest_cpu] += 1

                if (orig_cpu == 60):
                    print("Adding - task to cpu=60 migrate", common_secs, common_nsecs, runqlen[60])
                if (dest_cpu == 60):
                    print("Adding task to cpu=60 migrate", common_secs, common_nsecs, runqlen[60])

                if (confidence[orig_cpu] ==1 and runqlen[orig_cpu] < 0):
                    print("error orig", orig_cpu, str(common_secs)+"."+str(common_nsecs))


def sched__sched_switch(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, prev_comm, prev_pid, prev_prio, prev_state, 
        next_comm, next_pid, next_prio, perf_sample_dict):

                global runqlen

                # TASK_INTERRUPTIBLE = 0x001 => "S"
                # TASK_UNINTERRUPTIBLE = 0x002 => "D"
                if (prev_state == 1 or prev_state == 2):
                        runqlen[common_cpu] -= 1
                        if (common_cpu == 60):
                            print("Adding - task to cpu=60 switch", common_secs, common_nsecs, runqlen[60])


def sched__sched_wakeup(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, comm, pid, prio, success, 
        target_cpu, perf_sample_dict):

                global runqlen
                runqlen[target_cpu] += 1

                if (target_cpu == 60):
                    print("Adding task to cpu=60 wakeup", common_secs, common_nsecs, runqlen[60])

                # Taking sched trace in middle of workload screws the
                # runqlength count for this script as it won't know the initial
                # runqlength.
                # Hence confidence-1 iff the CPU entered idle
                # states somewhere in the trace
                global confidence
                if (confidence[target_cpu]==1):
                        if (runqlen[target_cpu] > 1):
                                print(str(common_comm) + " " + str(common_pid) + "\t" +
                                str(common_secs) + "." + str(common_nsecs) +
                                " problematic wakeup at cpu=" + str(common_cpu) +
                                " target_cpu="+str(target_cpu) + 
                                " runqlen="+str(runqlen[target_cpu]) + 
                                "\tcomm=" + comm + " " + str(pid))
                                pr()

                                first_cpu,last_cpu = sd_mask(common_cpu, LLC_CPUMASK_SIZE)
                                for i in range(first_cpu, last_cpu):
                                    if (is_idle_cpu(i)):
                                        print("It could have woken up on idle cpu=" + str(i))

                                print()

                #print_header(event_name, common_cpu, common_secs, common_nsecs, common_pid, common_comm)

def power__cpu_idle(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, state, cpu_id, perf_sample_dict):

                global runqlen
                if (state < 100):
                        if (confidence[cpu_id]==1 and runqlen[cpu_id]>0):
                            print("Runqueue not emptied before this", common_secs, common_nsecs, cpu_id)
                        runqlen[cpu_id] = 0
                        if (common_cpu == 60):
                            print("Adding - task to cpu=60 idle", common_secs, common_nsecs, runqlen[60], runqlen[60])
                        global confidence
                        confidence[cpu_id] = 1

def trace_unhandled(event_name, context, event_fields_dict, perf_sample_dict):
        print(get_dict_as_string(event_fields_dict))
        print('Sample: {'+get_dict_as_string(perf_sample_dict['sample'], ', ')+'}')

def print_header(event_name, cpu, secs, nsecs, pid, comm):
        print("%-20s %5u %05u.%09u %8u %-20s " % \
            (event_name, cpu, secs, nsecs, pid, comm), end="")

def get_dict_as_string(a_dict, delimiter=' '):
        return delimiter.join(['%s=%s'%(k,str(v))for k,v in sorted(a_dict.items())])
