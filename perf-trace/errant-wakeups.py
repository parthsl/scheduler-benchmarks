# perf script event handlers, generated by perf script -g python
# Licensed under the terms of the GNU GPL License version 2

# The common_* event handler fields are the most useful fields common to
# all events.  They don't necessarily correspond to the 'common_*' fields
# in the format files.  Those fields not available as handler params can
# be retrieved using Python functions of the form common_*(context).
# See the perf-script-python Documentation for the list of available functions.

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

def trace_begin():
	print("Perf-script for finding if wakeups happen on busy CPUs despite?")

def trace_end():
    pr()

def sched__sched_migrate_task(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, comm, pid, prio, orig_cpu, 
        dest_cpu, perf_sample_dict):

                global runqlen
                runqlen[orig_cpu] -= 1
                runqlen[dest_cpu] += 1


def sched__sched_switch(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, prev_comm, prev_pid, prev_prio, prev_state, 
        next_comm, next_pid, next_prio, perf_sample_dict):

                global runqlen

                # TASK_INTERRUPTIBLE = 0x001 => "S"
                # TASK_UNINTERRUPTIBLE = 0x002 => "D"
                if (prev_state == 1 or prev_state == 2):
                        runqlen[common_cpu] -= 1


def sched__sched_wakeup(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, comm, pid, prio, success, 
        target_cpu, perf_sample_dict):

                global runqlen
                runqlen[target_cpu] += 1

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
                                print()

                #print_header(event_name, common_cpu, common_secs, common_nsecs, common_pid, common_comm)

def power__cpu_idle(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, state, cpu_id, perf_sample_dict):

                global runqlen
                if (state < 100):
                        runqlen[cpu_id] = 0
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
