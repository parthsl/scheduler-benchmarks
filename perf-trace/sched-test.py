# Licensed under the terms of the GNU GPL License version 2
# See the perf-script-python Documentation for the list of available functions.
#
# This script parses perf.data file recorded with following events
# perf record -e sched:sched_wakeup,sched:sched_wakeup_new,sched:sched_switch,sched:sched_waking,sched:sched_migrate_task,sched:sched_update_nr_running -aR
# 
# The sched:sched_update_nr_running trace event can be registered/activated using below module
# https://github.ibm.com/pshah015/tracepoint-modules for loading extra modules
# 
# Sample output:
# ==============
# Perf-script for finding if wakeups happen on busy CPUs despite?
# Script parameters: 
# WAKEUP_SCOPE_SIZE :  8
# OFFLINE_CPUS :  []
# NR_CPUS :  176
# ============================Starting perf-script===========================
# Correct wakeup decision on idle rq =  2754
# Correct wakeup decision in busy cpu =  637
# Incorrect wakeup decision = 14
# Accuracy =  99.58883994126285 %
# ------------------Scheduler decision latency(in us)-------------------------
# 50%ile:          5.016
# 90%ile:          11.12
# 99%ile:          15.048
# 99.99%ile:       83.248
# ------------------Scheduling Latency (in us)--------------------------------
# 50%ile:          5.072
# 90%ile:          16.498
# 99%ile:          44.626
# 99.99%ile:       1205.182
# ------------------SMT Mode of target_cpu during sched_wakeup----------------
# key:value = SMT-mode : sample-count = {1: 2922, 2: 358, 3: 70, 4: 55}
# ------------------#Wake affine pulled---------------------------------------
# Number of times a task got pulled to waker's llc =  8
# ------------------Pre-migration wait time (in us)---------------------------
# Very few migrations occured. Wait time =  [22.42, 25.006, 14.744, 71.886]
# 
# NOTE: SET "SCRIPT SPECIFIC TUNABLES" BEFORE USING
# @author: Parth Shah <parth@linux.ibm.com>

from __future__ import print_function

import os
import sys
import math

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
	'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *

def percentile(data, percentile):
    size = len(data)
    return sorted(data)[int(math.ceil((size * percentile) / 100)) - 1]

# script specific tunables
NR_CPUS = 176
WAKEUP_SCOPE_SIZE = 8
LATENCY_THRESHOLD_US = (10**3)*10 # 10ms
VERBOSE_LEVEL = 1 # 0-No extra info, 1-wakeup errors, 2-runqlength at every wakeup
# OFFLINE_CPUS = [2*i+1 for i in range(40)] # odd threads are offline
OFFLINE_CPUS = [] # range(40, 80) # CPUs 40-79 are offline
WHITELIST_TASKS = [] #["schbench", "kubelet"]


# variables
runqlen = [0 for i in range(NR_CPUS)]
correct_decision_on_idle_cpu = 0
correct_decision_on_busy_cpu = 0
incorrect_decision = 0

# type-of event marked
WAKEUP = 1
WAKING = 2
SWITCH = 3
MIGRATE = 4
NR_RUNNING = 5

class Mark:
    def __init__(self, sec, nsec, event_type, waker_cpu=-1, wakee_pid=-1, prev_cpu=-1, target_cpu=-1):
        self.sec = sec
        self.nsec = nsec
        self.event_type = event_type
        self.waker_cpu = waker_cpu
        self.wakee_pid = wakee_pid
        self.prev_cpu = prev_cpu
        self.target_cpu = target_cpu

    def time_diff(self, sec, nsec):
        '''
        sec,nsec should be greater than self.sec
        '''
        diff = (sec - self.sec)*(10**9)
        diff += (nsec - self.nsec)
        return diff/(10**3)


# Store information like ktime, nr_running, etc. for each pid
pid_timehist = dict()
cpu_timehist = dict()

# DECISION flags, used as enumeration
CORRECT_DECISION_ON_IDLE_CPU = 1
CORRECT_DECISION_ON_BUSY_CPU = 2
INCORRECT_DECISION = 3

# Results storing variable
sched_latency = []
scheduler_decision_latency = []
smt_after_wakeup = dict() #If a task wakes up on idle core then it is said to be woken up on SMT-1.
wake_affine_pulled = 0 # Counter to keep track
pre_migration_wait_time = [] # Keep track of time spent after wakeup and before migration of task happens

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
    print_runqlen(20, NR_CPUS//20+1)


def is_idle_cpu(cpu):
    global runqlen

    return runqlen[cpu]

def is_comm_blacklist(comm):
    blacklist = ["migration", "kworker", "ksoftirqd"]

    if len(WHITELIST_TASKS)>0:
        for i in WHITELIST_TASKS:
            if i in comm:
                return False
        return True
    
    for i in blacklist:
        if i in comm:
            return True

    return False

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

def smt_mask(cpu, smt_size=4):
    return sd_mask(cpu, smt_size)

def nr_busy_in_smt(cpu, smt_size=4):
    smt_cpu_first,smt_cpu_last = smt_mask(cpu)
    smt_mode = smt_size
    global runqlen
    for i in range(smt_cpu_first, smt_cpu_last):
        if runqlen[i] == 0:
            smt_mode -= 1
    return smt_mode

def print_latency_hist(data):
    print('50%ile:\t\t', percentile(data, 50))
    print('90%ile:\t\t', percentile(data, 90))
    print('99%ile:\t\t', percentile(data, 99))
    print('99.99%ile:\t', percentile(data, 99.99))


def sched__sched_migrate_task(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, comm, pid, prio, orig_cpu, 
        dest_cpu, perf_sample_dict):
                
                global pid_timehist

                if pid in pid_timehist and pid_timehist[pid].event_type == WAKEUP:
                    wakeup_event = pid_timehist[pid]
                    global pre_migration_wait_time
                    pre_migration_wait_time.append(wakeup_event.time_diff(common_secs, common_nsecs))                    

                # if (runqlen[orig_cpu] < 0):
                #     print("error with -ve runq at orig_cpu=", orig_cpu,
                #             str(common_secs)+"."+str(common_nsecs))


def sched__sched_switch(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, prev_comm, prev_pid, prev_prio, prev_state, 
        next_comm, next_pid, next_prio, perf_sample_dict):

                global runqlen
                global pid_timehist

                if next_pid in pid_timehist and pid_timehist[next_pid].event_type==WAKEUP:
                    wakeup_mark = pid_timehist[next_pid]
                    tdiff = wakeup_mark.time_diff(common_secs, common_nsecs)
                    global sched_latency
                    sched_latency.append(tdiff)

                    if VERBOSE_LEVEL >= 1 and tdiff > (LATENCY_THRESHOLD_US):
                        print("Higher latency observed for wakeup at ktime=", wakeup_mark.sec, wakeup_mark.nsec)
                        print()

                if next_pid in pid_timehist:
                    del(pid_timehist[next_pid])


def sched__sched_waking(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, prio, success, 
	target_cpu, perf_sample_dict):
        # target_cpu is treated as prev_cpu
        global pid_timehist

        mark = Mark(common_secs, common_nsecs, event_type=WAKING, prev_cpu=target_cpu, waker_cpu=common_cpu)
        pid_timehist[pid] = mark
        cpu_timehist[common_cpu] = mark

def sched__sched_wakeup(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, comm, pid, prio, success, 
        target_cpu, perf_sample_dict):

                global scheduler_decision_latency
                global pid_timehist
                global runqlen
                global smt_after_wakeup
                is_wake_affine_pulled = False

                # Track pid which gets consumed in sched_switch
                prev_cpu = -1
                waker_cpu = -1
                if pid in pid_timehist and pid_timehist[pid].event_type==WAKING:
                    waking_mark = pid_timehist[pid]
                    scheduler_decision_latency.append(waking_mark.time_diff(common_secs, common_nsecs))
                    prev_cpu = waking_mark.prev_cpu
                    waker_cpu = waking_mark.waker_cpu

                pid_timehist[pid] = Mark(common_secs, common_nsecs, event_type=WAKEUP, prev_cpu=prev_cpu, waker_cpu=waker_cpu, target_cpu=target_cpu)
                
                # Update smt_after_wakeup
                target_smt_mode = nr_busy_in_smt(target_cpu)
                if target_smt_mode in smt_after_wakeup:
                    smt_after_wakeup[target_smt_mode] += 1
                else:
                    smt_after_wakeup[target_smt_mode] = 1

                # Analyse affinity related decision
                # If prev_cpu and waker_cpu are in same sd then affinity does not matter
                cpu_mask_tuple = sd_mask(waker_cpu, WAKEUP_SCOPE_SIZE)
                waker_sd_llc = range(cpu_mask_tuple[0], cpu_mask_tuple[1])

                if waker_cpu in waker_sd_llc and prev_cpu in waker_sd_llc:
                    '''
                    If prev_cpu and waker_cpu both share LLC then wake affine never happens
                    '''
                    pass
                else:
                    if target_cpu != prev_cpu:
                        global wake_affine_pulled
                        wake_affine_pulled += 1
                        is_wake_affine_pulled = True

                # review scheduler wakeup decisions
                decision = CORRECT_DECISION_ON_IDLE_CPU
                suggestion_str = ""
                if (runqlen[target_cpu] > 1) and prev_cpu != -1 and waker_cpu != -1:
                        decision = CORRECT_DECISION_ON_BUSY_CPU

                        # print(str(common_comm) + " prev_cpu=" + str(prev_cpu) + "\t" +
                        # str(common_secs) + "." + str(common_nsecs) +
                        # " problematic wakeup at cpu=" + str(common_cpu) +
                        # " target_cpu="+str(target_cpu) + 
                        # " runqlen="+str(runqlen[target_cpu]) + 
                        # "\tcomm=" + comm + " " + str(pid))
                        if VERBOSE_LEVEL >= 2:
                            pr()

                        if is_comm_blacklist(comm):
                            pass
                        else:
                            for loop in range(2):
                                if loop == 0:
                                    llc_mask = sd_mask(waker_cpu, WAKEUP_SCOPE_SIZE)
                                else:
                                    llc_mask = sd_mask(prev_cpu, WAKEUP_SCOPE_SIZE)
                                range_sd_llc = range(llc_mask[0], llc_mask[1])

                                for i in range_sd_llc:
                                    if i in OFFLINE_CPUS:
                                        continue
                                    if (is_idle_cpu(i)==0):
                                        if (suggestion_str == ""):
                                            suggestion_str = str(comm)+"/"+str(pid)+" could have woken up on idle cpu = "
                                        suggestion_str += str(i)+", "
                                        decision = INCORRECT_DECISION
                            
                                if prev_cpu in waker_sd_llc:
                                    break

                            if VERBOSE_LEVEL >= 1:
                                if waker_cpu in waker_sd_llc and prev_cpu in waker_sd_llc:
                                    print (suggestion_str, 'where target_cpu = ', target_cpu)
                                else:
                                    print(suggestion_str, "\twhere waker_cpu = ", waker_cpu, " and prev_cpu = ", prev_cpu, " and target_cpu = ", target_cpu)


                global correct_decision_on_idle_cpu
                global correct_decision_on_busy_cpu
                global incorrect_decision
                if decision == CORRECT_DECISION_ON_IDLE_CPU:
                    correct_decision_on_idle_cpu += 1
                elif decision == CORRECT_DECISION_ON_BUSY_CPU:
                    correct_decision_on_busy_cpu += 1
                else:
                    incorrect_decision += 1


def power__cpu_idle(event_name, context, common_cpu,
        common_secs, common_nsecs, common_pid, common_comm,
        common_callchain, state, cpu_id, perf_sample_dict):
    pass

def sched__sched_update_nr_running(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, cpu, change, nr_running, perf_sample_dict):

                global runqlen
                runqlen[cpu] = nr_running


def trace_unhandled(event_name, context, event_fields_dict, perf_sample_dict):
        print(get_dict_as_string(event_fields_dict))
        print('Sample: {'+get_dict_as_string(perf_sample_dict['sample'], ', ')+'}')

def print_header(event_name, cpu, secs, nsecs, pid, comm):
        print("%-20s %5u %05u.%09u %8u %-20s " % \
            (event_name, cpu, secs, nsecs, pid, comm), end="")

def get_dict_as_string(a_dict, delimiter=' '):
        return delimiter.join(['%s=%s'%(k,str(v))for k,v in sorted(a_dict.items())])

def trace_begin():
    print("Perf-script for calculating scheduler wakeup stats")
    print("Script parameters: ")
    print("WAKEUP_SCOPE_SIZE : ", WAKEUP_SCOPE_SIZE)
    print("OFFLINE_CPUS : ", OFFLINE_CPUS)
    print("NR_CPUS : ", NR_CPUS)
    print("============================Starting perf-script===========================\n")

def trace_end():
    global correct_decision_on_idle_cpu
    global correct_decision_on_busy_cpu
    global incorrect_decision
    print("Correct wakeup decision on idle rq = ", correct_decision_on_idle_cpu)
    print("Correct wakeup decision in busy cpu = ", correct_decision_on_busy_cpu)
    print("Incorrect wakeup decision =", incorrect_decision)
    ratio = correct_decision_on_idle_cpu + correct_decision_on_busy_cpu
    ratio = (ratio*100)/(incorrect_decision+ratio)
    print("Accuracy = ", ratio, "%")
    # print("---------------------------------------------------------------\n")
    # pr()
    global pid_timehist
    global sched_latency
    global scheduler_decision_latency
    print('------------------Scheduler decision latency(in us)-------------------------')
    print_latency_hist(scheduler_decision_latency)
    print('------------------Scheduling Latency (in us)--------------------------------')
    print_latency_hist(sched_latency)
    print('------------------SMT Mode of target_cpu during sched_wakeup----------------')
    print('key:value = SMT-mode : sample-count =', smt_after_wakeup)
    print('------------------#Wake affine pulled---------------------------------------')
    print('Number of times a task got pulled to waker\'s llc = ', wake_affine_pulled)
    print('------------------Pre-migration wait time (in us)---------------------------')
    global pre_migration_wait_time
    if (len(pre_migration_wait_time) < 10):
        print("Very few migrations occured. Wait time = ", pre_migration_wait_time)
    else:
        print_latency_hist(pre_migration_wait_time)
