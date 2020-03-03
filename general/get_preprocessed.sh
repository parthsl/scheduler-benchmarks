#! /bin/bash

# This scripts creates pre-processed <file>.i and parses it to get
# struct cfs_rq.
#
# e.g. 
# bash -c "kernel_src=/root/parth/linux/ ./get_p.sh"
#
# Uses idle.c file to pre-process as it is the shortest file including
# sched/sched.h header file

# Set target kernel source tree, file and struct to be extracted

if [ -z $kernel_src ]; then
	kernel_src=/root/linux/
fi
tfile=$kernel_src/kernel/sched/idle.i
tstruct="struct cfs_rq"

# Change above variables as per requirement

tstruct=$tstruct" {"

make $tfile -j `nproc`
cat $tfile | awk '
BEGIN{is_cfs=0}
{
	if(match($0, var)==1)is_cfs=1;
	if(is_cfs==1 && length($0)>=1 && substr($0, 0,1)!="#")print;
	if(match($0, "};")==1 && length($0)==2)is_cfs=0;
}' var="$tstruct"
