/*
 * This program provides a synthetic workload creation for testing of affinity
 * changes related kernel code changes.
 *
 * Author(s): Parth Shah <parth@linux.ibm.com> <parths1229@gmail.com>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <sched.h>
#include <pthread.h>
#include <errno.h>
#include <getopt.h>
#include <sys/syscall.h>
#include <signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/types.h>
#include <sys/syscall.h>

static int nr_threads;
static long long unsigned int array_size;
static long long unsigned timeout;
static long long unsigned int output_small = 0;
static int bind = 0;
pthread_mutex_t output_small_lock;

void tv_copy(struct timeval* tdest, struct timeval* tsrc)
{
	tdest->tv_sec = tsrc->tv_sec;
	tdest->tv_usec = tsrc->tv_usec;
}

void tvsub(struct timeval * tdiff, struct timeval * t1, struct timeval * t0)
{
	tdiff->tv_sec = t1->tv_sec - t0->tv_sec;
	tdiff->tv_usec = t1->tv_usec - t0->tv_usec;
	if (tdiff->tv_usec < 0 && tdiff->tv_sec > 0) {
		tdiff->tv_sec--;
		tdiff->tv_usec += 1000000;
		if (tdiff->tv_usec < 0) {
			fprintf(stderr, "lat_fs: tvsub shows test time ran \
					backwards!\n"); exit(1);
		}
	}

	/* time shouldn't go backwards!!! */
	if (tdiff->tv_usec < 0 || t1->tv_sec < t0->tv_sec) {
		tdiff->tv_sec = 0;
		tdiff->tv_usec = 0;
	}
}

/*
 * returns the difference between start and stop in usecs.  Negative values are
 * turned into 0
 */
unsigned long long tvdelta(struct timeval *start, struct timeval *stop)
{
	struct timeval td;
	unsigned long long usecs;

	tvsub(&td, stop, start);
	usecs = td.tv_sec;
	usecs *= 1000000;
	usecs += td.tv_usec;
	return (usecs);
}

int stick_this_thread_to_cpus(int *cpumask, int cpumask_length)
{
	int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	for(int i=0;i<cpumask_length; i++){
		if (cpumask[i] < 0 || cpumask[i] >= num_cores)
			return EINVAL;
		CPU_SET(cpumask[i], &cpuset);
	}

	pthread_t current_thread = pthread_self();    
	return pthread_setaffinity_np(current_thread, sizeof(cpu_set_t),
			&cpuset); }

void handle_sigint(int sig) 
{
	pthread_exit(NULL);
}

static int kill_force = 0;
void kill_signal(int sig)
{
	kill_force = 1;
}

static int cpumasks[2][4] = {{0,8,16,24}, {4,12,20,28}};
int cpumask_len =4;

void* worker(void *data)
{
	long long unsigned int sum = 0;
	struct timeval t1,t2;
	long long unsigned int period = 100000;
	long long unsigned int run_period = 30000;
	long long unsigned int wall_clock;
	int turn = 0;

	while(1){
		if(bind) {
			stick_this_thread_to_cpus(cpumasks[turn%2], cpumask_len);
			turn++;
		}

		gettimeofday(&t1,NULL);
		gettimeofday(&t2,NULL);

		while (tvdelta(&t1, &t2) < run_period) {
			for(int j=0;j<4*array_size; j++)
				sum += 45;
			gettimeofday(&t2,NULL);
			wall_clock = tvdelta(&t1, &t2);
		}
		pthread_mutex_lock(&output_small_lock);
		output_small += array_size;
		pthread_mutex_unlock(&output_small_lock);
		wall_clock = tvdelta(&t1,&t2);
		usleep(period-wall_clock);
	}

	return NULL;
}



enum {
	HELP_LONG_OPT = 1,
};
char *option_string = "t:h:n:bju";
static struct option long_options[] = {
	{"timeout", required_argument, 0, 't'},
	{"threads", required_argument, 0, 'n'},
	{"bind", no_argument, 0, 'b'},
	{"help", no_argument, 0, HELP_LONG_OPT},
	{0, 0, 0, 0}
};

static void print_usage(void)
{
	fprintf(stderr, "affinity_test usage:\n"
			"\t-t (--timeout): Execution time for the workload in s (def: 10) \n"
			"\t -n (--threads): Total threads to be spawned\n"
			"\t -b (--bind): Bind the threads\n"
	       );
	exit(1);
}

static void parse_options(int ac, char **av)
{
	int c;

	while (1) {
		int option_index = 0;

		c = getopt_long(ac, av, option_string,
				long_options, &option_index);

		if (c == -1)
			break;

		switch(c) {
			case 't':
				sscanf(optarg,"%llu",&timeout);
				timeout = timeout*1000000;
				break;
			case 'n':
				nr_threads = atoi(optarg);
				break;
			case 'b':
				bind = 1;
				break;
			case '?':
			case HELP_LONG_OPT:
				print_usage();
				break;
			default:
				break;
		}
	}

	if (optind < ac) {
		fprintf(stderr, "Error Extra arguments '%s'\n", av[optind]);
		exit(1);
	}
}

int main(int argc, char**argv){
	struct timeval t1,t2;
	pthread_t *tid;
	nr_threads = 16;
	array_size = 10000;
	timeout = 10000000;

	parse_options(argc, argv);
	printf("Running with array_size=%lld, total threads=%d\n",
			array_size, nr_threads);

	srand(time(NULL));
	tid = (pthread_t*)malloc(sizeof(pthread_t)*nr_threads);

	signal(SIGUSR1, handle_sigint);
	signal(SIGINT, kill_signal);

	gettimeofday(&t1,NULL);
	for(int i=0; i<nr_threads; i++)
	{
		pthread_create(&tid[i],NULL, worker, NULL);
	}

	while(1){
		gettimeofday(&t2,NULL);
		if(tvdelta(&t1,&t2) >= timeout || kill_force){
			for(int i=0; i<nr_threads; i++)
				pthread_kill(tid[i], SIGUSR1);
			break;
		}
		else
		usleep(100);
	}

	for(int i=0; i<nr_threads; i++)
		pthread_join(tid[i], NULL);

	printf("Total  Operations=%llu, time passed=%lld us\n", output_small, tvdelta(&t1,&t2));

	return 0;
}
