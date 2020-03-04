/*
 * This is the latest version of hackbench.c, that tests scheduler and
 * unix-socket (or pipe) performance.
 *
 * Usage: hackbench [-pipe] <num groups> [process|thread] [loops]
 *
 * Build it with:
 *   gcc -g -Wall -O2 -o hackbench hackbench.c -lpthread
 *
 * Downloaded from http://people.redhat.com/mingo/cfs-scheduler/tools/hackbench.c
 * February 19 2010.
 *
 */
/* Test groups of 20 processes spraying to 20 receivers */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <limits.h>
#define DATASIZE 100
static unsigned int loops = 100;
/*
 * 0 means thread mode and others mean process (default)
 */
static unsigned int process_mode = 1;
static int use_pipes = 0;
struct sender_context {
	unsigned int num_fds;
	int ready_out;
	int wakefd;
	int out_fds[0];
};
struct receiver_context {
	unsigned int num_packets;
	int in_fds[2];
	int ready_out;
	int wakefd;
};
typedef union {
	pthread_t threadid;
	pid_t     pid;
	long long error;
} childinfo_t;
static void barf(const char *msg)
{
	fprintf(stderr, "%s (error: %s)\n", msg, strerror(errno));
	exit(1);
}
static void print_usage_exit()
{
	printf("Usage: hackbench [-pipe] <num groups> [process|thread] [loops]\n");
	exit(1);
}
static void fdpair(int fds[2])
{
	if (use_pipes) {
		if (pipe(fds) == 0)
			return;
	} else {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0)
			return;
	}
	barf("Creating fdpair");
}
/* Block until we're ready to go */
static void ready(int ready_out, int wakefd)
{
	char dummy = '*';
	struct pollfd pollfd = { .fd = wakefd, .events = POLLIN };
	/* Tell them we're ready. */
	if (write(ready_out, &dummy, 1) != 1)
		barf("CLIENT: ready write");
	/* Wait for "GO" signal */
	if (poll(&pollfd, 1, -1) != 1)
		barf("poll");
}
/* Sender sprays loops messages down each file descriptor */
static void *sender(struct sender_context *ctx)
{
	char data[DATASIZE];
	unsigned int i, j;
	ready(ctx->ready_out, ctx->wakefd);
	memset(&data, '-', DATASIZE);
	/* Now pump to every receiver. */
	for (i = 0; i < loops; i++) {
		for (j = 0; j < ctx->num_fds; j++) {
			int ret, done = 0;
again:
			ret = write(ctx->out_fds[j], data + done, sizeof(data)-done);
			if (ret < 0)
				barf("SENDER: write");
			done += ret;
			if (done < sizeof(data))
				goto again;
		}
	}
	return NULL;
}
/* One receiver per fd */
static void *receiver(struct receiver_context* ctx)
{
	unsigned int i;
	if (process_mode)
		close(ctx->in_fds[1]);
	/* Wait for start... */
	ready(ctx->ready_out, ctx->wakefd);
	/* Receive them all */
	for (i = 0; i < ctx->num_packets; i++) {
		char data[DATASIZE];
		int ret, done = 0;
again:
		ret = read(ctx->in_fds[0], data + done, DATASIZE - done);
		if (ret < 0)
			barf("SERVER: read");
		done += ret;
		if (done < DATASIZE)
			goto again;
	}
	return NULL;
}
childinfo_t create_worker(void *ctx, void *(*func)(void *))
{
	pthread_attr_t attr;
	int err;
	childinfo_t child;
	pid_t childpid;
	switch (process_mode) {
		case 1: /* process mode */
			/* Fork the sender/receiver child. */
			switch ((childpid = fork())) {
				case -1:
					fprintf(stderr, "fork(): %s\n", strerror(errno));
					child.error = -1;
					return child;
				case 0:
					(*func) (ctx);
					exit(0);
			}
			child.pid = childpid;
			break;
		case 0: /* threaded mode */
			if (pthread_attr_init(&attr) != 0) {
				fprintf(stderr, "pthread_attr_init: %s\n", strerror(errno));
				child.error = -1;
				return child;
			}
#ifndef __ia64__
			if (pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN) != 0) {
				fprintf(stderr, "pthread_attr_setstacksize: %s\n", strerror(errno));
				child.error = -1;
				return child;
			}
#endif
			if ((err=pthread_create(&child.threadid, &attr, func, ctx)) != 0) {
				fprintf(stderr, "pthread_create failed: %s (%d)\n", strerror(err), err);
				child.error = -1;
				return child;
			}
			break;
	}
	return child;
}
unsigned int reap_workers(childinfo_t *child, unsigned int totchld, unsigned int dokill)
{
	unsigned int i, rc = 0;
	int status, err;
	void *thr_status;
	for( i = 0; i < totchld; i++ ) {
		switch( process_mode ) {
			case 1: /* process mode */
				if( dokill ) {
					kill(child[i].pid, SIGTERM);
				}
				fflush(stdout);
				waitpid(child[i].pid, &status, 0);
				if (!WIFEXITED(status))
					rc++;
				break;
			case 0: /* threaded mode */
				if( dokill ) {
					pthread_kill(child[i].threadid, SIGTERM);
				}
				err = pthread_join(child[i].threadid, &thr_status);
				if( err != 0 ) {
					fprintf(stderr, "pthread_join(): %s\n", strerror(err));
					rc++;
				}
				break;
		}
	}
	return rc;
}
/* One group of senders and receivers */
static unsigned int group(childinfo_t *child,
		unsigned int tab_offset,
		unsigned int num_fds,
		int ready_out,
		int wakefd)
{
	unsigned int i;
	struct sender_context* snd_ctx = malloc (sizeof(struct sender_context)
			+num_fds*sizeof(int));
	if (!snd_ctx) {
		fprintf(stderr, "** malloc() error (sender ctx): %s\n", strerror(errno));
		return 0;
	}
	for (i = 0; i < num_fds; i++) {
		int fds[2];
		struct receiver_context* ctx = malloc (sizeof(*ctx));
		if (!ctx) {
			fprintf(stderr, "** malloc() error (receiver ctx): %s\n", strerror(errno));
			return (i > 0 ? i-1 : 0);
		}
		/* Create the pipe between client and server */
		fdpair(fds);
		ctx->num_packets = num_fds*loops;
		ctx->in_fds[0] = fds[0];
		ctx->in_fds[1] = fds[1];
		ctx->ready_out = ready_out;
		ctx->wakefd = wakefd;
		child[tab_offset+i] = create_worker(ctx, (void *)(void *)receiver);
		if( child[tab_offset+i].error < 0 ) {
			return (i > 0 ? i-1 : 0);
		}
		snd_ctx->out_fds[i] = fds[1];
		if (process_mode)
			close(fds[0]);
	}
	/* Now we have all the fds, fork the senders */
	for (i = 0; i < num_fds; i++) {
		snd_ctx->ready_out = ready_out;
		snd_ctx->wakefd = wakefd;
		snd_ctx->num_fds = num_fds;
		child[tab_offset+num_fds+i] = create_worker(snd_ctx, (void *)(void *)sender);
		if( child[tab_offset+num_fds+i].error < 0 ) {
			return (num_fds+i)-1;
		}
	}
	/* Close the fds we have left */
	if (process_mode)
		for (i = 0; i < num_fds; i++)
			close(snd_ctx->out_fds[i]);
	/* Return number of children to reap */
	return num_fds * 2;
}
int main(int argc, char *argv[])
{
	unsigned int i, num_groups = 10, total_children;
	struct timeval start, stop, diff;
	unsigned int num_fds = 20;
	int readyfds[2], wakefds[2];
	char dummy;
	childinfo_t *child_tab;
	if (argv[1] && strcmp(argv[1], "-pipe") == 0) {
		use_pipes = 1;
		argc--;
		argv++;
	}
	if (argc >= 2 && (num_groups = atoi(argv[1])) == 0)
		print_usage_exit();
	printf("Running with %d*40 (== %d) tasks.\n",
			num_groups, num_groups*40);
	fflush(NULL);
	if (argc > 2) {
		if ( !strcmp(argv[2], "process") )
			process_mode = 1;
		else if ( !strcmp(argv[2], "thread") )
			process_mode = 0;
		else
			print_usage_exit();
	}
	if (argc > 3)
		loops = atoi(argv[3]);
	child_tab = malloc(num_fds * 2 * num_groups * sizeof(childinfo_t));
	if (!child_tab)
		barf("main:malloc()");
	fdpair(readyfds);
	fdpair(wakefds);
	total_children = 0;
	for (i = 0; i < num_groups; i++) {
		int c = group(child_tab, total_children, num_fds, readyfds[1], wakefds[0]);
		if( c > (num_fds*2) ) {
			reap_workers(child_tab, total_children, 1);
			fprintf(stderr, "%i children started?!?!?  Expected %i\n", c, num_fds*2);
			barf("Creating workers");
		}
		if( c < (num_fds*2) ) {
			reap_workers(child_tab, total_children + c, 1);
			barf("Creating workers");
		}
		total_children += c;
	}
	/* Wait for everyone to be ready */
	for (i = 0; i < total_children; i++)
		if (read(readyfds[0], &dummy, 1) != 1) {
			reap_workers(child_tab, total_children, 1);
			barf("Reading for readyfds");
		}
	gettimeofday(&start, NULL);
	/* Kick them off */
	if (write(wakefds[1], &dummy, 1) != 1) {
		reap_workers(child_tab, total_children, 1);
		barf("Writing to start them");
	}
	/* Reap them all */
	reap_workers(child_tab, total_children, 0);
	gettimeofday(&stop, NULL);
	/* Print time... */
	timersub(&stop, &start, &diff);
	printf("Time: %lu.%03lu\n", diff.tv_sec, diff.tv_usec/1000);
	free(child_tab);
	exit(0);
}
