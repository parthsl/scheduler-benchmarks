// From kernel 5.6-rc3
#include <linux/sched.h>

struct cfs_rq {
 struct load_weight load;
 unsigned int nr_running;
 unsigned int h_nr_running;
 unsigned int idle_h_nr_running;
 u64 exec_clock;
 u64 min_vruntime;
 struct rb_root_cached tasks_timeline;
 struct sched_entity *curr;
 struct sched_entity *next;
 struct sched_entity *last;
 struct sched_entity *skip;
 unsigned int nr_spread_over;
 struct sched_avg avg;
 struct {
  raw_spinlock_t lock __attribute__((__aligned__((1 << 7))));
  int nr;
  unsigned long load_avg;
  unsigned long util_avg;
  unsigned long runnable_avg;
 } removed;
 unsigned long tg_load_avg_contrib;
 long propagate;
 long prop_runnable_sum;
 unsigned long h_load;
 u64 last_h_load_update;
 struct sched_entity *h_load_next;
 struct rq *rq;
 int on_list;
 struct list_head leaf_cfs_rq_list;
 struct task_group *tg;
 int runtime_enabled;
 s64 runtime_remaining;
 u64 throttled_clock;
 u64 throttled_clock_task;
 u64 throttled_clock_task_time;
 int throttled;
 int throttle_count;
 struct list_head throttled_list;
};
