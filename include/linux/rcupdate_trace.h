/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Read-Copy Update mechanism for mutual exclusion, adapted for tracing.
 *
 * Copyright (C) 2020 Paul E. McKenney.
 */

#ifndef __LINUX_RCUPDATE_TRACE_H
#define __LINUX_RCUPDATE_TRACE_H

#include <linux/sched.h>
#include <linux/rcupdate.h>

#ifdef CONFIG_DEBUG_LOCK_ALLOC
extern struct lockdep_map rcu_trace_lock_map;

static inline int rcu_read_lock_trace_held(void)
{
	return lock_is_held(&rcu_trace_lock_map);
}
#else
static inline int rcu_read_lock_trace_held(void)
{
	return 1;
}
#endif

#ifdef CONFIG_TASKS_TRACE_RCU

void rcu_read_unlock_trace_special(struct task_struct *t, int nesting);
void exit_tasks_rcu_finish_trace(struct task_struct *t);

/**
 * rcu_read_lock_trace - mark beginning of an RCU-trace read-side section
 *
 * Tasks Trace RCU readers may execute in idle and CPU-hotplug paths. Its
 * explicit reader markers let the grace-period worker wait for active readers
 * without imposing restrictions on where those readers run.
 */
static inline void rcu_read_lock_trace(void)
{
	struct task_struct *t = current;

	WRITE_ONCE(t->trc_reader_nesting, READ_ONCE(t->trc_reader_nesting) + 1);
	barrier();
	if (IS_ENABLED(CONFIG_TASKS_TRACE_RCU_READ_MB) &&
	    t->trc_reader_special.b.need_mb)
		smp_mb();
	rcu_lock_acquire(&rcu_trace_lock_map);
}

/**
 * rcu_read_unlock_trace - mark the end of an RCU-trace read-side section
 *
 * Pairs with a preceding rcu_read_lock_trace(); nesting is allowed.
 */
static inline void rcu_read_unlock_trace(void)
{
	int nesting;
	struct task_struct *t = current;

	rcu_lock_release(&rcu_trace_lock_map);
	nesting = READ_ONCE(t->trc_reader_nesting) - 1;
	barrier();
	WRITE_ONCE(t->trc_reader_nesting, INT_MIN);
	if (likely(!READ_ONCE(t->trc_reader_special.s)) || nesting) {
		WRITE_ONCE(t->trc_reader_nesting, nesting);
		return;
	}
	rcu_read_unlock_trace_special(t, nesting);
}

void call_rcu_tasks_trace(struct rcu_head *rhp, rcu_callback_t func);
void synchronize_rcu_tasks_trace(void);
void rcu_barrier_tasks_trace(void);
#else
/* The BPF JIT forms these addresses even when it does not call them. */
static inline void rcu_read_lock_trace(void) { BUG(); }
static inline void rcu_read_unlock_trace(void) { BUG(); }
static inline void call_rcu_tasks_trace(struct rcu_head *rhp,
					rcu_callback_t func) { BUG(); }
static inline void synchronize_rcu_tasks_trace(void) { BUG(); }
static inline void rcu_barrier_tasks_trace(void) { BUG(); }
static inline void exit_tasks_rcu_finish_trace(struct task_struct *t) { }
#endif /* CONFIG_TASKS_TRACE_RCU */

#endif /* __LINUX_RCUPDATE_TRACE_H */
