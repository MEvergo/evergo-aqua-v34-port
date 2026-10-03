/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HW_BREAKPOINT_H
#define _LINUX_HW_BREAKPOINT_H

#include <linux/err.h>
#include <linux/perf_event.h>
#include <uapi/linux/hw_breakpoint.h>

/**
 * HW_BREAKPOINT_FLAG_STEP_ON_HIT - single-step automatically after a hit
 *
 * On architectures that support it, single-step the instruction following a
 * user hardware breakpoint hit, even when the event uses a custom callback.
 */
#define HW_BREAKPOINT_FLAG_STEP_ON_HIT	(1UL << 0)

/**
 * struct hw_breakpoint_resources - ARM64 debug-register capacity
 * @brps: total instruction-breakpoint register pairs available per CPU
 * @wrps: total watchpoint register pairs available per CPU
 *
 * These are the sanitized capacities used by perf, not free-slot counts
 * or sums across online CPUs.
 */
struct hw_breakpoint_resources {
	unsigned int brps;
	unsigned int wrps;
};

/**
 * struct hw_breakpoint_config - last validated ARM64 register configuration
 * @address: normalized address for the address register
 * @bas: eight-bit byte-address-select mask, not a byte length
 */
struct hw_breakpoint_config {
	u64 address;
	u32 bas;
};

#ifdef CONFIG_HAVE_HW_BREAKPOINT

extern int __init init_hw_breakpoint(void);

static inline void hw_breakpoint_init(struct perf_event_attr *attr)
{
	memset(attr, 0, sizeof(*attr));

	attr->type = PERF_TYPE_BREAKPOINT;
	attr->size = sizeof(*attr);
	/*
	 * As it's for in-kernel or ptrace use, we want it to be pinned
	 * and to call its callback every hits.
	 */
	attr->pinned = 1;
	attr->sample_period = 1;
}

static inline void ptrace_breakpoint_init(struct perf_event_attr *attr)
{
	hw_breakpoint_init(attr);
	attr->exclude_kernel = 1;
}

static inline unsigned long hw_breakpoint_addr(struct perf_event *bp)
{
	return bp->attr.bp_addr;
}

static inline int hw_breakpoint_type(struct perf_event *bp)
{
	return bp->attr.bp_type;
}

static inline unsigned long hw_breakpoint_len(struct perf_event *bp)
{
	return bp->attr.bp_len;
}

/**
 * register_user_hw_breakpoint_flags - register a user-space hardware breakpoint
 * @attr: breakpoint attributes
 * @triggered: callback to trigger when the breakpoint is hit
 * @context: user-supplied callback context
 * @tsk: task to which the address belongs
 * @flags: kernel-only %HW_BREAKPOINT_FLAG_* flags
 *
 * Unlike register_user_hw_breakpoint(), this helper allows a caller to opt in
 * to architecture-provided behavior such as automatic single-stepping after
 * each hit.  The flags belong to this event and are not part of @attr.
 *
 * Return: a pointer to the event, or an ERR_PTR() on failure.
 */
extern struct perf_event *
register_user_hw_breakpoint_flags(struct perf_event_attr *attr,
				  perf_overflow_handler_t triggered,
				  void *context,
				  struct task_struct *tsk,
				  unsigned long flags);

/**
 * register_user_hw_breakpoint - register a hardware breakpoint for user space
 * @attr: breakpoint attributes
 * @triggered: callback to trigger when we hit the breakpoint
 * @context: user-supplied callback context
 * @tsk: pointer to 'task_struct' of the process to which the address belongs
 *
 * This preserves the existing default behavior; it does not opt in to
 * architecture-specific behavior controlled by
 * register_user_hw_breakpoint_flags().
 */
extern struct perf_event *
register_user_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context,
			    struct task_struct *tsk);

/* FIXME: only change from the attr, and don't unregister */
extern int
modify_user_hw_breakpoint(struct perf_event *bp, struct perf_event_attr *attr);

extern int
hw_breakpoint_get_resources(struct hw_breakpoint_resources *resources);
extern int
hw_breakpoint_get_config(struct perf_event *bp,
			 struct hw_breakpoint_config *config);

/*
 * Kernel breakpoints are not associated with any particular thread.
 */
extern struct perf_event *
register_wide_hw_breakpoint_cpu(struct perf_event_attr *attr,
				perf_overflow_handler_t	triggered,
				void *context,
				int cpu);

extern struct perf_event * __percpu *
register_wide_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context);

extern int register_perf_hw_breakpoint(struct perf_event *bp);
extern int __register_perf_hw_breakpoint(struct perf_event *bp);
extern void unregister_hw_breakpoint(struct perf_event *bp);
extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);

extern int dbg_reserve_bp_slot(struct perf_event *bp);
extern int dbg_release_bp_slot(struct perf_event *bp);
extern int reserve_bp_slot(struct perf_event *bp);
extern void release_bp_slot(struct perf_event *bp);

extern void flush_ptrace_hw_breakpoint(struct task_struct *tsk);

static inline struct arch_hw_breakpoint *counter_arch_bp(struct perf_event *bp)
{
	return &bp->hw.info;
}

#else /* !CONFIG_HAVE_HW_BREAKPOINT */

static inline int __init init_hw_breakpoint(void) { return 0; }

static inline int
hw_breakpoint_get_resources(struct hw_breakpoint_resources *resources)
{
	return -ENOSYS;
}

static inline int
hw_breakpoint_get_config(struct perf_event *bp,
			 struct hw_breakpoint_config *config)
{
	return -ENOSYS;
}

static inline struct perf_event *
register_user_hw_breakpoint_flags(struct perf_event_attr *attr,
				  perf_overflow_handler_t triggered,
				  void *context,
				  struct task_struct *tsk,
				  unsigned long flags)
{
	return ERR_PTR(-ENOSYS);
}
static inline struct perf_event *
register_user_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context,
			    struct task_struct *tsk)	{ return NULL; }
static inline int
modify_user_hw_breakpoint(struct perf_event *bp,
			  struct perf_event_attr *attr)	{ return -ENOSYS; }
static inline struct perf_event *
register_wide_hw_breakpoint_cpu(struct perf_event_attr *attr,
				perf_overflow_handler_t	 triggered,
				void *context,
				int cpu)		{ return NULL; }
static inline struct perf_event * __percpu *
register_wide_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context)		{ return NULL; }
static inline int
register_perf_hw_breakpoint(struct perf_event *bp)	{ return -ENOSYS; }
static inline int
__register_perf_hw_breakpoint(struct perf_event *bp) 	{ return -ENOSYS; }
static inline void unregister_hw_breakpoint(struct perf_event *bp)	{ }
static inline void
unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)	{ }
static inline int
reserve_bp_slot(struct perf_event *bp)			{return -ENOSYS; }
static inline void release_bp_slot(struct perf_event *bp) 		{ }

static inline void flush_ptrace_hw_breakpoint(struct task_struct *tsk)	{ }

static inline struct arch_hw_breakpoint *counter_arch_bp(struct perf_event *bp)
{
	return NULL;
}

#endif /* CONFIG_HAVE_HW_BREAKPOINT */
#endif /* _LINUX_HW_BREAKPOINT_H */
