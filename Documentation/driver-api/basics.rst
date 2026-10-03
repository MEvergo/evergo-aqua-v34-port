Driver Basics
=============

Driver Entry and Exit points
----------------------------

.. kernel-doc:: include/linux/module.h
   :internal:

Driver device table
-------------------

.. kernel-doc:: include/linux/mod_devicetable.h
   :internal:

Kernel hardware-breakpoint stepping
-----------------------------------

Kernel consumers can use ``register_user_hw_breakpoint_flags()`` with
``HW_BREAKPOINT_FLAG_STEP_ON_HIT`` to request ARM64's automatic step-over
behavior for a custom overflow callback. The execute and watchpoint handlers
disable the relevant debug registers, perform one instruction step, and
restore them through the existing single-step path. The callback does not
need to advance the PC or install its own stepping logic.

The flags are per event and kernel-only: ``perf_event_attr``, ptrace and
existing user interfaces are unchanged. The original registration helper and
unflagged custom callbacks retain their previous behavior. The default perf
handler continues to auto-step. Watchpoints taken during kernel uaccess keep
their existing callback-skipping and stepping behavior.

Registration allocates the event disabled, stores the flags, and restores the
requested enabled state before publishing the event to the task. This avoids
first-hit, concurrent-fork and enable-on-exec windows. The caller's attributes
are not modified. Flags survive breakpoint modifications, caller-driven
rollback and callback inheritance. Unknown flags return ``ERR_PTR(-EINVAL)``;
without hardware-breakpoint support the helper returns ``ERR_PTR(-ENOSYS)``.
Removal still uses ``unregister_hw_breakpoint()``.

.. kernel-doc:: kernel/events/hw_breakpoint.c
   :functions: register_user_hw_breakpoint_flags


Atomic and pointer manipulation
-------------------------------

.. kernel-doc:: arch/x86/include/asm/atomic.h
   :internal:

Delaying, scheduling, and timer routines
----------------------------------------

.. kernel-doc:: include/linux/sched.h
   :internal:

.. kernel-doc:: kernel/sched/core.c
   :export:

.. kernel-doc:: kernel/sched/cpupri.c
   :internal:

.. kernel-doc:: kernel/sched/fair.c
   :internal:

.. kernel-doc:: include/linux/completion.h
   :internal:

.. kernel-doc:: kernel/time/timer.c
   :export:

Wait queues and Wake events
---------------------------

.. kernel-doc:: include/linux/wait.h
   :internal:

.. kernel-doc:: kernel/sched/wait.c
   :export:

High-resolution timers
----------------------

.. kernel-doc:: include/linux/ktime.h
   :internal:

.. kernel-doc:: include/linux/hrtimer.h
   :internal:

.. kernel-doc:: kernel/time/hrtimer.c
   :export:

Workqueues and Kevents
----------------------

.. kernel-doc:: include/linux/workqueue.h
   :internal:

.. kernel-doc:: kernel/workqueue.c
   :export:

Internal Functions
------------------

.. kernel-doc:: kernel/exit.c
   :internal:

.. kernel-doc:: kernel/signal.c
   :internal:

.. kernel-doc:: include/linux/kthread.h
   :internal:

.. kernel-doc:: kernel/kthread.c
   :export:

Kernel objects manipulation
---------------------------

.. kernel-doc:: lib/kobject.c
   :export:

Kernel utility functions
------------------------

.. kernel-doc:: include/linux/kernel.h
   :internal:

.. kernel-doc:: kernel/printk/printk.c
   :export:

.. kernel-doc:: kernel/panic.c
   :export:

.. kernel-doc:: kernel/rcu/tree.c
   :export:

.. kernel-doc:: kernel/rcu/tree_plugin.h
   :export:

.. kernel-doc:: kernel/rcu/update.c
   :export:

Device Resource Management
--------------------------

.. kernel-doc:: drivers/base/devres.c
   :export:

