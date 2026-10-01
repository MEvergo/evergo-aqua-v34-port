#ifndef __KSU_H_KSU_SYSCALL_HOOK
#define __KSU_H_KSU_SYSCALL_HOOK
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/version.h>

#if defined(__aarch64__) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
typedef asmlinkage long (*syscall_fn_t)(unsigned long, unsigned long,
                                       unsigned long, unsigned long,
                                       unsigned long, unsigned long);
#endif

#if defined(__x86_64__)
typedef sys_call_ptr_t syscall_fn_t;
#endif

extern syscall_fn_t *ksu_syscall_table;

// Dispatcher slot number in syscall table
extern int ksu_dispatcher_nr;

// Route the saved user registers through the kernel's syscall ABI.
typedef long (*ksu_syscall_hook_fn)(int orig_nr, const struct pt_regs *regs);

static inline long ksu_call_saved_syscall(syscall_fn_t fn, const struct pt_regs *regs)
{
#if defined(__aarch64__) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
    return fn(regs->regs[0], regs->regs[1], regs->regs[2],
              regs->regs[3], regs->regs[4], regs->regs[5]);
#else
    return fn(regs);
#endif
}

static inline long ksu_call_original_syscall(int nr, const struct pt_regs *regs)
{
    return ksu_call_saved_syscall(ksu_syscall_table[nr], regs);
}

// --- Dispatcher-based hook API (register/unregister) ---
// Register a handler into the dispatcher's routing table for syscall @nr.
// When a marked process invokes syscall @nr, the sys_enter tracepoint redirects
// it to the unified dispatcher, which looks up @fn by @nr and calls it.
// Does NOT modify the syscall table itself — the dispatcher slot is shared.
// Returns 0 on success, -EEXIST if already registered, -EINVAL if nr invalid.
int ksu_register_syscall_hook(int nr, ksu_syscall_hook_fn fn);

// Remove a handler from the dispatcher's routing table for syscall @nr.
// The syscall table is not touched — only the dispatcher stops routing @nr.
void ksu_unregister_syscall_hook(int nr);

// Check if a handler is registered in the dispatcher for syscall @nr.
bool ksu_has_syscall_hook(int nr);

// --- Direct syscall table patching API (hook/unhook) ---
// Directly overwrite syscall_table[@nr] with @fn using fixmap + stop_machine.
// Saves the original handler to *@old (if non-NULL) and records the entry
// for restoration at module exit. Use this for boot-time hooks that replace
// a real syscall entry (e.g. ksud hooking __NR_execve/__NR_read/__NR_fstat).
void ksu_syscall_table_hook(int nr, syscall_fn_t fn, syscall_fn_t *old);

// Restore syscall_table[@nr] to its original value recorded by
// ksu_syscall_table_hook(), and remove the entry from the tracking list.
// Use this to cleanly undo a direct hook when it is no longer needed
// (e.g. ksud unhooking __NR_read after init.rc injection is done).
void ksu_syscall_table_unhook(int nr);

void ksu_syscall_hook_init(void);
void ksu_syscall_hook_exit(void);

#endif
