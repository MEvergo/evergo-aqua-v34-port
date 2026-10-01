#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/uaccess.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#define copy_from_user_nofault probe_user_read
#define copy_to_user_nofault probe_user_write
#define strncpy_from_user_nofault strncpy_from_unsafe_user
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
typedef unsigned int ksu_poll_t;
#else
typedef __poll_t ksu_poll_t;
#endif

/*
 * ksu_copy_from_user_retry
 * try nofault copy first, if it fails, try with plain
 * paramters are the same as copy_from_user
 * 0 = success
 */
static long ksu_copy_from_user_retry(void *to, const void __user *from,
                                     unsigned long count)
{
    long ret = copy_from_user_nofault(to, from, count);
    if (likely(!ret))
        return ret;

    // we faulted! fallback to slow path
    return copy_from_user(to, from, count);
}

#endif
