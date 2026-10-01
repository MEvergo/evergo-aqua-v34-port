#include "linux/rcupdate.h"
#include "security.h"
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/lockdep.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>

#include "uapi/selinux.h"
#include "klog.h" // IWYU pragma: keep
#include "selinux.h"
#include "sepolicy.h"
#include "ss/services.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#include "ss/sidtab.h"
#include "ss/hashtab.h"
#endif
#include "linux/lsm_audit.h" // IWYU pragma: keep
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#include "netlabel.h"
#endif
#include "xfrm.h"

struct selinux_policy *backup_sepolicy;

#define ALL NULL

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
extern int avc_ss_reset(u32 seqno);
#else
extern int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
#endif

static void reset_avc_cache(u32 seqno)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    avc_ss_reset(0);
    selnl_notify_policyload(0);
    selinux_status_update_policyload(0);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    avc_ss_reset(selinux_state.avc, seqno);
    selnl_notify_policyload(seqno);
    selinux_status_update_policyload(&selinux_state, seqno);
    selinux_netlbl_cache_invalidate();
#else
    (void)seqno;
    avc_ss_reset(selinux_state.avc, 0);
    selnl_notify_policyload(0);
    selinux_status_update_policyload(&selinux_state, 0);
#endif
    selinux_xfrm_notify_policyload();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
static DEFINE_MUTEX(ksu_legacy_policy_mutex);

static void ksu_destroy_legacy_backup(struct selinux_policy *policy, bool sidtab_initialized)
{
    if (!policy)
        return;
    if (policy->sidtab) {
        if (sidtab_initialized)
            sidtab_destroy(policy->sidtab);
        kfree(policy->sidtab);
    }
    ksu_destroy_sepolicy(policy);
}

static int ksu_snapshot_policy(struct policydb *snapshot, struct selinux_policy **backup, u32 *seqno,
                               bool capture_backup)
{
    struct selinux_ss *ss = selinux_state.ss;
    struct selinux_policy *backup_candidate = NULL;
    void *buffer = NULL;
    size_t capacity, length = 0;
    u32 base_seqno;
    u16 map_size;
    int ret;

    if (!ss || !selinux_state.initialized)
        return -EAGAIN;

    read_lock(&ss->policy_rwlock);
    base_seqno = ss->latest_granting;
    map_size = ss->map.size;
    capacity = ksu_policydb_clone_size(&ss->policydb);
    read_unlock(&ss->policy_rwlock);
    if (!capacity)
        return -EOVERFLOW;

    if (capture_backup && !backup_sepolicy) {
        backup_candidate = kzalloc(sizeof(*backup_candidate), GFP_KERNEL);
        if (backup_candidate && map_size) {
            backup_candidate->map.mapping = kcalloc(map_size, sizeof(*ss->map.mapping), GFP_KERNEL);
            if (!backup_candidate->map.mapping) {
                pr_warn("SELinux: backup map allocation failed; policy apply continues without hide backup\n");
                ksu_destroy_legacy_backup(backup_candidate, false);
                backup_candidate = NULL;
            }
        }
        if (backup_candidate)
            backup_candidate->map.size = map_size;
        else
            pr_warn("SELinux: backup policy allocation failed; policy apply continues without hide backup\n");
    }

    for (;;) {
        bool retry_capacity = false;

        buffer = vmalloc(capacity);
        if (!buffer) {
            ret = -ENOMEM;
            goto out;
        }

        read_lock(&ss->policy_rwlock);
        if (ss->latest_granting != base_seqno || ss->map.size != map_size ||
            ksu_policydb_clone_size(&ss->policydb) > capacity) {
            ret = -EAGAIN;
        } else if (map_size && !ss->map.mapping) {
            ret = -EINVAL;
        } else if (ss->policydb.policyvers < POLICYDB_VERSION_AVTAB) {
            ret = -EOPNOTSUPP;
        } else {
            ret = ksu_policydb_serialize(&ss->policydb, buffer, capacity, &length);
            retry_capacity = ret == -EINVAL;
            if (!ret && backup_candidate && map_size)
                memcpy(backup_candidate->map.mapping, ss->map.mapping, sizeof(*ss->map.mapping) * map_size);
        }
        read_unlock(&ss->policy_rwlock);

        if (!ret)
            break;
        if (!retry_capacity)
            goto out;

        vfree(buffer);
        buffer = NULL;
        if (capacity > (size_t)-1 / 2) {
            ret = -E2BIG;
            goto out;
        }
        capacity *= 2;
    }

    ret = ksu_policydb_deserialize(snapshot, buffer, length);
    if (ret)
        goto out;

    if (backup_candidate) {
        ret = ksu_policydb_deserialize(&backup_candidate->policydb, buffer, length);
        if (ret) {
            pr_warn("SELinux: backup policy decode failed; policy apply continues without hide backup: %d\n", ret);
            ksu_destroy_legacy_backup(backup_candidate, false);
            backup_candidate = NULL;
        } else {
            backup_candidate->sidtab = kzalloc(sizeof(*backup_candidate->sidtab), GFP_KERNEL);
            if (!backup_candidate->sidtab) {
                pr_warn("SELinux: backup SID table allocation failed; policy apply continues without hide backup\n");
                ksu_destroy_legacy_backup(backup_candidate, false);
                backup_candidate = NULL;
            } else if (policydb_load_isids(&backup_candidate->policydb, backup_candidate->sidtab)) {
                pr_warn("SELinux: backup SID initialization failed; policy apply continues without hide backup\n");
                kfree(backup_candidate->sidtab);
                backup_candidate->sidtab = NULL;
                ksu_destroy_legacy_backup(backup_candidate, false);
                backup_candidate = NULL;
            } else {
                backup_candidate->latest_granting = base_seqno;
            }
        }
    }

    if (backup)
        *backup = backup_candidate;
    *seqno = base_seqno;
    backup_candidate = NULL;
    ret = 0;
out:
    vfree(buffer);
    ksu_destroy_legacy_backup(backup_candidate, backup_candidate && backup_candidate->sidtab);
    return ret;
}

static int ksu_refresh_policy_len(struct policydb *db)
{
    size_t capacity = ksu_policydb_clone_size(db);
    size_t length;
    void *buffer;
    int ret;

    if (!capacity)
        return -EOVERFLOW;

    for (;;) {
        buffer = vmalloc(capacity);
        if (!buffer)
            return -ENOMEM;
        ret = ksu_policydb_serialize(db, buffer, capacity, &length);
        vfree(buffer);
        if (!ret) {
            db->len = length;
            return 0;
        }
        if (ret != -EINVAL)
            return ret;
        if (capacity > (size_t)-1 / 2)
            return -E2BIG;
        capacity *= 2;
    }
}

static int ksu_install_policydb(struct policydb *new_policydb, struct policydb *old_policydb, u32 base_seqno,
                                u32 *new_seqno)
{
    struct selinux_ss *ss = selinux_state.ss;

    write_lock_irq(&ss->policy_rwlock);
    if (ss->latest_granting != base_seqno) {
        write_unlock_irq(&ss->policy_rwlock);
        return -EAGAIN;
    }
    memcpy(old_policydb, &ss->policydb, sizeof(*old_policydb));
    memcpy(&ss->policydb, new_policydb, sizeof(*new_policydb));
    *new_seqno = ++ss->latest_granting;
    write_unlock_irq(&ss->policy_rwlock);

    ksu_destroy_policydb(old_policydb);
    reset_avc_cache(*new_seqno);
    return 0;
}
#endif

#define KSU_APPLY_RULE(rule)                                                                                           \
    do {                                                                                                               \
        if (!(rule)) {                                                                                                 \
            pr_err("SELinux: required KernelSU policy rule failed: %s\n", #rule);                                    \
            goto out_abort;                                                                                            \
        }                                                                                                              \
    } while (0)

void apply_kernelsu_rules(void)
{
    struct policydb *db;

    if (!getenforce())
        pr_info("SELinux permissive or disabled, apply rules!\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    struct selinux_policy *pol, *old_pol;

    mutex_lock(&selinux_state.policy_mutex);
    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));
    if (!backup_sepolicy) {
        struct selinux_policy *backup = ksu_dup_sepolicy(old_pol);
        if (IS_ERR(backup)) {
            pr_err("failed to create backup sepolicy: %ld\n", PTR_ERR(backup));
        } else {
            backup->sidtab = kzalloc(sizeof(*backup->sidtab), GFP_KERNEL);
            if (!backup->sidtab) {
                pr_err("failed to alloc backup sidtab\n");
                ksu_destroy_sepolicy(backup);
            } else {
                int ret = policydb_load_isids(&backup->policydb, backup->sidtab);
                if (ret) {
                    pr_err("failed to load isids for backup sepolicy: %d!\n", ret);
                    kfree(backup->sidtab);
                    ksu_destroy_sepolicy(backup);
                } else {
                    backup_sepolicy = backup;
                    pr_info("backup sepolicy success! latest_granting=%d\n", backup->latest_granting);
                }
            }
        }
    }

    pol = ksu_dup_sepolicy(old_pol);
    if (IS_ERR(pol)) {
        pr_err("failed to dup selinux_policy: %ld\n", PTR_ERR(pol));
        goto out_unlock;
    }
    db = &pol->policydb;
#else
    struct policydb *new_policydb = kzalloc(sizeof(*new_policydb), GFP_KERNEL);
    struct policydb *old_policydb = kzalloc(sizeof(*old_policydb), GFP_KERNEL);
    struct selinux_policy *backup_candidate = NULL;
    u32 base_seqno, new_seqno;
    int ret;

    mutex_lock(&ksu_legacy_policy_mutex);
    if (!new_policydb || !old_policydb) {
        pr_err("SELinux: policy clone allocation failed\n");
        goto out_legacy;
    }
    ret = ksu_snapshot_policy(new_policydb, &backup_candidate, &base_seqno, true);
    if (ret) {
        pr_err("SELinux: policy snapshot failed: %d\n", ret);
        goto out_legacy;
    }
    db = new_policydb;
#endif

    KSU_APPLY_RULE(ksu_type(db, KERNEL_SU_DOMAIN, "domain"));
    KSU_APPLY_RULE(ksu_permissive(db, KERNEL_SU_DOMAIN));
    KSU_APPLY_RULE(ksu_typeattribute(db, KERNEL_SU_DOMAIN, "mlstrustedsubject"));
    KSU_APPLY_RULE(ksu_typeattribute(db, KERNEL_SU_DOMAIN, "netdomain"));
    KSU_APPLY_RULE(ksu_typeattribute(db, KERNEL_SU_DOMAIN, "bluetoothdomain"));

    // Create unconstrained file type
    KSU_APPLY_RULE(ksu_type(db, KERNEL_SU_FILE, "file_type"));
    KSU_APPLY_RULE(ksu_typeattribute(db, KERNEL_SU_FILE, "mlstrustedobject"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_FILE, ALL, ALL));

    // allow all!
    KSU_APPLY_RULE(ksu_allow(db, KERNEL_SU_DOMAIN, ALL, ALL, ALL));

    // allow us do any ioctl
    if (db->policyvers < POLICYDB_VERSION_XPERMS_IOCTL) {
        pr_err("SELinux: policy version %u lacks ioctl extended permissions required by KernelSU\n", db->policyvers);
        goto out_abort;
    }
    KSU_APPLY_RULE(ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "blk_file", ALL));
    KSU_APPLY_RULE(ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "fifo_file", ALL));
    KSU_APPLY_RULE(ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "chr_file", ALL));
    KSU_APPLY_RULE(ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "file", ALL));

    // our ksud triggered by init
    KSU_APPLY_RULE(ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL));

    // copied from Magisk rules
    // suRights
    KSU_APPLY_RULE(ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "search"));
    KSU_APPLY_RULE(ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "read"));
    KSU_APPLY_RULE(ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "open"));
    KSU_APPLY_RULE(ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "read"));
    KSU_APPLY_RULE(ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "process", "getattr"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "process", "sigchld"));

    // allowLog
    KSU_APPLY_RULE(ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "dir", "search"));
    KSU_APPLY_RULE(ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "read"));
    KSU_APPLY_RULE(ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "open"));
    KSU_APPLY_RULE(ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "getattr"));

    // dumpsys, send fd
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fd", "use"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "write"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "read"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "open"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "getattr"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "read"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "write"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "connectto"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "getopt"));
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "getattr"));

    // A 4.14 policy need not define memfd_file (Aqua's active policy does not).
    // Such permissions cannot be evaluated by this kernel; retain the other
    // required rules instead of discarding the entire atomic policy update.
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
    if (hashtab_search(db->p_classes.table, "memfd_file")) {
#endif
        KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "execute"));
        KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "getattr"));
        KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "map"));
        KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "read"));
        KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "write"));
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
    } else {
        pr_info("SELinux: memfd_file class absent; continuing without inapplicable rules\n");
    }
#endif

    // bootctl
    KSU_APPLY_RULE(ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "dir", "search"));
    KSU_APPLY_RULE(ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "read"));
    KSU_APPLY_RULE(ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "open"));
    KSU_APPLY_RULE(ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "process", "getattr"));

    // Allow all binder transactions
    KSU_APPLY_RULE(ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "binder", ALL));

    // Allow system server kill su process
    KSU_APPLY_RULE(ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "getpgid"));
    KSU_APPLY_RULE(ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "sigkill"));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);
    reset_avc_cache(0);
    goto out_unlock;

out_abort:
    ksu_destroy_sepolicy(pol);
out_unlock:
    mutex_unlock(&selinux_state.policy_mutex);
#else
    ret = ksu_refresh_policy_len(new_policydb);
    if (ret) {
        pr_err("SELinux: sizing KernelSU policy failed: %d\n", ret);
        goto out_abort;
    }
    ret = ksu_install_policydb(new_policydb, old_policydb, base_seqno, &new_seqno);
    if (ret) {
        pr_err("SELinux: installing KernelSU policy failed: %d\n", ret);
        goto out_abort;
    }
    kfree(new_policydb);
    new_policydb = NULL;
    kfree(old_policydb);
    old_policydb = NULL;
    if (backup_candidate && !backup_sepolicy) {
        backup_sepolicy = backup_candidate;
        pr_info("backup sepolicy success! latest_granting=%d\n", backup_candidate->latest_granting);
        backup_candidate = NULL;
    }
    goto out_legacy;

out_abort:
    ksu_destroy_policydb(new_policydb);
    kfree(new_policydb);
    new_policydb = NULL;
out_legacy:
    ksu_destroy_legacy_backup(backup_candidate, backup_candidate && backup_candidate->sidtab);
    kfree(old_policydb);
    kfree(new_policydb);
    mutex_unlock(&ksu_legacy_policy_mutex);
#endif
}

#undef KSU_APPLY_RULE

#define KSU_SEPOLICY_MAX_BATCH_SIZE (8U * 1024U * 1024U)
#define KSU_SEPOLICY_MAX_ARGS 5

struct sepol_data {
    u32 cmd;
    u32 subcmd;
};

struct sepol_batch_cursor {
    const u8 *cur;
    const u8 *end;
};

static size_t sepol_remaining(const struct sepol_batch_cursor *cursor)
{
    return (size_t)(cursor->end - cursor->cur);
}

static int sepol_read_cmd_header(struct sepol_batch_cursor *cursor, struct sepol_data *header)
{
    if (sepol_remaining(cursor) < sizeof(*header)) {
        return -EINVAL;
    }

    memcpy(header, cursor->cur, sizeof(*header));
    cursor->cur += sizeof(*header);

    return 0;
}

static int sepol_read_string(struct sepol_batch_cursor *cursor, const char **out)
{
    u32 len;
    const char *str;

    if (sepol_remaining(cursor) < sizeof(len)) {
        return -EINVAL;
    }

    memcpy(&len, cursor->cur, sizeof(len));
    cursor->cur += sizeof(len);

    if (len >= sepol_remaining(cursor)) {
        return -EINVAL;
    }

    str = (const char *)cursor->cur;
    if (memchr(str, '\0', len) != NULL || str[len] != '\0') {
        return -EINVAL;
    }

    cursor->cur += len + 1;
    if (len == 0) {
        *out = ALL;
        return 0;
    }

    *out = str;
    return 0;
}

static int sepol_require_not_all(const char *value, const char *name)
{
    if (value != ALL) {
        return 0;
    }

    pr_err("sepol: %s cannot be ALL.\n", name);
    return -EINVAL;
}

static int sepol_expected_argc(u32 cmd)
{
    switch (cmd) {
    case KSU_SEPOLICY_CMD_NORMAL_PERM:
        return 4;
    case KSU_SEPOLICY_CMD_XPERM:
        return 5;
    case KSU_SEPOLICY_CMD_TYPE_STATE:
        return 1;
    case KSU_SEPOLICY_CMD_TYPE:
    case KSU_SEPOLICY_CMD_TYPE_ATTR:
        return 2;
    case KSU_SEPOLICY_CMD_ATTR:
        return 1;
    case KSU_SEPOLICY_CMD_TYPE_TRANSITION:
        return 5;
    case KSU_SEPOLICY_CMD_TYPE_CHANGE:
        return 4;
    case KSU_SEPOLICY_CMD_GENFSCON:
        return 3;
    default:
        return -EINVAL;
    }
}

static int apply_one_sepolicy_cmd(struct policydb *db, const struct sepol_data *header, const char **args)
{
    bool success = false;
    int ret;

    switch (header->cmd) {
    case KSU_SEPOLICY_CMD_NORMAL_PERM:
        if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_ALLOW) {
            success = ksu_allow(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DENY) {
            success = ksu_deny(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_AUDITALLOW) {
            success = ksu_auditallow(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DONTAUDIT) {
            success = ksu_dontaudit(db, args[0], args[1], args[2], args[3]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_XPERM:
        ret = sepol_require_not_all(args[3], "operation");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[4], "perm_set");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == KSU_SEPOLICY_SUBCMD_XPERM_ALLOW) {
            success = ksu_allowxperm(db, args[0], args[1], args[2], args[4]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_XPERM_AUDITALLOW) {
            success = ksu_auditallowxperm(db, args[0], args[1], args[2], args[4]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_XPERM_DONTAUDIT) {
            success = ksu_dontauditxperm(db, args[0], args[1], args[2], args[4]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_TYPE_STATE:
        ret = sepol_require_not_all(args[0], "type");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_STATE_PERMISSIVE) {
            success = ksu_permissive(db, args[0]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_STATE_ENFORCE) {
            success = ksu_enforce(db, args[0]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_TYPE:
    case KSU_SEPOLICY_CMD_TYPE_ATTR:
        ret = sepol_require_not_all(args[0], "type");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "attribute");
        if (ret < 0) {
            return ret;
        }

        if (header->cmd == KSU_SEPOLICY_CMD_TYPE) {
            success = ksu_type(db, args[0], args[1]);
        } else {
            success = ksu_typeattribute(db, args[0], args[1]);
        }
        if (!success) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    case KSU_SEPOLICY_CMD_ATTR:
        ret = sepol_require_not_all(args[0], "attribute");
        if (ret < 0) {
            return ret;
        }

        if (!ksu_attribute(db, args[0])) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    case KSU_SEPOLICY_CMD_TYPE_TRANSITION: {
        const char *object = ALL;

        ret = sepol_require_not_all(args[0], "src");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "tgt");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "cls");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[3], "default_type");
        if (ret < 0) {
            return ret;
        }

        object = args[4];

        success = ksu_type_transition(db, args[0], args[1], args[2], args[3], object);
        return success ? 0 : -EINVAL;
    }

    case KSU_SEPOLICY_CMD_TYPE_CHANGE:
        ret = sepol_require_not_all(args[0], "src");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "tgt");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "cls");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[3], "default_type");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_CHANGE) {
            success = ksu_type_change(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_MEMBER) {
            success = ksu_type_member(db, args[0], args[1], args[2], args[3]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_GENFSCON:
        ret = sepol_require_not_all(args[0], "name");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "path");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "context");
        if (ret < 0) {
            return ret;
        }

        if (!ksu_genfscon(db, args[0], args[1], args[2])) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    default:
        pr_err("sepol: unknown cmd: %d\n", header->cmd);
        return -EINVAL;
    }
}

int handle_sepolicy(void __user *user_data, u64 data_len)
{
    struct policydb *db;
    struct sepol_batch_cursor cursor;
    u8 *payload;
    int ret;
    int success_cmd_count;
    u32 cmd_index;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    struct selinux_policy *pol, *old_pol;
#else
    struct policydb *new_policydb = NULL, *old_policydb = NULL;
    u32 base_seqno, new_seqno;
#endif

    if (!user_data || !data_len)
        return -EINVAL;

    if (data_len > KSU_SEPOLICY_MAX_BATCH_SIZE)
        return -E2BIG;

    payload = kvmalloc((size_t)data_len, GFP_KERNEL);
    if (!payload)
        return -ENOMEM;

    if (copy_from_user(payload, user_data, (size_t)data_len)) {
        ret = -EFAULT;
        goto out_free;
    }

    if (!getenforce())
        pr_info("SELinux permissive or disabled when handle policy!\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    mutex_lock(&selinux_state.policy_mutex);
    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));
    pol = ksu_dup_sepolicy(old_pol);
    if (IS_ERR(pol)) {
        ret = PTR_ERR(pol);
        pr_err("ksu_dup_sepolicy err: %d\n", ret);
        goto out_unlock;
    }
    db = &pol->policydb;
#else
    mutex_lock(&ksu_legacy_policy_mutex);
    new_policydb = kzalloc(sizeof(*new_policydb), GFP_KERNEL);
    old_policydb = kzalloc(sizeof(*old_policydb), GFP_KERNEL);
    if (!new_policydb || !old_policydb) {
        ret = -ENOMEM;
        goto out_unlock;
    }
    ret = ksu_snapshot_policy(new_policydb, NULL, &base_seqno, false);
    if (ret) {
        pr_err("sepol: policy snapshot failed: %d\n", ret);
        goto out_unlock;
    }
    db = new_policydb;
#endif

    cursor.cur = payload;
    cursor.end = payload + (size_t)data_len;
    success_cmd_count = 0;
    cmd_index = 0;
    while (cursor.cur < cursor.end) {
        struct sepol_data header;
        const char *args[KSU_SEPOLICY_MAX_ARGS] = { 0 };
        int expected_argc;
        u32 arg_index;

        ret = sepol_read_cmd_header(&cursor, &header);
        if (ret < 0) {
            pr_err("sepol: failed to read cmd header #%u.\n", cmd_index);
            goto out_drop_new_policy;
        }

        expected_argc = sepol_expected_argc(header.cmd);
        if (expected_argc < 0 || expected_argc > KSU_SEPOLICY_MAX_ARGS) {
            ret = -EINVAL;
            pr_err("sepol: invalid cmd header #%u.\n", cmd_index);
            goto out_drop_new_policy;
        }

        for (arg_index = 0; arg_index < (u32)expected_argc; arg_index++) {
            ret = sepol_read_string(&cursor, &args[arg_index]);
            if (ret < 0) {
                pr_err("sepol: failed to read cmd #%u arg #%u.\n", cmd_index, arg_index);
                goto out_drop_new_policy;
            }
        }

        ret = apply_one_sepolicy_cmd(db, &header, args);
        if (ret < 0) {
            pr_err("sepol: cmd #%u failed, cmd=%u subcmd=%u.\n", cmd_index, header.cmd, header.subcmd);
        } else {
            success_cmd_count++;
        }
        cmd_index++;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);
    reset_avc_cache(0);
    ret = success_cmd_count;
    goto out_unlock;
#else
    ret = ksu_refresh_policy_len(new_policydb);
    if (ret) {
        pr_err("sepol: sizing policy failed: %d\n", ret);
        goto out_drop_new_policy;
    }
    ret = ksu_install_policydb(new_policydb, old_policydb, base_seqno, &new_seqno);
    if (ret) {
        pr_err("sepol: policy install failed: %d\n", ret);
        goto out_drop_new_policy;
    }
    kfree(new_policydb);
    new_policydb = NULL;
    kfree(old_policydb);
    old_policydb = NULL;
    ret = success_cmd_count;
    goto out_unlock;
#endif

out_drop_new_policy:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ksu_destroy_sepolicy(pol);
#else
    ksu_destroy_policydb(new_policydb);
    kfree(new_policydb);
    new_policydb = NULL;
#endif
out_unlock:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    mutex_unlock(&selinux_state.policy_mutex);
#else
    ksu_destroy_policydb(new_policydb);
    kfree(new_policydb);
    kfree(old_policydb);
    mutex_unlock(&ksu_legacy_policy_mutex);
#endif
out_free:
    kvfree(payload);
    return ret;
}
