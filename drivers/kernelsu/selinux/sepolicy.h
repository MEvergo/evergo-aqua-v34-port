#ifndef __KSU_H_SEPOLICY
#define __KSU_H_SEPOLICY

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#include "ss/services.h"
#else
#include "ss/policydb.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
struct sidtab;

/*
 * Kernels before 5.10 keep the active policy database and SID table in
 * selinux_state.ss rather than in a selinux_policy object.
 */
struct selinux_policy {
    struct policydb policydb;
    struct sidtab *sidtab;
    struct selinux_map map;
    u32 latest_granting;
};

size_t ksu_policydb_clone_size(const struct policydb *db);
int ksu_policydb_serialize(struct policydb *db, void *buffer, size_t capacity, size_t *length);
int ksu_policydb_deserialize(struct policydb *db, const void *buffer, size_t length);
void ksu_destroy_policydb(struct policydb *db);
#else
struct selinux_policy;

struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol);
#endif

void ksu_destroy_sepolicy(struct selinux_policy *orig);


// Operation on types
bool ksu_type(struct policydb *db, const char *name, const char *attr);
bool ksu_attribute(struct policydb *db, const char *name);
bool ksu_permissive(struct policydb *db, const char *type);
bool ksu_enforce(struct policydb *db, const char *type);
bool ksu_typeattribute(struct policydb *db, const char *type, const char *attr);
bool ksu_exists(struct policydb *db, const char *type);

// Access vector rules
bool ksu_allow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);
bool ksu_deny(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);
bool ksu_auditallow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);
bool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);

// Extended permissions access vector rules
bool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range);
bool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range);
bool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range);

// Type rules
bool ksu_type_transition(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def,
                         const char *obj);
bool ksu_type_change(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def);
bool ksu_type_member(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def);

// File system labeling
bool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *ctx);

#endif
