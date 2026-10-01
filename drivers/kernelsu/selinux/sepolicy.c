#include "ss/avtab.h"
#include "ss/constraint.h"
#include "ss/ebitmap.h"
#include "ss/hashtab.h"
#include "ss/policydb.h"
#include "ss/services.h"
#include <linux/gfp.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "sepolicy.h"
#include "klog.h" // IWYU pragma: keep
#include "ss/symtab.h"

#define KSU_SUPPORT_ADD_TYPE

//////////////////////////////////////////////////////
// Declaration
//////////////////////////////////////////////////////

static struct avtab_node *get_avtab_node(struct policydb *db, struct avtab_key *key,
                                         struct avtab_extended_perms *xperms);

static bool is_redundant_avtab_node(struct avtab_node *node);

static bool remove_avtab_node(struct policydb *db, struct avtab_node *node);

static bool add_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *p, int effect,
                     bool invert);

static bool add_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt, struct class_datum *cls,
                         struct perm_datum *perm, int effect, bool invert);

static bool add_xperm_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt,
                               struct class_datum *cls, uint16_t low, uint16_t high, int effect, bool invert);
static bool add_xperm_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *range,
                           int effect, bool invert);

static bool add_type_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *d, int effect);

static bool add_filename_trans(struct policydb *db, const char *s, const char *t, const char *c, const char *d,
                               const char *o);

static bool add_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *context);

static bool add_type(struct policydb *db, const char *type_name, bool attr);

static bool set_type_state(struct policydb *db, const char *type_name, bool permissive);

static bool add_typeattribute_raw(struct policydb *db, struct type_datum *type, struct type_datum *attr);

static bool add_typeattribute(struct policydb *db, const char *type, const char *attr);

//////////////////////////////////////////////////////
// Implementation
//////////////////////////////////////////////////////

// Invert is adding rules for auditdeny; in other cases, invert is removing
// rules
#define strip_av(effect, invert) ((effect == AVTAB_AUDITDENY) == !invert)

#define ksu_hash_for_each(node_ptr, n_slot, cur)                                                                       \
    int i;                                                                                                             \
    for (i = 0; i < n_slot; ++i)                                                                                       \
        for (cur = node_ptr[i]; cur; cur = cur->next)

// htable is a struct instead of pointer above 5.8.0:
// https://elixir.bootlin.com/linux/v5.8-rc1/source/security/selinux/ss/symtab.h
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define ksu_hashtab_for_each(htab, cur) ksu_hash_for_each(htab.htable, htab.size, cur)
#else
#define ksu_hashtab_for_each(htab, cur) ksu_hash_for_each(htab->htable, htab->size, cur)
#endif

// symtab_search is introduced on 5.9.0:
// https://elixir.bootlin.com/linux/v5.9-rc1/source/security/selinux/ss/symtab.h
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#define symtab_search(s, name) hashtab_search((s)->table, name)
#define symtab_insert(s, name, datum) hashtab_insert((s)->table, name, datum)
#endif

static struct avtab_node *avtab_bucket(struct avtab *avtab, int slot)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
    return flex_array_get_ptr(avtab->htable, slot);
#else
    return avtab->htable[slot];
#endif
}

static int avtab_set_bucket(struct avtab *avtab, int slot, struct avtab_node *node)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
    return flex_array_put_ptr(avtab->htable, slot, node, GFP_KERNEL | __GFP_ZERO);
#else
    avtab->htable[slot] = node;
    return 0;
#endif
}

static int avtab_removed_bucket(struct avtab *avtab, struct avtab_node *node)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
    return flex_array_put_ptr(avtab->htable, 0, node, GFP_KERNEL | __GFP_ZERO);
#else
    avtab->htable[0] = node;
    return 0;
#endif
}


static struct avtab_node *get_avtab_node(struct policydb *db, struct avtab_key *key,
                                         struct avtab_extended_perms *xperms)
{
    struct avtab_node *node;

    /* AVTAB_XPERMS entries are not necessarily unique */
    if (key->specified & AVTAB_XPERMS) {
        bool match = false;
        node = avtab_search_node(&db->te_avtab, key);
        while (node) {
            if ((node->datum.u.xperms->specified == xperms->specified) &&
                (node->datum.u.xperms->driver == xperms->driver)) {
                match = true;
                break;
            }
            node = avtab_search_node_next(node, key->specified);
        }
        if (!match)
            node = NULL;
    } else {
        node = avtab_search_node(&db->te_avtab, key);
    }

    if (!node) {
        struct avtab_datum avdatum = {};
        int grow_size;
        /*
     * AUDITDENY, aka DONTAUDIT, are &= assigned, versus |= for
     * others. Initialize the data accordingly.
     */
        if (key->specified & AVTAB_XPERMS) {
            avdatum.u.xperms = xperms;
        } else {
            avdatum.u.data = key->specified == AVTAB_AUDITDENY ? ~0U : 0U;
        }
        /* this is used to get the node - insertion is actually unique */
        node = avtab_insert_nonunique(&db->te_avtab, key, &avdatum);
        if (!node)
            return NULL;

        grow_size = sizeof(struct avtab_key) + sizeof(struct avtab_datum);
        if (key->specified & AVTAB_XPERMS) {
            grow_size = sizeof(struct avtab_key) + sizeof(u8) * 2 +
                        sizeof(u32) * ARRAY_SIZE(avdatum.u.xperms->perms.p);
        }
        db->len += grow_size;
    }

    return node;
}

static bool is_redundant_avtab_node(struct avtab_node *node)
{
    int i;

    if (node->key.specified & AVTAB_XPERMS) {
        if (!node->datum.u.xperms)
            return true;
        for (i = 0; i < ARRAY_SIZE(node->datum.u.xperms->perms.p); i++) {
            if (node->datum.u.xperms->perms.p[i])
                return false;
        }
        return true;
    }
    if (!(node->key.specified & AVTAB_AV))
        return false;
    if (node->key.specified & AVTAB_AUDITDENY)
        return node->datum.u.data == ~0U;
    return node->datum.u.data == 0U;
}

static bool remove_avtab_node(struct policydb *db, struct avtab_node *node)
{
    int i;
    int ret;
    int shrink_size = sizeof(struct avtab_key) + sizeof(struct avtab_datum);
    struct avtab removed = {};
    struct avtab_node *n;
    struct avtab_node *prev;

    ret = avtab_alloc(&removed, 1);
    if (ret < 0)
        return false;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
    ret = flex_array_prealloc(removed.htable, 0, 1, GFP_KERNEL | __GFP_ZERO);
    if (ret < 0) {
        avtab_destroy(&removed);
        return false;
    }
#endif

    for (i = 0; i < db->te_avtab.nslot; i++) {
        prev = NULL;
        for (n = avtab_bucket(&db->te_avtab, i); n; prev = n, n = n->next) {
            if (n != node)
                continue;

            if (prev) {
                prev->next = n->next;
            } else if (avtab_set_bucket(&db->te_avtab, i, n->next)) {
                avtab_destroy(&removed);
                return false;
            }

            if (avtab_removed_bucket(&removed, n)) {
                if (prev)
                    prev->next = n;
                else
                    avtab_set_bucket(&db->te_avtab, i, n);
                avtab_destroy(&removed);
                return false;
            }
            if (db->te_avtab.nel > 0)
                db->te_avtab.nel--;

            if ((n->key.specified & AVTAB_XPERMS) && n->datum.u.xperms)
                shrink_size = sizeof(struct avtab_key) + sizeof(u8) * 2 +
                              sizeof(u32) * ARRAY_SIZE(n->datum.u.xperms->perms.p);
            n->next = NULL;
            removed.nel = 1;
            avtab_destroy(&removed);
            if (db->len >= shrink_size)
                db->len -= shrink_size;
            return true;
        }
    }

    avtab_destroy(&removed);
    return false;
}


static bool add_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *p, int effect,
                     bool invert)
{
    struct type_datum *src = NULL, *tgt = NULL;
    struct class_datum *cls = NULL;
    struct perm_datum *perm = NULL;

    if (s) {
        src = symtab_search(&db->p_types, s);
        if (src == NULL) {
            pr_info("source type %s does not exist\n", s);
            return false;
        }
    }

    if (t) {
        tgt = symtab_search(&db->p_types, t);
        if (tgt == NULL) {
            pr_info("target type %s does not exist\n", t);
            return false;
        }
    }

    if (c) {
        cls = symtab_search(&db->p_classes, c);
        if (cls == NULL) {
            pr_info("class %s does not exist\n", c);
            return false;
        }
    }

    if (p) {
        if (c == NULL) {
            pr_info("No class is specified, cannot add perm [%s] \n", p);
            return false;
        }

        perm = symtab_search(&cls->permissions, p);
        if (perm == NULL && cls->comdatum != NULL) {
            perm = symtab_search(&cls->comdatum->permissions, p);
        }
        if (perm == NULL) {
            pr_info("perm %s does not exist in class %s\n", p, c);
            return false;
        }
    }
    return add_rule_raw(db, src, tgt, cls, perm, effect, invert);
}

static bool add_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt, struct class_datum *cls,
                         struct perm_datum *perm, int effect, bool invert)
{
    bool success = true;

    if (src == NULL) {
        struct hashtab_node *node;
        if (strip_av(effect, invert)) {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                success &= add_rule_raw(db, (struct type_datum *)node->datum, tgt, cls, perm, effect, invert);
            };
        } else {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                struct type_datum *type = (struct type_datum *)(node->datum);
                if (type->attribute) {
                    success &= add_rule_raw(db, type, tgt, cls, perm, effect, invert);
                }
            };
        }
    } else if (tgt == NULL) {
        struct hashtab_node *node;
        if (strip_av(effect, invert)) {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                success &= add_rule_raw(db, src, (struct type_datum *)node->datum, cls, perm, effect, invert);
            };
        } else {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                struct type_datum *type = (struct type_datum *)(node->datum);
                if (type->attribute) {
                    success &= add_rule_raw(db, src, type, cls, perm, effect, invert);
                }
            };
        }
    } else if (cls == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_classes.table, node)
        {
            success &= add_rule_raw(db, src, tgt, (struct class_datum *)node->datum, perm, effect, invert);
        }
    } else {
        struct avtab_key key;
        struct avtab_node *node;

        key.source_type = src->value;
        key.target_type = tgt->value;
        key.target_class = cls->value;
        key.specified = effect;

        if (invert && effect != AVTAB_AUDITDENY) {
            node = avtab_search_node(&db->te_avtab, &key);
            if (!node)
                return true;
        } else {
            node = get_avtab_node(db, &key, NULL);
            if (!node)
                return false;
        }

        if (invert) {
            if (perm)
                node->datum.u.data &= ~(1U << (perm->value - 1));
            else
                node->datum.u.data = 0U;
        } else {
            if (perm)
                node->datum.u.data |= 1U << (perm->value - 1);
            else
                node->datum.u.data = ~0U;
        }
        if (is_redundant_avtab_node(node))
            return remove_avtab_node(db, node);
    }

    return success;
}

#define ioctl_driver(x) (x >> 8 & 0xFF)
#define ioctl_func(x) (x & 0xFF)

#define xperm_set(x, p) (p[x >> 5] |= (1U << (x & 0x1f)))

static bool add_xperm_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt,
                               struct class_datum *cls, uint16_t low, uint16_t high, int effect, bool invert)
{
    bool success = true;

    if (src == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            struct type_datum *type = node->datum;
            if (type->attribute)
                success &= add_xperm_rule_raw(db, type, tgt, cls, low, high, effect, invert);
        };
    } else if (tgt == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            struct type_datum *type = node->datum;
            if (type->attribute)
                success &= add_xperm_rule_raw(db, src, type, cls, low, high, effect, invert);
        };
    } else if (cls == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_classes.table, node)
        {
            success &= add_xperm_rule_raw(db, src, tgt, node->datum, low, high, effect, invert);
        };
    } else {
        struct avtab_key key = {
            .source_type = src->value,
            .target_type = tgt->value,
            .target_class = cls->value,
            .specified = effect,
        };
        struct avtab_extended_perms xperms = {};
        struct avtab_node *node;
        int i;

        if (ioctl_driver(low) != ioctl_driver(high)) {
            xperms.specified = AVTAB_XPERMS_IOCTLDRIVER;
            xperms.driver = 0;
        } else {
            xperms.specified = AVTAB_XPERMS_IOCTLFUNCTION;
            xperms.driver = ioctl_driver(low);
        }

        if (xperms.specified == AVTAB_XPERMS_IOCTLDRIVER) {
            for (i = ioctl_driver(low); i <= ioctl_driver(high); ++i)
                xperm_set(i, xperms.perms.p);
        } else {
            for (i = ioctl_func(low); i <= ioctl_func(high); ++i)
                xperm_set(i, xperms.perms.p);
        }

        node = avtab_search_node(&db->te_avtab, &key);
        while (node && (!node->datum.u.xperms ||
                        node->datum.u.xperms->specified != xperms.specified ||
                        node->datum.u.xperms->driver != xperms.driver))
            node = avtab_search_node_next(node, key.specified);

        if (!node) {
            if (invert)
                return true;
            node = get_avtab_node(db, &key, &xperms);
            return node != NULL;
        }

        if (invert) {
            for (i = 0; i < ARRAY_SIZE(xperms.perms.p); ++i)
                node->datum.u.xperms->perms.p[i] &= ~xperms.perms.p[i];
        } else {
            for (i = 0; i < ARRAY_SIZE(xperms.perms.p); ++i)
                node->datum.u.xperms->perms.p[i] |= xperms.perms.p[i];
        }

        if (is_redundant_avtab_node(node))
            return remove_avtab_node(db, node);
    }

    return success;
}

static bool add_xperm_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *range,
                           int effect, bool invert)
{
    struct type_datum *src = NULL, *tgt = NULL;
    struct class_datum *cls = NULL;
    u16 low = 0, high = 0xffff;

    if (s) {
        src = symtab_search(&db->p_types, s);
        if (src == NULL) {
            pr_info("source type %s does not exist\n", s);
            return false;
        }
    }

    if (t) {
        tgt = symtab_search(&db->p_types, t);
        if (tgt == NULL) {
            pr_info("target type %s does not exist\n", t);
            return false;
        }
    }

    if (c) {
        cls = symtab_search(&db->p_classes, c);
        if (cls == NULL) {
            pr_info("class %s does not exist\n", c);
            return false;
        }
    }

    if (range) {
        int parsed;

        if (strchr(range, '-')) {
            parsed = sscanf(range, "%hx-%hx", &low, &high);
            if (parsed != 2) {
                pr_err("invalid xperm range: %s\n", range);
                return false;
            }
        } else {
            parsed = sscanf(range, "%hx", &low);
            if (parsed != 1) {
                pr_err("invalid xperm value: %s\n", range);
                return false;
            }
            high = low;
        }
        if (low > high) {
            pr_err("invalid xperm range: %s\n", range);
            return false;
        }
    }

    return add_xperm_rule_raw(db, src, tgt, cls, low, high, effect, invert);
}


static bool add_type_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *d, int effect)
{
    struct type_datum *src, *tgt, *def;
    struct class_datum *cls;

    src = symtab_search(&db->p_types, s);
    if (src == NULL) {
        pr_info("source type %s does not exist\n", s);
        return false;
    }
    tgt = symtab_search(&db->p_types, t);
    if (tgt == NULL) {
        pr_info("target type %s does not exist\n", t);
        return false;
    }
    cls = symtab_search(&db->p_classes, c);
    if (cls == NULL) {
        pr_info("class %s does not exist\n", c);
        return false;
    }
    def = symtab_search(&db->p_types, d);
    if (def == NULL) {
        pr_info("default type %s does not exist\n", d);
        return false;
    }

    struct avtab_key key;
    key.source_type = src->value;
    key.target_type = tgt->value;
    key.target_class = cls->value;
    key.specified = effect;

    struct avtab_node *node = get_avtab_node(db, &key, NULL);
    if (!node)
        return false;
    node->datum.u.data = def->value;

    return true;
}

// 5.9.0 : static inline int hashtab_insert(struct hashtab *h, void *key, void
// *datum, struct hashtab_key_params key_params) 5.8.0: int
// hashtab_insert(struct hashtab *h, void *k, void *d);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
static u32 filenametr_hash(const void *k)
{
    const struct filename_trans_key *ft = k;
    unsigned long hash;
    unsigned int byte_num;
    unsigned char focus;

    hash = ft->ttype ^ ft->tclass;

    byte_num = 0;
    while ((focus = ft->name[byte_num++]))
        hash = partial_name_hash(focus, hash);
    return hash;
}

static int filenametr_cmp(const void *k1, const void *k2)
{
    const struct filename_trans_key *ft1 = k1;
    const struct filename_trans_key *ft2 = k2;
    int v;

    v = ft1->ttype - ft2->ttype;
    if (v)
        return v;

    v = ft1->tclass - ft2->tclass;
    if (v)
        return v;

    return strcmp(ft1->name, ft2->name);
}

static const struct hashtab_key_params filenametr_key_params = {
    .hash = filenametr_hash,
    .cmp = filenametr_cmp,
};
#endif

static bool add_filename_trans(struct policydb *db, const char *s, const char *t, const char *c, const char *d,
                               const char *o)
{
    struct type_datum *src, *tgt, *def;
    struct class_datum *cls;

    src = symtab_search(&db->p_types, s);
    if (!src) {
        pr_warn("source type %s does not exist\n", s);
        return false;
    }
    tgt = symtab_search(&db->p_types, t);
    if (!tgt) {
        pr_warn("target type %s does not exist\n", t);
        return false;
    }
    cls = symtab_search(&db->p_classes, c);
    if (!cls) {
        pr_warn("class %s does not exist\n", c);
        return false;
    }
    def = symtab_search(&db->p_types, d);
    if (!def) {
        pr_warn("default type %s does not exist\n", d);
        return false;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    {
        struct filename_trans_key key = {
            .ttype = tgt->value,
            .tclass = cls->value,
            .name = o,
        };
        struct filename_trans_key *new_key = NULL;
        struct filename_trans_datum *last = NULL;
        struct filename_trans_datum *trans = policydb_filenametr_search(db, &key);
        int rc;

        while (trans) {
            if (ebitmap_get_bit(&trans->stypes, src->value - 1)) {
                trans->otype = def->value;
                return true;
            }
            if (trans->otype == def->value)
                break;
            last = trans;
            trans = trans->next;
        }

        if (!trans) {
            trans = kzalloc(sizeof(*trans), GFP_KERNEL);
            if (!trans)
                goto filename_trans_v59_out;
            new_key = kzalloc(sizeof(*new_key), GFP_KERNEL);
            if (!new_key)
                goto filename_trans_v59_free_trans;
            *new_key = key;
            new_key->name = kstrdup(key.name, GFP_KERNEL);
            if (!new_key->name)
                goto filename_trans_v59_free_key;
            trans->next = last;
            trans->otype = def->value;
            rc = hashtab_insert(&db->filename_trans, new_key, trans, filenametr_key_params);
            if (rc) {
                pr_err("add_filename_trans: hashtab_insert failed: %d\n", rc);
                goto filename_trans_v59_free_name;
            }
        }

        db->compat_filename_trans_count++;
        return ebitmap_set_bit(&trans->stypes, src->value - 1, 1) == 0;

filename_trans_v59_free_name:
        kfree(new_key->name);
filename_trans_v59_free_key:
        kfree(new_key);
filename_trans_v59_free_trans:
        kfree(trans);
filename_trans_v59_out:
        return false;
    }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    {
        struct filename_trans_key key = {
            .ttype = tgt->value,
            .tclass = cls->value,
            .name = o,
        };
        struct filename_trans_key *new_key = NULL;
        struct filename_trans_datum *last = NULL;
        struct filename_trans_datum *trans = hashtab_search(&db->filename_trans, &key);
        int rc;

        while (trans) {
            if (ebitmap_get_bit(&trans->stypes, src->value - 1)) {
                trans->otype = def->value;
                return true;
            }
            if (trans->otype == def->value)
                break;
            last = trans;
            trans = trans->next;
        }
        if (!trans) {
            trans = kzalloc(sizeof(*trans), GFP_KERNEL);
            if (!trans)
                goto filename_trans_v57_out;
            new_key = kzalloc(sizeof(*new_key), GFP_KERNEL);
            if (!new_key)
                goto filename_trans_v57_free_trans;
            *new_key = key;
            new_key->name = kstrdup(key.name, GFP_KERNEL);
            if (!new_key->name)
                goto filename_trans_v57_free_key;
            trans->next = last;
            trans->otype = def->value;
            rc = hashtab_insert(db->filename_trans, new_key, trans);
            if (rc) {
                pr_err("add_filename_trans: hashtab_insert failed: %d\n", rc);
                goto filename_trans_v57_free_name;
            }
        }
        return ebitmap_set_bit(&trans->stypes, src->value - 1, 1) == 0;

filename_trans_v57_free_name:
        kfree(new_key->name);
filename_trans_v57_free_key:
        kfree(new_key);
filename_trans_v57_free_trans:
        kfree(trans);
filename_trans_v57_out:
        return false;
    }
#else
    {
        struct filename_trans key = {
            .stype = src->value,
            .ttype = tgt->value,
            .tclass = cls->value,
            .name = o,
        };
        struct filename_trans *new_key;
        struct filename_trans_datum *trans;
        int rc;

        trans = hashtab_search(db->filename_trans, &key);
        if (trans) {
            trans->otype = def->value;
            return true;
        }

        new_key = kzalloc(sizeof(*new_key), GFP_KERNEL);
        if (!new_key)
            return false;
        *new_key = key;
        new_key->name = kstrdup(key.name, GFP_KERNEL);
        if (!new_key->name) {
            kfree(new_key);
            return false;
        }
        trans = kzalloc(sizeof(*trans), GFP_KERNEL);
        if (!trans) {
            kfree(new_key->name);
            kfree(new_key);
            return false;
        }
        trans->otype = def->value;
        rc = hashtab_insert(db->filename_trans, new_key, trans);
        if (rc) {
            pr_err("add_filename_trans: hashtab_insert failed: %d\n", rc);
            kfree(new_key->name);
            kfree(new_key);
            kfree(trans);
            return false;
        }
        return ebitmap_set_bit(&db->filename_trans_ttypes, tgt->value, 1) == 0;
    }
#endif
}

static bool add_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *context)
{
    return false;
}

// https://github.com/torvalds/linux/commit/590b9d576caec6b4c46bba49ed36223a399c3fc5#diff-cc9aa90e094e6e0f47bd7300db4f33cf4366b98b55d8753744f31eb69c691016R844-R845
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define ksu_kvrealloc(p, new_size, _old_size) kvrealloc(p, new_size, GFP_KERNEL)
// https://github.com/torvalds/linux/commit/de2860f4636256836450c6543be744a50118fc66#diff-fa19cdd9c3369d7f59aa2e8404628109408dbf8e1b568d1157a27328f75b8410R638-R652
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
#define ksu_kvrealloc(p, new_size, old_size) kvrealloc(p, old_size, new_size, GFP_KERNEL)
#else
// https://cs.android.com/android/_/android/kernel/common/+/f5f3e54f811679761c33526e695bd296190faade
// Some 5.10 kernel don't have this backport, so copy one.
void *ksu_kvrealloc_compat(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
{
    void *newp;

    if (oldsize >= newsize)
        return (void *)p;
    newp = kvmalloc(newsize, flags);
    if (!newp)
        return NULL;
    memcpy(newp, p, oldsize);
    kvfree(p);
    return newp;
}
#define ksu_kvrealloc(p, new_size, old_size) ksu_kvrealloc_compat(p, old_size, new_size, GFP_KERNEL)
#endif

static bool add_type(struct policydb *db, const char *type_name, bool attr)
{
    struct type_datum *type = symtab_search(&db->p_types, type_name);
    if (type) {
        pr_warn("Type %s already exists\n", type_name);
        return true;
    }

    u32 value = db->p_types.nprim + 1;
    type = kzalloc(sizeof(*type), GFP_KERNEL);
    if (!type) {
        pr_err("add_type: alloc type_datum failed.\n");
        return false;
    }

    type->primary = 1;
    type->value = value;
    type->attribute = attr;

    char *key = kstrdup(type_name, GFP_KERNEL);
    if (!key) {
        pr_err("add_type: alloc key failed.\n");
        kfree(type);
        return false;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
    {
        u32 old_count = db->p_types.nprim;
        struct flex_array *new_attr_map = NULL;
        struct flex_array *new_types = NULL;
        struct flex_array *new_names = NULL;
        struct ebitmap self_map = {};
        bool self_map_stored = false;
        u32 i;

        new_attr_map = flex_array_alloc(sizeof(struct ebitmap), value, GFP_KERNEL | __GFP_ZERO);
        new_types = flex_array_alloc(sizeof(struct type_datum *), value, GFP_KERNEL | __GFP_ZERO);
        new_names = flex_array_alloc(sizeof(char *), value, GFP_KERNEL | __GFP_ZERO);
        if (!new_attr_map || !new_types || !new_names) {
            pr_err("add_type: alloc legacy policydb arrays failed\n");
            goto legacy_out;
        }

        for (i = 0; i < old_count; ++i) {
            struct ebitmap *old_map = flex_array_get(db->type_attr_map_array, i);
            struct type_datum *old_type = flex_array_get_ptr(db->type_val_to_struct_array, i);
            char *old_name = flex_array_get_ptr(db->sym_val_to_name[SYM_TYPES], i);

            if (old_map && flex_array_put(new_attr_map, i, old_map, GFP_KERNEL | __GFP_ZERO)) {
                pr_err("add_type: copy legacy type attribute map failed\n");
                goto legacy_out;
            }
            if (old_type && flex_array_put_ptr(new_types, i, old_type, GFP_KERNEL | __GFP_ZERO)) {
                pr_err("add_type: copy legacy type index failed\n");
                goto legacy_out;
            }
            if (old_name && flex_array_put_ptr(new_names, i, old_name, GFP_KERNEL | __GFP_ZERO)) {
                pr_err("add_type: copy legacy type name failed\n");
                goto legacy_out;
            }
        }

        ebitmap_init(&self_map);
        if (ebitmap_set_bit(&self_map, value - 1, 1)) {
            ebitmap_destroy(&self_map);
            pr_err("add_type: initialize legacy type attribute map failed\n");
            goto legacy_out;
        }
        if (flex_array_put(new_attr_map, value - 1, &self_map, GFP_KERNEL | __GFP_ZERO)) {
            ebitmap_destroy(&self_map);
            pr_err("add_type: store legacy type attribute map failed\n");
            goto legacy_out;
        }
        self_map_stored = true;

        if (flex_array_put_ptr(new_types, value - 1, type, GFP_KERNEL | __GFP_ZERO) ||
            flex_array_put_ptr(new_names, value - 1, key, GFP_KERNEL | __GFP_ZERO)) {
            pr_err("add_type: store legacy type index failed\n");
            goto legacy_out;
        }

        if (symtab_insert(&db->p_types, key, type)) {
            pr_err("add_type: insert symtab failed.\n");
            goto legacy_out;
        }

        flex_array_free(db->type_attr_map_array);
        flex_array_free(db->type_val_to_struct_array);
        flex_array_free(db->sym_val_to_name[SYM_TYPES]);
        db->type_attr_map_array = new_attr_map;
        db->type_val_to_struct_array = new_types;
        db->sym_val_to_name[SYM_TYPES] = new_names;
        db->p_types.nprim = value;

        for (i = 0; i < db->p_roles.nprim; ++i) {
            if (ebitmap_set_bit(&db->role_val_to_struct[i]->types, value - 1, 1)) {
                pr_err("add_type: update legacy role type map failed\n");
                return false;
            }
        }
        return true;

legacy_out:
        if (self_map_stored) {
            struct ebitmap *stored_map = flex_array_get(new_attr_map, value - 1);
            if (stored_map)
                ebitmap_destroy(stored_map);
        }
        if (new_attr_map)
            flex_array_free(new_attr_map);
        if (new_types)
            flex_array_free(new_types);
        if (new_names)
            flex_array_free(new_names);
        kfree(key);
        kfree(type);
        return false;
    }
#else
    u32 old_count = db->p_types.nprim;
    struct ebitmap *new_type_attr_map_array;
    struct type_datum **new_type_val_to_struct;
    char **new_val_to_name_types;

    db->p_types.nprim = value;
    if (symtab_insert(&db->p_types, key, type)) {
        pr_err("add_type: insert symtab failed.\n");
        db->p_types.nprim = old_count;
        kfree(key);
        kfree(type);
        return false;
    }

    new_type_attr_map_array =
        ksu_kvrealloc(db->type_attr_map_array, value * sizeof(struct ebitmap), old_count * sizeof(struct ebitmap));
    if (!new_type_attr_map_array) {
        pr_err("add_type: alloc type_attr_map_array failed\n");
        return false;
    }

    new_type_val_to_struct = ksu_kvrealloc(db->type_val_to_struct, sizeof(*db->type_val_to_struct) * value,
                                           sizeof(*db->type_val_to_struct) * old_count);
    if (!new_type_val_to_struct) {
        pr_err("add_type: alloc type_val_to_struct failed\n");
        return false;
    }

    new_val_to_name_types =
        ksu_kvrealloc(db->sym_val_to_name[SYM_TYPES], sizeof(char *) * value, sizeof(char *) * old_count);
    if (!new_val_to_name_types) {
        pr_err("add_type: alloc val_to_name failed\n");
        return false;
    }

    db->type_attr_map_array = new_type_attr_map_array;
    ebitmap_init(&db->type_attr_map_array[value - 1]);
    if (ebitmap_set_bit(&db->type_attr_map_array[value - 1], value - 1, 1))
        return false;

    db->type_val_to_struct = new_type_val_to_struct;
    db->type_val_to_struct[value - 1] = type;

    db->sym_val_to_name[SYM_TYPES] = new_val_to_name_types;
    db->sym_val_to_name[SYM_TYPES][value - 1] = key;

    int i;
    for (i = 0; i < db->p_roles.nprim; ++i) {
        if (ebitmap_set_bit(&db->role_val_to_struct[i]->types, value - 1, 1)) {
            pr_err("add_type: update role type map failed\n");
            return false;
        }
    }

    return true;
#endif
}

static bool set_type_state(struct policydb *db, const char *type_name, bool permissive)
{
    struct type_datum *type;
    bool success = true;

    if (type_name == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            type = node->datum;
            if (ebitmap_set_bit(&db->permissive_map, type->value, permissive)) {
                pr_err("Could not set bit in permissive map\n");
                success = false;
            }
        };
        return success;
    }

    type = symtab_search(&db->p_types, type_name);
    if (type == NULL) {
        pr_info("type %s does not exist\n", type_name);
        return false;
    }
    if (ebitmap_set_bit(&db->permissive_map, type->value, permissive)) {
        pr_err("Could not set bit in permissive map\n");
        return false;
    }
    return true;
}

static struct ebitmap *type_attr_map(struct policydb *db, u32 type_value)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
    return flex_array_get(db->type_attr_map_array, type_value - 1);
#else
    return &db->type_attr_map_array[type_value - 1];
#endif
}

static bool add_typeattribute_raw(struct policydb *db, struct type_datum *type, struct type_datum *attr)
{
    struct ebitmap *sattr = type_attr_map(db, type->value);
    struct hashtab_node *node;
    struct constraint_node *n;
    struct constraint_expr *e;

    if (!sattr || ebitmap_set_bit(sattr, attr->value - 1, 1)) {
        pr_err("add_typeattribute: update type attribute map failed\n");
        return false;
    }

    ksu_hashtab_for_each(db->p_classes.table, node)
    {
        struct class_datum *cls = node->datum;
        for (n = cls->constraints; n; n = n->next) {
            for (e = n->expr; e; e = e->next) {
                if (e->expr_type == CEXPR_NAMES && ebitmap_get_bit(&e->type_names->types, attr->value - 1) &&
                    ebitmap_set_bit(&e->names, type->value - 1, 1)) {
                    pr_err("add_typeattribute: update constraint names failed\n");
                    return false;
                }
            }
        }
    };
    return true;
}

static bool add_typeattribute(struct policydb *db, const char *type, const char *attr)
{
    struct type_datum *type_d = symtab_search(&db->p_types, type);
    if (type_d == NULL) {
        pr_info("type %s does not exist\n", type);
        return false;
    } else if (type_d->attribute) {
        pr_info("type %s is an attribute\n", attr);
        return false;
    }

    struct type_datum *attr_d = symtab_search(&db->p_types, attr);
    if (attr_d == NULL) {
        pr_info("attribute %s does not exist\n", attr);
        return false;
    } else if (!attr_d->attribute) {
        pr_info("type %s is not an attribute\n", attr);
        return false;
    }

    return add_typeattribute_raw(db, type_d, attr_d);
}

//////////////////////////////////////////////////////////////////////////

// Operation on types
bool ksu_type(struct policydb *db, const char *name, const char *attr)
{
    return add_type(db, name, false) && add_typeattribute(db, name, attr);
}

bool ksu_attribute(struct policydb *db, const char *name)
{
    return add_type(db, name, true);
}

bool ksu_permissive(struct policydb *db, const char *type)
{
    return set_type_state(db, type, true);
}

bool ksu_enforce(struct policydb *db, const char *type)
{
    return set_type_state(db, type, false);
}

bool ksu_typeattribute(struct policydb *db, const char *type, const char *attr)
{
    return add_typeattribute(db, type, attr);
}

bool ksu_exists(struct policydb *db, const char *type)
{
    return symtab_search(&db->p_types, type) != NULL;
}

// Access vector rules
bool ksu_allow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_ALLOWED, false);
}

bool ksu_deny(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_ALLOWED, true);
}

bool ksu_auditallow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_AUDITALLOW, false);
}
bool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_AUDITDENY, true);
}

// Extended permissions access vector rules
bool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_ALLOWED, false);
}

bool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_AUDITALLOW, false);
}

bool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_DONTAUDIT, false);
}

// Type rules
bool ksu_type_transition(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def,
                         const char *obj)
{
    if (obj) {
        return add_filename_trans(db, src, tgt, cls, def, obj);
    } else {
        return add_type_rule(db, src, tgt, cls, def, AVTAB_TRANSITION);
    }
}

bool ksu_type_change(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def)
{
    return add_type_rule(db, src, tgt, cls, def, AVTAB_CHANGE);
}

bool ksu_type_member(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def)
{
    return add_type_rule(db, src, tgt, cls, def, AVTAB_MEMBER);
}

// File system labeling
bool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *ctx)
{
    return add_genfscon(db, fs_name, path, ctx);
}

// ======== sepolicy ========

void ksu_destroy_sepolicy(struct selinux_policy *pol)
{
    if (!pol)
        return;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    kfree(pol->map.mapping);
#endif
    policydb_destroy(&pol->policydb);
    kfree(pol);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
size_t ksu_policydb_clone_size(const struct policydb *db)
{
    size_t extra;

    if (!db || db->p_types.nprim > ((size_t)-1) / (sizeof(u32) + sizeof(u64)))
        return 0;
    extra = (size_t)db->p_types.nprim * (sizeof(u32) + sizeof(u64));
    if (db->len > (size_t)-1 - extra)
        return 0;
    return db->len + extra;
}

int ksu_policydb_serialize(struct policydb *db, void *buffer, size_t capacity, size_t *length)
{
    static const size_t config_offset = 20;
    struct policy_file fp;
    size_t written;
    int ret;

    if (!db || !buffer || !length || capacity < ksu_policydb_clone_size(db))
        return -EINVAL;

    fp.data = buffer;
    fp.len = capacity;
    ret = policydb_write(db, &fp);
    if (ret) {
        pr_err("sepolicy: policydb_write: %d\n", ret);
        return ret;
    }

    written = capacity - fp.len;
    if (written < config_offset + sizeof(u32))
        return -EINVAL;

    {
        u32 *config = (u32 *)((u8 *)buffer + config_offset);
        if (db->android_netlink_route)
            *config |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
        if (db->android_netlink_getneigh)
            *config |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
    }

    *length = written;
    return 0;
}

int ksu_policydb_deserialize(struct policydb *db, const void *buffer, size_t length)
{
    struct policy_file fp;
    int ret;

    if (!db || !buffer || !length)
        return -EINVAL;

    memset(db, 0, sizeof(*db));
    fp.data = (void *)buffer;
    fp.len = length;
    ret = policydb_read(db, &fp);
    if (ret) {
        pr_err("sepolicy: policydb_read: %d\n", ret);
        policydb_destroy(db);
        memset(db, 0, sizeof(*db));
        return ret;
    }
    db->len = length;
    return 0;
}

void ksu_destroy_policydb(struct policydb *db)
{
    if (db)
        policydb_destroy(db);
}
#else
struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol)
{
    int ret;
    size_t len;
    struct selinux_policy *new_pol;
    void *data;
    struct policy_file fp;

    len = old_pol->policydb.len;
    data = vmalloc(len);
    if (!data) {
        pr_err("alloc policy len %ld\n", len);
        ret = -ENOMEM;
        goto out_free_data;
    }

    fp.data = data;
    fp.len = len;

    ret = policydb_write(&old_pol->policydb, &fp);
    if (ret) {
        pr_err("sepolicy: policydb_write: %d\n", ret);
        goto out_free_data;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    {
        static const size_t config_offset = 20;
        if (len >= config_offset + sizeof(u32)) {
            u32 *config = (u32 *)((u8 *)data + config_offset);
            if (old_pol->policydb.android_netlink_route)
                *config |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
            if (old_pol->policydb.android_netlink_getneigh)
                *config |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
        }
    }
#endif

    new_pol = kmemdup(old_pol, sizeof(*old_pol), GFP_KERNEL);
    if (!new_pol) {
        ret = -ENOMEM;
        pr_err("sepolicy: dup old pol\n");
        goto out_free_data;
    }
    memset(&new_pol->policydb, 0, sizeof(new_pol->policydb));

    fp.data = data;
    fp.len = len;
    ret = policydb_read(&new_pol->policydb, &fp);
    if (ret) {
        pr_err("sepolicy: policydb_read: %d\n", ret);
        kfree(new_pol);
        goto out_free_data;
    }
    new_pol->policydb.len = old_pol->policydb.len;
    kvfree(data);
    return new_pol;

out_free_data:
    kvfree(data);
    return ERR_PTR(ret);
}
#endif
