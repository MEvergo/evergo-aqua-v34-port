// SPDX-License-Identifier: GPL-2.0
#include <linux/limits.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/sections.h>

#include "hook_abi.h"
#include "arch/arm64/hook_reloc.h"
#include "kpm_internal.h"
#include "../hook/patch_memory.h"

#define KPM_HOOK_RECORD_LIMIT 256
#define KPM_HOOK_MODULE_REFS 2
#define KPM_HOOK_STUB_SIZE 64
#define KPM_HOOK_TRAMPOLINE_ENTRY_OFFSET KPM_HOOK_STUB_SIZE
#define KPM_HOOK_TRAMPOLINE_CODE_OFFSET \
	(KPM_HOOK_TRAMPOLINE_ENTRY_OFFSET + sizeof(u32))
#define KPM_ARM64_BTI_JC 0xd50324df
#define KPM_HOOK_STATE_EMPTY KPM_HOOK_ITEM_EMPTY
#define KPM_HOOK_STATE_READY KPM_HOOK_ITEM_READY
#define KPM_ARM64_HOOK_PATCH_SIZE \
	(KPM_ARM64_HOOK_PATCH_WORDS * sizeof(u32))
#define HOOK_BAD_ADDRESS (-KPM_HOOK_BAD_ADDRESS)
#define HOOK_DUPLICATED (-KPM_HOOK_DUPLICATED)
#define HOOK_NO_MEMORY (-KPM_HOOK_NO_MEMORY)
#define HOOK_BAD_RELO (-KPM_HOOK_BAD_RELOCATION)
#define HOOK_CHAIN_FULL (-KPM_HOOK_CHAIN_FULL)

enum kpm_hook_kind {
	KPM_HOOK_INLINE_CHAIN,
	KPM_HOOK_FP_CHAIN,
	KPM_HOOK_INLINE_DIRECT,
	KPM_HOOK_FP_DIRECT,
};

struct kpm_hook_record {
	struct list_head node;
	enum kpm_hook_kind kind;
	unsigned long key;
	unsigned int argno;
	unsigned int arg_group;
	bool installed;
	void *code_page;
	struct module *module_refs[KPM_HOOK_MODULE_REFS];
	unsigned int module_ref_count;
	struct kpm_module *direct_owner;
	struct kpm_hook_t *raw_hook;
	struct kpm_module __rcu *owners[KPM_FP_HOOK_CHAIN_NUM];
	spinlock_t chain_lock;
	union {
		struct kpm_hook_chain inline_chain;
		struct kpm_fp_hook_chain fp_chain;
		struct kpm_hook_t direct_hook;
	} abi;
	void *direct_original;
	void *direct_replace;
};

union kpm_hook_fargs {
	struct kpm_hook_fargs0 f0;
	struct kpm_hook_fargs4 f4;
	struct kpm_hook_fargs8 f8;
	struct kpm_hook_fargs12 f12;
};

struct kpm_hook_callback_snapshot {
	void *before;
	void *after;
	void *udata;
	struct kpm_module *owner;
	bool held;
};

static LIST_HEAD(kpm_hook_records);
static DEFINE_MUTEX(kpm_hook_lock);
static unsigned int kpm_hook_record_count;
static unsigned long kpm_hook_transit[] = {
	(unsigned long)kpm_hook_transit0,
	(unsigned long)kpm_hook_transit4,
	(unsigned long)kpm_hook_transit8,
	(unsigned long)kpm_hook_transit12,
};

static struct kpm_hook_t *kpm_record_inline_hook(struct kpm_hook_record *record)
{
	if (record->kind == KPM_HOOK_INLINE_CHAIN)
		return &record->abi.inline_chain.hook;
	if (record->kind == KPM_HOOK_INLINE_DIRECT)
		return &record->abi.direct_hook;
	return NULL;
}

static struct kpm_hook_chain *kpm_record_inline_chain(
	struct kpm_hook_record *record)
{
	return record->kind == KPM_HOOK_INLINE_CHAIN ?
		&record->abi.inline_chain : NULL;
}

static struct kpm_fp_hook_chain *kpm_record_fp_chain(
	struct kpm_hook_record *record)
{
	return record->kind == KPM_HOOK_FP_CHAIN ? &record->abi.fp_chain : NULL;
}

static bool kpm_record_has_module(struct kpm_hook_record *record,
				  struct module *module)
{
	unsigned int i;

	for (i = 0; i < record->module_ref_count; i++) {
		if (record->module_refs[i] == module)
			return true;
	}
	return false;
}

static int kpm_hook_pin_address(struct kpm_hook_record *record,
				unsigned long address, bool text,
				struct module **domain)
{
	struct module *module;
	int error = -EINVAL;

	if (init_section_intersects((void *)address, sizeof(u32)))
		return -EINVAL;

	if (text && core_kernel_text(address) && !is_kernel_inittext(address)) {
		*domain = NULL;
		return 0;
	}
	if (!text && core_kernel_data((unsigned long)address)) {
		*domain = NULL;
		return 0;
	}
#ifdef CONFIG_MODULES
	preempt_disable();
	module = __module_address(address);
	if (module) {
		if (within_module_init(address, module)) {
			error = -EINVAL;
		} else if (kpm_record_has_module(record, module)) {
			*domain = module;
			error = 0;
		} else if (record->module_ref_count == KPM_HOOK_MODULE_REFS) {
			error = -E2BIG;
		} else if (try_module_get(module)) {
			record->module_refs[record->module_ref_count++] = module;
			*domain = module;
			error = 0;
		} else {
			error = -EBUSY;
		}
	}
	preempt_enable();
#endif
	return error;
}

static int kpm_hook_pin_text_range(struct kpm_hook_record *record,
				   unsigned long address, size_t len)
{
	struct module *domain = NULL;
	struct module *current_domain;
	size_t offset;
	int error;

	if (!len || (address & 3) || (len & 3) || address > ULONG_MAX - len)
		return -EINVAL;
	for (offset = 0; offset < len; offset += sizeof(u32)) {
		error = kpm_hook_pin_address(record, address + offset, true,
					     &current_domain);
		if (error)
			return error;
		if (offset && current_domain != domain)
			return -EINVAL;
		domain = current_domain;
	}
	return 0;
}

static int kpm_hook_pin_data(struct kpm_hook_record *record,
			     unsigned long address)
{
	struct module *domain;

	if ((address & (sizeof(void *) - 1)) ||
	    address > ULONG_MAX - sizeof(void *) ||
	    init_section_intersects((void *)address, sizeof(void *)))
		return -EINVAL;
	return kpm_hook_pin_address(record, address, false, &domain);
}

static void *kpm_hook_exec_alloc(void)
{
	void *page;

#ifdef CONFIG_MODULES
	page = module_alloc(PAGE_SIZE);
#else
	page = __vmalloc(PAGE_SIZE, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
#endif
	if (!page)
		return NULL;
	if (set_memory_nx((unsigned long)page, 1) ||
	    set_memory_rw((unsigned long)page, 1)) {
#ifdef CONFIG_MODULES
		module_memfree(page);
#else
		vfree(page);
#endif
		return NULL;
	}
	return page;
}

static void kpm_hook_exec_free(void *page)
{
	if (!page)
		return;
	set_memory_nx((unsigned long)page, 1);
	set_memory_rw((unsigned long)page, 1);
#ifdef CONFIG_MODULES
	module_memfree(page);
#else
	vfree(page);
#endif
}

static int kpm_hook_exec_seal(void *page)
{
	int error;

	flush_icache_range((unsigned long)page,
			   (unsigned long)page + PAGE_SIZE);
	smp_wmb();
	error = set_memory_ro((unsigned long)page, 1);
	if (error)
		return error;
	error = set_memory_x((unsigned long)page, 1);
	if (error) {
		set_memory_nx((unsigned long)page, 1);
		set_memory_rw((unsigned long)page, 1);
	}
	return error;
}

static void kpm_hook_write_stub(void *page, struct kpm_hook_record *record,
				unsigned long transit)
{
	u32 *code = page;
	u64 chain = (unsigned long)record;
	u64 entry = transit;

	/* BTI JC permits both indirect calls and jumps. */
	code[0] = KPM_ARM64_BTI_JC;
	code[1] = 0x580000b0; /* ldr x16, #20 */
	code[2] = 0x580000d1; /* ldr x17, #24 */
	code[3] = 0xd61f0220; /* br x17 */
	code[4] = 0xd503201f;
	code[5] = 0xd503201f;
	memcpy(&code[6], &chain, sizeof(chain));
	memcpy(&code[8], &entry, sizeof(entry));
}

static int kpm_hook_make_branch(unsigned long from, unsigned long to,
				u32 *instructions, unsigned int *count)
{
	s64 delta;

	if ((from | to) & 3)
		return -EINVAL;
	if (to >= from) {
		delta = (s64)(to - from);
		if (delta <= 0x7fffffcLL) {
			instructions[0] = 0x14000000 |
				(((u64)delta >> 2) & 0x03ffffff);
			instructions[1] = 0xd503201f;
			instructions[2] = 0xd503201f;
			instructions[3] = 0xd503201f;
			*count = KPM_ARM64_HOOK_PATCH_WORDS;
			return 0;
		}
	} else {
		delta = -(s64)(from - to);
		if (delta >= -0x8000000LL) {
			instructions[0] = 0x14000000 |
				(((u64)delta >> 2) & 0x03ffffff);
			instructions[1] = 0xd503201f;
			instructions[2] = 0xd503201f;
			instructions[3] = 0xd503201f;
			*count = KPM_ARM64_HOOK_PATCH_WORDS;
			return 0;
		}
	}
	instructions[0] = 0x58000051;
	instructions[1] = 0xd61f0220;
	instructions[2] = (u32)to;
	instructions[3] = (u32)((u64)to >> 32);
	*count = KPM_ARM64_HOOK_PATCH_WORDS;
	return 0;
}


static int kpm_hook_prepare_inline(struct kpm_hook_t *hook,
				   unsigned long relocated_address);
static void kpm_hook_write_trampoline_entry(void *page)
{
	u32 *entry = (u32 *)((u8 *)page +
			     KPM_HOOK_TRAMPOLINE_ENTRY_OFFSET);

	*entry = KPM_ARM64_BTI_JC;
}

static int kpm_hook_build_stub(struct kpm_hook_record *record)
{
	void *page = record->code_page;
	struct kpm_hook_t *hook = kpm_record_inline_hook(record);
	unsigned long stub = (unsigned long)page;
	unsigned long trampoline = stub + KPM_HOOK_TRAMPOLINE_ENTRY_OFFSET;
	int error;

	if (hook) {
		hook->relo_addr = trampoline;
		hook->replace_addr = stub;
		error = kpm_hook_prepare_inline(
			hook, trampoline + sizeof(u32));
		if (error)
			return error;
		kpm_hook_write_trampoline_entry(page);
		memcpy((u8 *)page + KPM_HOOK_TRAMPOLINE_CODE_OFFSET,
		       hook->relo_insts,
		       hook->relo_insts_num * sizeof(u32));
		kpm_hook_write_stub(page, record,
			kpm_hook_transit[record->arg_group / 4]);
		return kpm_hook_exec_seal(page);
	}
	if (record->kind == KPM_HOOK_FP_CHAIN) {
		struct kpm_fp_hook_chain *chain = &record->abi.fp_chain;

		chain->hook.replace_addr = stub;
		kpm_hook_write_stub(page, record,
			kpm_hook_transit[record->arg_group / 4]);
		return kpm_hook_exec_seal(page);
	}
	return -EINVAL;
}

static int kpm_hook_patch_inline(struct kpm_hook_t *hook, bool install)
{
	struct ksu_patch_text_op op;

	if (!hook || !hook->origin_addr ||
	    hook->tramp_insts_num != KPM_ARM64_HOOK_PATCH_WORDS)
		return -EINVAL;
	op.dst = (void *)hook->origin_addr;
	op.src = install ? (const void *)hook->tramp_insts :
		(const void *)hook->origin_insts;
	op.expected = install ? (const void *)hook->origin_insts :
		(const void *)hook->tramp_insts;
	op.len = KPM_ARM64_HOOK_PATCH_WORDS * sizeof(u32);
	return ksu_patch_text_batch(&op, 1);
}

static int kpm_hook_patch_pointer(unsigned long address, void *expected,
				  void *replacement)
{
	struct ksu_patch_text_op op;

	op.dst = (void *)address;
	op.src = &replacement;
	op.expected = &expected;
	op.len = sizeof(replacement);
	return ksu_patch_text_batch(&op, 1);
}

static void kpm_hook_record_free(struct kpm_hook_record *record)
{
	unsigned int i;

	if (!record)
		return;
	kpm_hook_exec_free(record->code_page);
	for (i = 0; i < record->module_ref_count; i++)
		module_put(record->module_refs[i]);
	kfree(record);
}

static struct kpm_hook_record *kpm_hook_record_alloc(enum kpm_hook_kind kind,
						      unsigned long key)
{
	struct kpm_hook_record *record;

	if (kpm_hook_record_count >= KPM_HOOK_RECORD_LIMIT)
		return NULL;
	record = kzalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return NULL;
	INIT_LIST_HEAD(&record->node);
	record->kind = kind;
	record->key = key;
	spin_lock_init(&record->chain_lock);
	return record;
}

static void kpm_hook_record_keep(struct kpm_hook_record *record)
{
	list_add_tail(&record->node, &kpm_hook_records);
	kpm_hook_record_count++;
}

static struct kpm_hook_record *kpm_hook_find_record(enum kpm_hook_kind kind,
						     unsigned long key)
{
	struct kpm_hook_record *record;

	list_for_each_entry(record, &kpm_hook_records, node) {
		if (record->kind == kind && record->key == key &&
		    record->installed)
			return record;
	}
	return NULL;
}
static struct kpm_hook_record *kpm_hook_find_raw_record(
	struct kpm_hook_t *hook)
{
	struct kpm_hook_record *record;

	list_for_each_entry(record, &kpm_hook_records, node) {
		if (record->raw_hook == hook)
			return record;
	}
	return NULL;
}

static int kpm_hook_error_from_errno(int error)
{
	if (error == -ENOMEM || error == -E2BIG)
		return -HOOK_NO_MEMORY;
	if (error == -EBUSY)
		return -HOOK_DUPLICATED;
	if (error == -EINVAL || error == -EFAULT)
		return -HOOK_BAD_ADDRESS;
	return -HOOK_BAD_RELO;
}

static bool kpm_hook_valid_callback(struct kpm_module *owner,
				    void *callback)
{
	unsigned long address = (unsigned long)callback;
	unsigned long image_start;

	if (!callback)
		return true;
	if (address & 3)
		return false;
	if (core_kernel_text(address) && !is_kernel_inittext(address))
		return true;
	if (!owner || !owner->image)
		return false;
	image_start = (unsigned long)owner->image;
	return address >= image_start && address - image_start < owner->text_size;
}

static unsigned int kpm_hook_chain_limit(struct kpm_hook_record *record)
{
	return record->kind == KPM_HOOK_INLINE_CHAIN ?
		KPM_HOOK_CHAIN_NUM : KPM_FP_HOOK_CHAIN_NUM;
}

static int kpm_hook_chain_add_record(struct kpm_hook_record *record,
				     void *before, void *after, void *udata,
				     struct kpm_module *owner)
{
	struct kpm_hook_chain *inline_chain;
	struct kpm_fp_hook_chain *fp_chain;
	int *items_max;
	s8 *states;
	void **before_items;
	void **after_items;
	void **udata_items;
	unsigned long flags;
	unsigned int i;
	unsigned int limit;
	int empty = -1;
	int max;

	if (!record || !owner || (!before && !after) ||
	    !kpm_hook_valid_callback(owner, before) ||
	    !kpm_hook_valid_callback(owner, after) ||
	    (READ_ONCE(owner->state) != KPM_MODULE_LOADING &&
	     READ_ONCE(owner->state) != KPM_MODULE_LIVE))
		return -HOOK_BAD_ADDRESS;
	inline_chain = kpm_record_inline_chain(record);
	fp_chain = kpm_record_fp_chain(record);
	if (!inline_chain && !fp_chain)
		return -HOOK_BAD_ADDRESS;
	limit = kpm_hook_chain_limit(record);
	if (record->kind == KPM_HOOK_INLINE_CHAIN) {
		items_max = &inline_chain->chain_items_max;
		states = inline_chain->states;
		before_items = inline_chain->befores;
		after_items = inline_chain->afters;
		udata_items = inline_chain->udata;
	} else {
		items_max = &fp_chain->chain_items_max;
		states = fp_chain->states;
		before_items = fp_chain->befores;
		after_items = fp_chain->afters;
		udata_items = fp_chain->udata;
	}
	spin_lock_irqsave(&record->chain_lock, flags);
	max = READ_ONCE(*items_max);
	if (max < 0 || max > limit)
		max = limit;
	for (i = 0; i < max; i++) {
		if (smp_load_acquire(&states[i]) != KPM_HOOK_STATE_READY) {
			if (empty < 0)
				empty = i;
			continue;
		}
		if ((before && READ_ONCE(before_items[i]) == before) ||
		    (after && READ_ONCE(after_items[i]) == after)) {
			spin_unlock_irqrestore(&record->chain_lock, flags);
			return -HOOK_DUPLICATED;
		}
	}
	if (empty < 0 && max < limit)
		empty = max;
	if (empty < 0) {
		spin_unlock_irqrestore(&record->chain_lock, flags);
		return -HOOK_CHAIN_FULL;
	}
	WRITE_ONCE(states[empty], KPM_HOOK_STATE_EMPTY);
	WRITE_ONCE(before_items[empty], before);
	WRITE_ONCE(after_items[empty], after);
	WRITE_ONCE(udata_items[empty], udata);
	rcu_assign_pointer(record->owners[empty], owner);
	if (empty >= max)
		WRITE_ONCE(*items_max, empty + 1);
	smp_store_release(&states[empty], KPM_HOOK_STATE_READY);
	spin_unlock_irqrestore(&record->chain_lock, flags);
	return 0;
}

static bool kpm_hook_chain_remove_record(struct kpm_hook_record *record,
					 void *before, void *after,
					 struct kpm_module *owner)
{
	struct kpm_hook_chain *inline_chain = kpm_record_inline_chain(record);
	struct kpm_fp_hook_chain *fp_chain = kpm_record_fp_chain(record);
	int *items_max;
	s8 *states;
	void **before_items;
	void **after_items;
	void **udata_items;
	unsigned long flags;
	unsigned int i;
	int max;
	bool removed = false;

	if (record->kind == KPM_HOOK_INLINE_CHAIN) {
		items_max = &inline_chain->chain_items_max;
		states = inline_chain->states;
		before_items = inline_chain->befores;
		after_items = inline_chain->afters;
		udata_items = inline_chain->udata;
	} else {
		items_max = &fp_chain->chain_items_max;
		states = fp_chain->states;
		before_items = fp_chain->befores;
		after_items = fp_chain->afters;
		udata_items = fp_chain->udata;
	}
	spin_lock_irqsave(&record->chain_lock, flags);
	max = READ_ONCE(*items_max);
	if (max < 0 || max > kpm_hook_chain_limit(record))
		max = kpm_hook_chain_limit(record);
	for (i = 0; i < max; i++) {
		if (READ_ONCE(states[i]) != KPM_HOOK_STATE_READY)
			continue;
		if ((before || after) &&
		    !((before && READ_ONCE(before_items[i]) == before) ||
		      (after && READ_ONCE(after_items[i]) == after)))
			continue;
		if (owner && rcu_access_pointer(record->owners[i]) != owner)
			continue;
		smp_store_release(&states[i], KPM_HOOK_STATE_EMPTY);
		WRITE_ONCE(before_items[i], NULL);
		WRITE_ONCE(after_items[i], NULL);
		WRITE_ONCE(udata_items[i], NULL);
		rcu_assign_pointer(record->owners[i], NULL);
		removed = true;
	}
	while (max > 0 &&
	       READ_ONCE(states[max - 1]) != KPM_HOOK_STATE_READY)
		max--;
	WRITE_ONCE(*items_max, max);
	spin_unlock_irqrestore(&record->chain_lock, flags);
	return removed;
}

static bool kpm_hook_chain_empty(struct kpm_hook_record *record)
{
	struct kpm_hook_chain *inline_chain = kpm_record_inline_chain(record);
	struct kpm_fp_hook_chain *fp_chain = kpm_record_fp_chain(record);
	int items_max;

	if (inline_chain)
		items_max = READ_ONCE(inline_chain->chain_items_max);
	else
		items_max = READ_ONCE(fp_chain->chain_items_max);
	return items_max <= 0;
}


static int kpm_hook_uninstall_record(struct kpm_hook_record *record)
{
	int error;

	if (record->kind == KPM_HOOK_INLINE_CHAIN) {
		error = kpm_hook_patch_inline(&record->abi.inline_chain.hook,
					      false);
	} else if (record->kind == KPM_HOOK_FP_CHAIN) {
		struct kpm_fp_hook_chain *chain = &record->abi.fp_chain;

		error = kpm_hook_patch_pointer(chain->hook.fp_addr,
					       (void *)chain->hook.replace_addr,
					       (void *)chain->hook.origin_fp);
	} else if (record->kind == KPM_HOOK_INLINE_DIRECT) {
		error = kpm_hook_patch_inline(&record->abi.direct_hook, false);
	} else {
		error = kpm_hook_patch_pointer(record->key,
					       record->direct_replace,
					       record->direct_original);
	}
	if (!error)
		record->installed = false;
	return error;
}

static int kpm_hook_prepare_inline(struct kpm_hook_t *hook,
				   unsigned long relocated_address)
{
	kpm_hook_insn_t source[KPM_ARM64_HOOK_PATCH_WORDS];
	size_t relocated_words;
	unsigned int branch_count;
	int error;

	if (!hook || !hook->origin_addr || !hook->replace_addr ||
	    !hook->relo_addr || !relocated_address ||
	    (hook->origin_addr & 3) || (hook->relo_addr & 3) ||
	    (relocated_address & 3))
		return -HOOK_BAD_ADDRESS;
	if (probe_kernel_read(source, (void *)hook->origin_addr,
			      sizeof(source)))
		return -HOOK_BAD_ADDRESS;
	memcpy(hook->origin_insts, source, sizeof(source));
	error = kpm_arm64_relocate_hook(
		source, hook->origin_addr, KPM_ARM64_HOOK_PATCH_WORDS,
		hook->relo_insts, relocated_address,
		KPM_HOOK_RELOCATE_WORDS, &relocated_words);
	if (error || relocated_words > KPM_HOOK_RELOCATE_WORDS)
		return -HOOK_BAD_RELO;
	hook->relo_insts_num = relocated_words;
	error = kpm_hook_make_branch(hook->origin_addr, hook->replace_addr,
				     hook->tramp_insts, &branch_count);
	if (error || branch_count != KPM_ARM64_HOOK_PATCH_WORDS)
		return -HOOK_BAD_RELO;
	hook->tramp_insts_num = branch_count;
	return 0;
}

int hook_prepare(struct kpm_hook_t *hook)
{
	struct kpm_hook_record *record;
	struct kpm_module *owner = kpm_current_module();
	unsigned long target;
	int error;

	if (!owner || (READ_ONCE(owner->state) != KPM_MODULE_LOADING &&
		       READ_ONCE(owner->state) != KPM_MODULE_LIVE) ||
	    !hook || !hook->replace_addr ||
	    !kpm_hook_valid_callback(owner, (void *)hook->replace_addr))
		return -HOOK_BAD_ADDRESS;
	target = branch_func_addr(hook->origin_addr);
	if (!target)
		return -HOOK_BAD_ADDRESS;
	hook->origin_addr = target;
	mutex_lock(&kpm_hook_lock);
	if (kpm_hook_find_raw_record(hook) ||
	    kpm_hook_find_record(KPM_HOOK_INLINE_DIRECT, target) ||
	    kpm_hook_find_record(KPM_HOOK_INLINE_CHAIN, target)) {
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_DUPLICATED;
	}
	if (kpm_hook_record_count >= KPM_HOOK_RECORD_LIMIT) {
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_NO_MEMORY;
	}
	record = kpm_hook_record_alloc(KPM_HOOK_INLINE_DIRECT, target);
	if (!record) {
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_NO_MEMORY;
	}
	record->direct_owner = owner;
	record->raw_hook = hook;
	record->code_page = kpm_hook_exec_alloc();
	if (!record->code_page) {
		error = -HOOK_NO_MEMORY;
		goto fail;
	}
	error = kpm_hook_pin_text_range(record, target,
					KPM_ARM64_HOOK_PATCH_SIZE);
	if (error) {
		error = kpm_hook_error_from_errno(error);
		goto fail;
	}
	hook->relo_addr = (unsigned long)record->code_page +
		KPM_HOOK_TRAMPOLINE_ENTRY_OFFSET;
	error = kpm_hook_prepare_inline(
		hook, hook->relo_addr + sizeof(u32));
	if (error)
		goto fail;
	kpm_hook_write_trampoline_entry(record->code_page);
	memcpy((u8 *)record->code_page + KPM_HOOK_TRAMPOLINE_CODE_OFFSET,
	       hook->relo_insts, hook->relo_insts_num * sizeof(u32));
	error = kpm_hook_exec_seal(record->code_page);
	if (error) {
		error = kpm_hook_error_from_errno(error);
		goto fail;
	}
	record->abi.direct_hook = *hook;
	record->direct_original = (void *)hook->relo_addr;
	record->direct_replace = (void *)hook->replace_addr;
	kpm_hook_record_keep(record);
	mutex_unlock(&kpm_hook_lock);
	return 0;
fail:
	kpm_hook_record_free(record);
	mutex_unlock(&kpm_hook_lock);
	return error;
}

void hook_install(struct kpm_hook_t *hook)
{
	struct kpm_hook_record *record;
	struct kpm_module *owner = kpm_current_module();
	int error;

	if (!owner || !hook) {
		pr_err("KPM: hook_install requires an owning module\n");
		return;
	}
	mutex_lock(&kpm_hook_lock);
	record = kpm_hook_find_raw_record(hook);
	if (!record || record->direct_owner != owner) {
		error = -HOOK_BAD_ADDRESS;
	} else if (record->installed) {
		error = -HOOK_DUPLICATED;
	} else {
		error = kpm_hook_patch_inline(&record->abi.direct_hook, true);
		if (!error || error == -EUCLEAN) {
			record->installed = true;
			WRITE_ONCE(owner->ever_patched, true);
		}
	}
	mutex_unlock(&kpm_hook_lock);
	if (error)
		pr_err("KPM: hook_install failed for %px: %d\n",
		       hook ? (void *)hook->origin_addr : NULL, error);
}

void hook_uninstall(struct kpm_hook_t *hook)
{
	struct kpm_hook_record *record;
	struct kpm_module *owner = kpm_current_module();
	int error;

	if (!owner || !hook)
		return;
	mutex_lock(&kpm_hook_lock);
	record = kpm_hook_find_raw_record(hook);
	if (!record || record->direct_owner != owner)
		error = -HOOK_BAD_ADDRESS;
	else if (!record->installed) {
		list_del_init(&record->node);
		kpm_hook_record_count--;
		kpm_hook_record_free(record);
		error = 0;
	} else {
		error = kpm_hook_patch_inline(&record->abi.direct_hook, false);
		if (!error)
			record->installed = false;
	}
	mutex_unlock(&kpm_hook_lock);
	if (error)
		pr_err("KPM: hook_uninstall failed for %px: %d\n",
		       hook ? (void *)hook->origin_addr : NULL, error);
}

s32 branch_relative(u32 *instructions, u64 from, u64 to)
{
	u64 delta;

	if (!instructions || ((from | to) & 3))
		return 0;
	if (to >= from) {
		delta = to - from;
		if (delta > 0x7fffffcULL)
			return 0;
	} else {
		delta = from - to;
		if (delta > 0x8000000ULL)
			return 0;
	}
	instructions[0] = 0x14000000 |
		(((to - from) >> 2) & 0x03ffffff);
	instructions[1] = 0xd503201f;
	return 2;
}

s32 branch_absolute(u32 *instructions, u64 to)
{
	if (!instructions)
		return 0;
	instructions[0] = 0x58000051;
	instructions[1] = 0xd61f0220;
	instructions[2] = (u32)to;
	instructions[3] = (u32)(to >> 32);
	return 4;
}

s32 ret_absolute(u32 *instructions, u64 to)
{
	if (!instructions)
		return 0;
	instructions[0] = 0x58000051;
	instructions[1] = 0xd65f0220;
	instructions[2] = (u32)to;
	instructions[3] = (u32)(to >> 32);
	return 4;
}

s32 branch_from_to(u32 *instructions, u64 from, u64 to)
{
	(void)from;
	return ret_absolute(instructions, to);
}

unsigned long branch_func_addr(unsigned long address)
{
	u32 instruction;
	unsigned long target;
	int i;

	for (i = 0; i < 8; i++) {
		if (probe_kernel_read(&instruction, (void *)address,
				      sizeof(instruction)))
			break;
		if ((instruction & 0xfffffc1f) == 0xd503241f) {
			address += sizeof(instruction);
			continue;
		}
		if ((instruction & 0xfc000000) != 0x14000000)
			break;
		target = address + ((s64)((s32)(instruction << 6) >> 4));
		if (target == address)
			break;
		address = target;
	}
	return address;
}


static int *kpm_hook_fargs_skip(union kpm_hook_fargs *fargs,
				unsigned int group)
{
	switch (group) {
	case 0:
		return &fargs->f0.skip_origin;
	case 4:
		return &fargs->f4.skip_origin;
	case 8:
		return &fargs->f8.skip_origin;
	default:
		return &fargs->f12.skip_origin;
	}
}

static u64 *kpm_hook_fargs_ret(union kpm_hook_fargs *fargs,
			       unsigned int group)
{
	switch (group) {
	case 0:
		return &fargs->f0.ret;
	case 4:
		return &fargs->f4.ret;
	case 8:
		return &fargs->f8.ret;
	default:
		return &fargs->f12.ret;
	}
}

static u64 *kpm_hook_fargs_args(union kpm_hook_fargs *fargs,
				unsigned int group)
{
	switch (group) {
	case 0:
		return fargs->f0.args;
	case 4:
		return fargs->f4.args;
	case 8:
		return fargs->f8.args;
	default:
		return fargs->f12.args;
	}
}

static void kpm_hook_call_callback(union kpm_hook_fargs *fargs,
				   unsigned int group, void *callback,
				   void *udata)
{
	if (!callback)
		return;
	switch (group) {
	case 0:
		((void (*)(struct kpm_hook_fargs0 *, void *))callback)(
			&fargs->f0, udata);
		break;
	case 4:
		((void (*)(struct kpm_hook_fargs4 *, void *))callback)(
			&fargs->f4, udata);
		break;
	case 8:
		((void (*)(struct kpm_hook_fargs8 *, void *))callback)(
			&fargs->f8, udata);
		break;
	default:
		((void (*)(struct kpm_hook_fargs12 *, void *))callback)(
			&fargs->f12, udata);
		break;
	}
}

static u64 kpm_hook_call_origin(struct kpm_hook_record *record,
				union kpm_hook_fargs *fargs,
				unsigned int group)
{
	u64 *args = kpm_hook_fargs_args(fargs, group);
	unsigned long origin;

	if (record->kind == KPM_HOOK_INLINE_CHAIN)
		origin = record->abi.inline_chain.hook.relo_addr;
	else
		origin = record->abi.fp_chain.hook.origin_fp;
	switch (group) {
	case 0:
		return ((u64 (*)(void))origin)();
	case 4:
		return ((u64 (*)(u64, u64, u64, u64))origin)(
			args[0], args[1], args[2], args[3]);
	case 8:
		return ((u64 (*)(u64, u64, u64, u64, u64, u64, u64, u64))origin)(
			args[0], args[1], args[2], args[3], args[4], args[5],
			args[6], args[7]);
	default:
		return ((u64 (*)(u64, u64, u64, u64, u64, u64, u64, u64,
				 u64, u64, u64, u64))origin)(
			args[0], args[1], args[2], args[3], args[4], args[5],
			args[6], args[7], args[8], args[9], args[10], args[11]);
	}
}

static u64 kpm_hook_dispatch_record(struct kpm_hook_record *record,
				   const u64 *register_args,
				   const u64 *stack_args,
				   unsigned int group)
{
	struct kpm_hook_callback_snapshot snapshot[KPM_FP_HOOK_CHAIN_NUM];
	union kpm_hook_fargs fargs;
	struct kpm_hook_chain *inline_chain;
	struct kpm_fp_hook_chain *fp_chain;
	unsigned long flags;
	unsigned int max;
	unsigned int limit;
	unsigned int i;
	u64 *args;
	u64 ret;

	memset(snapshot, 0, sizeof(snapshot));
	memset(&fargs, 0, sizeof(fargs));
	if (!record || group != record->arg_group ||
	    (group != 0 && group != 4 && group != 8 && group != 12))
		return 0;
	inline_chain = kpm_record_inline_chain(record);
	fp_chain = kpm_record_fp_chain(record);
	if (!inline_chain && !fp_chain)
		return 0;
	limit = kpm_hook_chain_limit(record);
	rcu_read_lock();
	spin_lock_irqsave(&record->chain_lock, flags);
	max = inline_chain ? READ_ONCE(inline_chain->chain_items_max) :
		READ_ONCE(fp_chain->chain_items_max);
	if (max > limit)
		max = limit;
	for (i = 0; i < max; i++) {
		s8 state = inline_chain ? inline_chain->states[i] :
			fp_chain->states[i];

		if (state != KPM_HOOK_STATE_READY)
			continue;
		snapshot[i].before = inline_chain ?
			READ_ONCE(inline_chain->befores[i]) :
			READ_ONCE(fp_chain->befores[i]);
		snapshot[i].after = inline_chain ?
			READ_ONCE(inline_chain->afters[i]) :
			READ_ONCE(fp_chain->afters[i]);
		snapshot[i].udata = inline_chain ?
			READ_ONCE(inline_chain->udata[i]) :
			READ_ONCE(fp_chain->udata[i]);
		snapshot[i].owner = rcu_dereference(record->owners[i]);
	}
	spin_unlock_irqrestore(&record->chain_lock, flags);
	for (i = 0; i < max; i++) {
		if (!snapshot[i].owner ||
		    (!snapshot[i].before && !snapshot[i].after))
			continue;
		if (kpm_module_try_get_rcu(snapshot[i].owner))
			snapshot[i].held = true;
		else {
			snapshot[i].before = NULL;
			snapshot[i].after = NULL;
		}
	}
	rcu_read_unlock();
	if (inline_chain)
		fargs.f0.chain = inline_chain;
	else
		fargs.f0.chain = fp_chain;
	args = kpm_hook_fargs_args(&fargs, group);
	for (i = 0; i < group; i++)
		args[i] = register_args ? register_args[i] : 0;
	if (group == 12 && stack_args) {
		for (i = 8; i < record->argno; i++)
			args[i] = stack_args[i - 8];
	}
	for (i = 0; i < max; i++) {
		if (snapshot[i].held)
			kpm_hook_call_callback(&fargs, group, snapshot[i].before,
					       snapshot[i].udata);
	}
	if (!*kpm_hook_fargs_skip(&fargs, group)) {
		ret = kpm_hook_call_origin(record, &fargs, group);
		*kpm_hook_fargs_ret(&fargs, group) = ret;
	}
	for (i = max; i > 0; i--) {
		struct kpm_hook_callback_snapshot *entry = &snapshot[i - 1];

		if (entry->held)
			kpm_hook_call_callback(&fargs, group, entry->after,
					       entry->udata);
	}
	ret = *kpm_hook_fargs_ret(&fargs, group);
	for (i = 0; i < max; i++) {
		if (snapshot[i].held)
			kpm_module_put(snapshot[i].owner);
	}
	return ret;
}

u64 kpm_hook_dispatch_inline(void *record, const u64 *register_args,
			     const u64 *stack_args, unsigned int group)
{
	return kpm_hook_dispatch_record(record, register_args, stack_args,
					group);
}

static struct kpm_hook_record *kpm_hook_new_inline(
		unsigned long target, unsigned int argno,
		struct kpm_module *owner, void *before, void *after, void *udata,
		int *error)
{
	struct kpm_hook_record *record;
	struct kpm_hook_t *hook;
	unsigned int group = (argno + 3) & ~3U;
	int patch_error;

	if (group > 12)
		group = 12;
	record = kpm_hook_record_alloc(KPM_HOOK_INLINE_CHAIN, target);
	if (!record) {
		*error = -HOOK_NO_MEMORY;
		return NULL;
	}
	record->argno = argno;
	record->arg_group = group;
	record->code_page = kpm_hook_exec_alloc();
	if (!record->code_page) {
		*error = -HOOK_NO_MEMORY;
		goto fail;
	}
	hook = &record->abi.inline_chain.hook;
	hook->func_addr = target;
	hook->origin_addr = target;
	hook->replace_addr = (unsigned long)record->code_page;
	hook->relo_addr = (unsigned long)record->code_page +
		KPM_HOOK_TRAMPOLINE_ENTRY_OFFSET;
	patch_error = kpm_hook_pin_text_range(record, target,
					      KPM_ARM64_HOOK_PATCH_SIZE);
	if (patch_error) {
		*error = kpm_hook_error_from_errno(patch_error);
		goto fail;
	}
	patch_error = kpm_hook_chain_add_record(record, before, after, udata,
						owner);
	if (patch_error) {
		*error = patch_error;
		goto fail;
	}
	patch_error = kpm_hook_build_stub(record);
	if (patch_error) {
		*error = patch_error < 0 ?
			kpm_hook_error_from_errno(patch_error) : patch_error;
		goto fail;
	}
	patch_error = kpm_hook_patch_inline(hook, true);
	if (patch_error == -EUCLEAN) {
		WRITE_ONCE(owner->ever_patched, true);
		record->installed = true;
		kpm_hook_record_keep(record);
		*error = -HOOK_BAD_ADDRESS;
		return NULL;
	}
	if (patch_error) {
		*error = kpm_hook_error_from_errno(patch_error);
		goto fail;
	}
	record->installed = true;
	kpm_hook_record_keep(record);
	*error = 0;
	return record;
fail:
	kpm_hook_record_free(record);
	return NULL;
}

int hook_wrap(void *func, int argno, void *before, void *after, void *udata)
{
	struct kpm_hook_record *record;
	struct kpm_module *owner = kpm_current_module();
	unsigned long target;
	int error;

	if (!owner || (READ_ONCE(owner->state) != KPM_MODULE_LOADING &&
		       READ_ONCE(owner->state) != KPM_MODULE_LIVE))
		return -HOOK_BAD_ADDRESS;
	if (argno < 0 || argno > 12 || (!before && !after))
		return -HOOK_BAD_ADDRESS;
	target = branch_func_addr((unsigned long)func);
	if (!target)
		return -HOOK_BAD_ADDRESS;
	mutex_lock(&kpm_hook_lock);
	record = kpm_hook_find_record(KPM_HOOK_INLINE_CHAIN, target);
	if (record) {
		if (record->argno != argno) {
			error = -HOOK_BAD_ADDRESS;
		} else {
			error = kpm_hook_chain_add_record(record, before, after,
							 udata, owner);
		}
		mutex_unlock(&kpm_hook_lock);
		return error;
	}
	if (kpm_hook_find_record(KPM_HOOK_INLINE_DIRECT, target)) {
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_DUPLICATED;
	}
	if (kpm_hook_record_count >= KPM_HOOK_RECORD_LIMIT) {
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_NO_MEMORY;
	}
	record = kpm_hook_new_inline(target, argno, owner, before, after,
				     udata, &error);
	mutex_unlock(&kpm_hook_lock);
	return error;
}

void hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
	struct kpm_hook_record *record;
	unsigned long target = branch_func_addr((unsigned long)func);
	int error;

	mutex_lock(&kpm_hook_lock);
	record = kpm_hook_find_record(KPM_HOOK_INLINE_CHAIN, target);
	if (record && kpm_hook_chain_remove_record(record, before, after, NULL) &&
	    remove && kpm_hook_chain_empty(record)) {
		error = kpm_hook_uninstall_record(record);
		if (error)
			pr_err("KPM: failed to remove hook at %px: %d\n",
			       (void *)target, error);
	}
	mutex_unlock(&kpm_hook_lock);
	if (record && remove)
		synchronize_rcu();
}

int hook_chain_add(struct kpm_hook_chain *chain, void *before, void *after,
		   void *udata)
{
	struct kpm_hook_record *record;
	struct kpm_module *owner = kpm_current_module();

	if (!chain)
		return -HOOK_BAD_ADDRESS;
	record = container_of(chain, struct kpm_hook_record, abi.inline_chain);
	if (record->kind != KPM_HOOK_INLINE_CHAIN || !READ_ONCE(record->installed))
		return -HOOK_BAD_ADDRESS;
	return kpm_hook_chain_add_record(record, before, after, udata, owner);
}

void hook_chain_remove(struct kpm_hook_chain *chain, void *before, void *after)
{
	struct kpm_hook_record *record;

	if (!chain)
		return;
	record = container_of(chain, struct kpm_hook_record, abi.inline_chain);
	if (record->kind == KPM_HOOK_INLINE_CHAIN)
		kpm_hook_chain_remove_record(record, before, after, NULL);
}

static struct kpm_hook_record *kpm_hook_new_fp(
		unsigned long address, void *original, unsigned int argno,
		struct kpm_module *owner, void *before, void *after, void *udata,
		int *error)
{
	struct kpm_hook_record *record;
	struct kpm_fp_hook_chain *chain;
	void *stub;
	int patch_error;
	unsigned int group = (argno + 3) & ~3U;

	if (group > 12)
		group = 12;
	record = kpm_hook_record_alloc(KPM_HOOK_FP_CHAIN, address);
	if (!record) {
		*error = -HOOK_NO_MEMORY;
		return NULL;
	}
	record->argno = argno;
	record->arg_group = group;
	record->code_page = kpm_hook_exec_alloc();
	if (!record->code_page) {
		*error = -HOOK_NO_MEMORY;
		goto fail;
	}
	chain = &record->abi.fp_chain;
	chain->hook.fp_addr = address;
	chain->hook.origin_fp = (unsigned long)original;
	stub = record->code_page;
	chain->hook.replace_addr = (unsigned long)stub;
	patch_error = kpm_hook_pin_data(record, address);
	if (!patch_error)
		patch_error = kpm_hook_pin_text_range(record,
						      (unsigned long)original,
						      sizeof(u32));
	if (patch_error) {
		*error = kpm_hook_error_from_errno(patch_error);
		goto fail;
	}
	patch_error = kpm_hook_chain_add_record(record, before, after, udata,
						owner);
	if (patch_error) {
		*error = patch_error;
		goto fail;
	}
	kpm_hook_write_stub(record->code_page, record,
		kpm_hook_transit[group / 4]);
	patch_error = kpm_hook_exec_seal(record->code_page);
	if (patch_error) {
		*error = kpm_hook_error_from_errno(patch_error);
		goto fail;
	}
	patch_error = kpm_hook_patch_pointer(address, original, stub);
	if (patch_error == -EUCLEAN) {
		WRITE_ONCE(owner->ever_patched, true);
		record->installed = true;
		kpm_hook_record_keep(record);
		*error = -HOOK_BAD_ADDRESS;
		return NULL;
	}
	if (patch_error) {
		*error = kpm_hook_error_from_errno(patch_error);
		goto fail;
	}
	record->installed = true;
	kpm_hook_record_keep(record);
	*error = 0;
	return record;
fail:
	kpm_hook_record_free(record);
	return NULL;
}

int fp_hook_wrap(void *fp_addr, int argno, void *before, void *after,
		 void *udata)
{
	struct kpm_hook_record *record;
	struct kpm_module *owner = kpm_current_module();
	void *original;
	int error;

	if (!owner || (READ_ONCE(owner->state) != KPM_MODULE_LOADING &&
		       READ_ONCE(owner->state) != KPM_MODULE_LIVE))
		return -HOOK_BAD_ADDRESS;
	if (argno < 0 || argno > 12 || (!before && !after) || !fp_addr)
		return -HOOK_BAD_ADDRESS;
	if (probe_kernel_read(&original, fp_addr, sizeof(original)) || !original)
		return -HOOK_BAD_ADDRESS;
	mutex_lock(&kpm_hook_lock);
	record = kpm_hook_find_record(KPM_HOOK_FP_CHAIN,
				      (unsigned long)fp_addr);
	if (record) {
		if (record->argno != argno)
			error = -HOOK_BAD_ADDRESS;
		else
			error = kpm_hook_chain_add_record(record, before, after,
							 udata, owner);
		mutex_unlock(&kpm_hook_lock);
		return error;
	}
	if (kpm_hook_record_count >= KPM_HOOK_RECORD_LIMIT) {
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_NO_MEMORY;
	}
	kpm_hook_new_fp((unsigned long)fp_addr, original, argno, owner,
			before, after, udata, &error);
	mutex_unlock(&kpm_hook_lock);
	return error;
}

void fp_hook_unwrap(void *fp_addr, void *before, void *after)
{
	struct kpm_hook_record *record;
	unsigned long address = (unsigned long)fp_addr;
	int error;

	mutex_lock(&kpm_hook_lock);
	record = kpm_hook_find_record(KPM_HOOK_FP_CHAIN, address);
	if (record && kpm_hook_chain_remove_record(record, before, after, NULL) &&
	    kpm_hook_chain_empty(record)) {
		error = kpm_hook_uninstall_record(record);
		if (error)
			pr_err("KPM: failed to remove fp hook at %px: %d\n",
			       fp_addr, error);
	}
	mutex_unlock(&kpm_hook_lock);
	if (record)
		synchronize_rcu();
}

void fp_hook(void *fp_addr, void *replace_func, void **backup_func)
{
	struct kpm_hook_record *record;
	struct kpm_module *owner = kpm_current_module();
	void *original;
	int error;

	if (!owner || !fp_addr || !replace_func || !backup_func ||
	    (READ_ONCE(owner->state) != KPM_MODULE_LOADING &&
	     READ_ONCE(owner->state) != KPM_MODULE_LIVE) ||
	    probe_kernel_read(&original, fp_addr, sizeof(original)) || !original ||
	    !kpm_hook_valid_callback(owner, replace_func))
		return;
	mutex_lock(&kpm_hook_lock);
	if (kpm_hook_find_record(KPM_HOOK_FP_DIRECT, (unsigned long)fp_addr) ||
	    kpm_hook_record_count >= KPM_HOOK_RECORD_LIMIT) {
		mutex_unlock(&kpm_hook_lock);
		return;
	}
	record = kpm_hook_record_alloc(KPM_HOOK_FP_DIRECT,
				       (unsigned long)fp_addr);
	if (!record) {
		mutex_unlock(&kpm_hook_lock);
		return;
	}
	error = kpm_hook_pin_data(record, (unsigned long)fp_addr);
	if (!error)
		error = kpm_hook_pin_text_range(record, (unsigned long)original,
						 sizeof(u32));
	if (error) {
		kpm_hook_record_free(record);
		mutex_unlock(&kpm_hook_lock);
		return;
	}
	error = kpm_hook_patch_pointer((unsigned long)fp_addr, original,
				       replace_func);
	if (error == -EUCLEAN) {
		record->direct_original = original;
		record->direct_replace = replace_func;
		record->direct_owner = owner;
		record->installed = true;
		WRITE_ONCE(owner->ever_patched, true);
		*backup_func = original;
		kpm_hook_record_keep(record);
	} else if (!error) {
		record->direct_original = original;
		record->direct_replace = replace_func;
		record->direct_owner = owner;
		record->installed = true;
		WRITE_ONCE(owner->ever_patched, true);
		*backup_func = original;
		kpm_hook_record_keep(record);
	} else {
		kpm_hook_record_free(record);
	}
	mutex_unlock(&kpm_hook_lock);
}

void fp_unhook(void *fp_addr, void *backup_func)
{
	struct kpm_hook_record *record;
	int error;

	mutex_lock(&kpm_hook_lock);
	record = kpm_hook_find_record(KPM_HOOK_FP_DIRECT,
				      (unsigned long)fp_addr);
	if (record && record->direct_original == backup_func) {
		error = kpm_hook_uninstall_record(record);
		if (error)
			pr_err("KPM: fp_unhook failed at %px: %d\n",
			       fp_addr, error);
	}
	mutex_unlock(&kpm_hook_lock);
}

int hook(void *func, void *replace_func, void **backup_func)
{
	struct kpm_hook_record *record;
	struct kpm_module *owner = kpm_current_module();
	struct kpm_hook_t *hook;
	unsigned long target;
	int error;

	if (!owner || (READ_ONCE(owner->state) != KPM_MODULE_LOADING &&
		       READ_ONCE(owner->state) != KPM_MODULE_LIVE) ||
	    !func || !replace_func || !backup_func ||
	    !kpm_hook_valid_callback(owner, replace_func))
		return -HOOK_BAD_ADDRESS;
	target = branch_func_addr((unsigned long)func);
	mutex_lock(&kpm_hook_lock);
	if (kpm_hook_find_record(KPM_HOOK_INLINE_DIRECT, target) ||
	    kpm_hook_find_record(KPM_HOOK_INLINE_CHAIN, target)) {
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_DUPLICATED;
	}
	if (kpm_hook_record_count >= KPM_HOOK_RECORD_LIMIT) {
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_NO_MEMORY;
	}
	record = kpm_hook_record_alloc(KPM_HOOK_INLINE_DIRECT, target);
	if (!record) {
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_NO_MEMORY;
	}
	record->direct_owner = owner;
	record->code_page = kpm_hook_exec_alloc();
	if (!record->code_page) {
		kpm_hook_record_free(record);
		mutex_unlock(&kpm_hook_lock);
		return -HOOK_NO_MEMORY;
	}
	error = kpm_hook_pin_text_range(record, target,
					KPM_ARM64_HOOK_PATCH_SIZE);
	if (error) {
		kpm_hook_record_free(record);
		mutex_unlock(&kpm_hook_lock);
		return kpm_hook_error_from_errno(error);
	}
	hook = &record->abi.direct_hook;
	hook->func_addr = (unsigned long)func;
	hook->origin_addr = target;
	hook->replace_addr = (unsigned long)replace_func;
	hook->relo_addr = (unsigned long)record->code_page +
		KPM_HOOK_TRAMPOLINE_ENTRY_OFFSET;
	error = kpm_hook_prepare_inline(
		hook, hook->relo_addr + sizeof(u32));
	if (error) {
		kpm_hook_record_free(record);
		mutex_unlock(&kpm_hook_lock);
		return error;
	}
	kpm_hook_write_trampoline_entry(record->code_page);
	memcpy((u8 *)record->code_page + KPM_HOOK_TRAMPOLINE_CODE_OFFSET,
	       hook->relo_insts, hook->relo_insts_num * sizeof(u32));
	error = kpm_hook_exec_seal(record->code_page);
	if (!error)
		error = kpm_hook_patch_inline(hook, true);
	if (error && error != -EUCLEAN) {
		kpm_hook_record_free(record);
		mutex_unlock(&kpm_hook_lock);
		return kpm_hook_error_from_errno(error);
	}
	record->direct_original = (void *)hook->relo_addr;
	record->direct_replace = replace_func;
	record->installed = true;
	WRITE_ONCE(owner->ever_patched, true);
	*backup_func = (void *)hook->relo_addr;
	kpm_hook_record_keep(record);
	mutex_unlock(&kpm_hook_lock);
	return error ? -HOOK_BAD_ADDRESS : 0;
}

void unhook(void *func)
{
	struct kpm_hook_record *record;
	unsigned long target = branch_func_addr((unsigned long)func);
	int error;

	mutex_lock(&kpm_hook_lock);
	record = kpm_hook_find_record(KPM_HOOK_INLINE_DIRECT, target);
	if (record) {
		error = kpm_hook_uninstall_record(record);
		if (error)
			pr_err("KPM: unhook failed at %px: %d\n",
			       (void *)target, error);
	}
	mutex_unlock(&kpm_hook_lock);
}

static bool kpm_hook_chain_remove_owner(struct kpm_hook_record *record,
					struct kpm_module *owner)
{
	struct kpm_hook_chain *inline_chain = kpm_record_inline_chain(record);
	struct kpm_fp_hook_chain *fp_chain = kpm_record_fp_chain(record);
	int *items_max;
	s8 *states;
	void **before_items;
	void **after_items;
	void **udata_items;
	unsigned long flags;
	unsigned int i;
	int max;
	bool removed = false;

	if (inline_chain) {
		items_max = &inline_chain->chain_items_max;
		states = inline_chain->states;
		before_items = inline_chain->befores;
		after_items = inline_chain->afters;
		udata_items = inline_chain->udata;
	} else {
		items_max = &fp_chain->chain_items_max;
		states = fp_chain->states;
		before_items = fp_chain->befores;
		after_items = fp_chain->afters;
		udata_items = fp_chain->udata;
	}
	spin_lock_irqsave(&record->chain_lock, flags);
	max = READ_ONCE(*items_max);
	if (max < 0 || max > kpm_hook_chain_limit(record))
		max = kpm_hook_chain_limit(record);
	for (i = 0; i < max; i++) {
		if (smp_load_acquire(&states[i]) != KPM_HOOK_STATE_READY ||
		    rcu_access_pointer(record->owners[i]) != owner)
			continue;
		smp_store_release(&states[i], KPM_HOOK_STATE_EMPTY);
		WRITE_ONCE(before_items[i], NULL);
		WRITE_ONCE(after_items[i], NULL);
		WRITE_ONCE(udata_items[i], NULL);
		rcu_assign_pointer(record->owners[i], NULL);
		removed = true;
	}
	while (max > 0 &&
	       smp_load_acquire(&states[max - 1]) != KPM_HOOK_STATE_READY)
		max--;
	WRITE_ONCE(*items_max, max);
	spin_unlock_irqrestore(&record->chain_lock, flags);
	return removed;
}

void kpm_hook_remove_owner(struct kpm_module *owner)
{
	struct kpm_hook_record *record;
	struct kpm_hook_record *next;
	int error;

	if (!owner)
		return;
	mutex_lock(&kpm_hook_lock);
	list_for_each_entry_safe(record, next, &kpm_hook_records, node) {
		if (record->direct_owner == owner && record->raw_hook &&
		    !record->installed) {
			list_del_init(&record->node);
			kpm_hook_record_count--;
			kpm_hook_record_free(record);
			continue;
		}
		if ((record->kind != KPM_HOOK_INLINE_CHAIN &&
		     record->kind != KPM_HOOK_FP_CHAIN) ||
		    !kpm_hook_chain_remove_owner(record, owner) ||
		    !kpm_hook_chain_empty(record))
			continue;
		error = kpm_hook_uninstall_record(record);
		if (error)
			pr_err("KPM: owner cleanup failed at %px: %d\n",
			       (void *)record->key, error);
	}
	mutex_unlock(&kpm_hook_lock);
	synchronize_rcu();
}
