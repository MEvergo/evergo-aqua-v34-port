/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __SUKISU_KPM_HOOK_ABI_H
#define __SUKISU_KPM_HOOK_ABI_H

#include <linux/types.h>

#define KPM_HOOK_CHAIN_NUM 16
#define KPM_FP_HOOK_CHAIN_NUM 32
#define KPM_HOOK_TRANSIT_WORDS 96
#define KPM_HOOK_TRAMPOLINE_WORDS 6
#define KPM_HOOK_RELOCATE_WORDS 36

#define KPM_HOOK_ITEM_EMPTY 0
#define KPM_HOOK_ITEM_READY 1
#define KPM_HOOK_ITEM_BUSY 2

#define KPM_HOOK_NO_ERROR 0
#define KPM_HOOK_BAD_ADDRESS 4095
#define KPM_HOOK_DUPLICATED 4094
#define KPM_HOOK_NO_MEMORY 4093
#define KPM_HOOK_BAD_RELOCATION 4092
#define KPM_HOOK_TRANSIT_NO_MEMORY 4091
#define KPM_HOOK_CHAIN_FULL 4090

struct kpm_hook_t {
	u64 func_addr;
	u64 origin_addr;
	u64 replace_addr;
	u64 relo_addr;
	s32 tramp_insts_num;
	s32 relo_insts_num;
	u32 origin_insts[KPM_HOOK_TRAMPOLINE_WORDS] __aligned(8);
	u32 tramp_insts[KPM_HOOK_TRAMPOLINE_WORDS] __aligned(8);
	u32 relo_insts[KPM_HOOK_RELOCATE_WORDS] __aligned(8);
} __aligned(8);

struct kpm_hook_fargs_local {
	union {
		struct {
			u64 data0;
			u64 data1;
			u64 data2;
			u64 data3;
			u64 data4;
			u64 data5;
			u64 data6;
			u64 data7;
		};
		u64 data[8];
	};
};

#define KPM_HOOK_FARGS_FIELDS \
	void *chain; \
	int skip_origin; \
	struct kpm_hook_fargs_local local; \
	u64 ret

struct kpm_hook_fargs0 {
	KPM_HOOK_FARGS_FIELDS;
	u64 args[0];
} __aligned(8);

struct kpm_hook_fargs4 {
	KPM_HOOK_FARGS_FIELDS;
	union {
		struct { u64 arg0, arg1, arg2, arg3; };
		u64 args[4];
	};
} __aligned(8);

typedef struct kpm_hook_fargs4 kpm_hook_fargs1;
typedef struct kpm_hook_fargs4 kpm_hook_fargs2;
typedef struct kpm_hook_fargs4 kpm_hook_fargs3;

struct kpm_hook_fargs8 {
	KPM_HOOK_FARGS_FIELDS;
	union {
		struct { u64 arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7; };
		u64 args[8];
	};
} __aligned(8);

typedef struct kpm_hook_fargs8 kpm_hook_fargs5;
typedef struct kpm_hook_fargs8 kpm_hook_fargs6;
typedef struct kpm_hook_fargs8 kpm_hook_fargs7;

struct kpm_hook_fargs12 {
	KPM_HOOK_FARGS_FIELDS;
	union {
		struct {
			u64 arg0, arg1, arg2, arg3, arg4, arg5;
			u64 arg6, arg7, arg8, arg9, arg10, arg11;
		};
		u64 args[12];
	};
} __aligned(8);

typedef struct kpm_hook_fargs12 kpm_hook_fargs9;
typedef struct kpm_hook_fargs12 kpm_hook_fargs10;
typedef struct kpm_hook_fargs12 kpm_hook_fargs11;

struct kpm_hook_chain {
	struct kpm_hook_t hook;
	s32 chain_items_max;
	s8 states[KPM_HOOK_CHAIN_NUM];
	void *udata[KPM_HOOK_CHAIN_NUM];
	void *befores[KPM_HOOK_CHAIN_NUM];
	void *afters[KPM_HOOK_CHAIN_NUM];
	u32 transit[KPM_HOOK_TRANSIT_WORDS];
} __aligned(8);

struct kpm_fp_hook_t {
	unsigned long fp_addr;
	u64 replace_addr;
	u64 origin_fp;
} __aligned(8);

struct kpm_fp_hook_chain {
	struct kpm_fp_hook_t hook;
	s32 chain_items_max;
	s8 states[KPM_FP_HOOK_CHAIN_NUM];
	void *udata[KPM_FP_HOOK_CHAIN_NUM];
	void *befores[KPM_FP_HOOK_CHAIN_NUM];
	void *afters[KPM_FP_HOOK_CHAIN_NUM];
	u32 transit[KPM_HOOK_TRANSIT_WORDS];
} __aligned(8);

void kpm_hook_transit0(void);
void kpm_hook_transit4(void);
void kpm_hook_transit8(void);
void kpm_hook_transit12(void);
u64 kpm_hook_dispatch_inline(void *record, const u64 *register_args,
			     const u64 *stack_args,
			     unsigned int arg_group);
int hook_prepare(struct kpm_hook_t *hook);
void hook_install(struct kpm_hook_t *hook);
void hook_uninstall(struct kpm_hook_t *hook);
int hook(void *func, void *replace, void **backup);
void unhook(void *func);
int hook_chain_add(struct kpm_hook_chain *chain, void *before, void *after,
		   void *udata);
void hook_chain_remove(struct kpm_hook_chain *chain, void *before,
		       void *after);
int hook_wrap(void *func, int argno, void *before, void *after, void *udata);
void hook_unwrap_remove(void *func, void *before, void *after, int remove);
void fp_hook(void *fp_addr, void *replace, void **backup);
void fp_unhook(void *fp_addr, void *backup);
int fp_hook_wrap(void *fp_addr, int argno, void *before, void *after,
		 void *udata);
void fp_hook_unwrap(void *fp_addr, void *before, void *after);
s32 branch_relative(u32 *buffer, u64 from, u64 to);
s32 branch_absolute(u32 *buffer, u64 to);
s32 ret_absolute(u32 *buffer, u64 to);
s32 branch_from_to(u32 *buffer, u64 from, u64 to);
unsigned long branch_func_addr(unsigned long address);
#endif
