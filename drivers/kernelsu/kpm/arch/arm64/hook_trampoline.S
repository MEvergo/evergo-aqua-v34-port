/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/linkage.h>

	.text
	.align 2


	.global kpm_hook_transit0
	.type kpm_hook_transit0, %function
kpm_hook_transit0:
	.inst 0xd503249f
	sub	sp, sp, #128
	stp	x29, x30, [sp, #112]
	stp	xzr, xzr, [sp, #0]
	stp	xzr, xzr, [sp, #16]
	stp	xzr, xzr, [sp, #32]
	stp	xzr, xzr, [sp, #48]
	stp	xzr, xzr, [sp, #64]
	stp	xzr, xzr, [sp, #80]
	mov	x0, x16
	mov	x1, sp
	mov	x2, xzr
	mov	x3, #0
	bl	kpm_hook_dispatch_inline
	ldp	x29, x30, [sp, #112]
	add	sp, sp, #128
	ret
	.size kpm_hook_transit0, .-kpm_hook_transit0

	.global kpm_hook_transit4
	.type kpm_hook_transit4, %function
kpm_hook_transit4:
	.inst 0xd503249f
	sub	sp, sp, #128
	stp	x29, x30, [sp, #112]
	stp	x0, x1, [sp, #0]
	stp	x2, x3, [sp, #16]
	mov	x0, x16
	mov	x1, sp
	mov	x2, xzr
	mov	x3, #4
	bl	kpm_hook_dispatch_inline
	ldp	x29, x30, [sp, #112]
	add	sp, sp, #128
	ret
	.size kpm_hook_transit4, .-kpm_hook_transit4

	.global kpm_hook_transit8
	.type kpm_hook_transit8, %function
kpm_hook_transit8:
	.inst 0xd503249f
	sub	sp, sp, #128
	stp	x29, x30, [sp, #112]
	stp	x0, x1, [sp, #0]
	stp	x2, x3, [sp, #16]
	stp	x4, x5, [sp, #32]
	stp	x6, x7, [sp, #48]
	mov	x0, x16
	mov	x1, sp
	mov	x2, xzr
	mov	x3, #8
	bl	kpm_hook_dispatch_inline
	ldp	x29, x30, [sp, #112]
	add	sp, sp, #128
	ret
	.size kpm_hook_transit8, .-kpm_hook_transit8

	.global kpm_hook_transit12
	.type kpm_hook_transit12, %function
kpm_hook_transit12:
	.inst 0xd503249f
	sub	sp, sp, #128
	stp	x29, x30, [sp, #112]
	stp	x0, x1, [sp, #0]
	stp	x2, x3, [sp, #16]
	stp	x4, x5, [sp, #32]
	stp	x6, x7, [sp, #48]
	mov	x0, x16
	mov	x1, sp
	add	x2, sp, #128
	mov	x3, #12
	bl	kpm_hook_dispatch_inline
	ldp	x29, x30, [sp, #112]
	add	sp, sp, #128
	ret
	.size kpm_hook_transit12, .-kpm_hook_transit12
