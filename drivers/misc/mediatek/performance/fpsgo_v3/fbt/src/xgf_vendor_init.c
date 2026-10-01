// SPDX-License-Identifier: GPL-2.0
/* Register the private XGF3 core only after FPSGO has initialized XGF/FSTB. */
#include <linux/init.h>
#include <linux/kernel.h>

#include "xgf.h"

extern int xgf_ko_init(void);
extern long long xgf_ema2_predict(struct xgf_ema2_predictor *pt, long long x);
extern void xgf_ema2_init(struct xgf_ema2_predictor *pt);

static int __init xgf_vendor_init(void)
{
	int ret;

	if (!xgf_ko_enabled) {
		pr_err("XGF3 support tracepoints did not initialize\n");
		return -ENODEV;
	}

	pr_info("XGF3 private init begin\n");
	ret = xgf_ko_init();
	pr_info("XGF3 xgf_ko_init ret=%d\n", ret);

	if (ret) {
		pr_err("XGF3 core initialization failed: %d\n", ret);
		return ret;
	}

	xgf_est_runtime_fp = xgf_est_runtime;
	fpsgo_xgf2ko_calculate_target_fps_fp = fpsgo_xgf2ko_calculate_target_fps;
	fpsgo_xgf2ko_do_recycle_fp = fpsgo_xgf2ko_do_recycle;
	xgff_est_runtime_fp = xgff_est_runtime;
	xgff_update_start_prev_index_fp = xgff_update_start_prev_index;
	xgf_ema2_predict_fp = xgf_ema2_predict;
	xgf_ema2_init_fp = xgf_ema2_init;
	pr_info("XGF3 binding complete\n");
	pr_info("XGF3 notify begin\n");
	notify_xgf_ko_ready();
	pr_info("XGF3 notify complete\n");

	return 0;
}
late_initcall(xgf_vendor_init);
