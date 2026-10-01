/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MALI_KBASE_CMA_MGM_H
#define MALI_KBASE_CMA_MGM_H

struct device;
struct memory_group_manager_device;

bool mali_cma_mgm_matches(struct device *dev,
			  struct memory_group_manager_device *mgm);

#endif /* MALI_KBASE_CMA_MGM_H */
