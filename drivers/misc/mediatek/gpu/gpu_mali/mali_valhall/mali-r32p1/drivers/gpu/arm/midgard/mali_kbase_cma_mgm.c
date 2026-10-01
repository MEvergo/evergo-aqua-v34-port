// SPDX-License-Identifier: GPL-2.0
/* Dedicated, non-default CMA fallback for MT6833 Mali page pools. */
#include <linux/cma.h>
#include <linux/dma-contiguous.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/memory_group_manager.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include <mali_kbase.h>
#include "mali_kbase_cma_mgm.h"

struct mali_cma_mgm {
	struct memory_group_manager_device mgm;
	struct cma *area;
	unsigned long first_pfn;
	unsigned long end_pfn;
	spinlock_t release_lock;
	struct list_head release_list;
	struct work_struct release_work;
};

static bool mali_cma_contains(const struct mali_cma_mgm *manager,
			      const struct page *page)
{
	unsigned long pfn = page_to_pfn(page);

	return pfn >= manager->first_pfn && pfn < manager->end_pfn;
}

static struct page *mali_cma_alloc_page(struct memory_group_manager_device *mgm,
			int group_id, gfp_t gfp_mask, unsigned int order)
{
	struct mali_cma_mgm *manager = mgm->data;
	struct page *page;
	unsigned int i;

	/* Kbase currently calls only from sleepable contexts with non-movable GFP. */
	if (WARN_ON_ONCE(group_id < 0 ||
			 group_id >= MEMORY_GROUP_MANAGER_NR_GROUPS ||
			 order >= MAX_ORDER ||
			 (gfp_mask & (__GFP_MOVABLE | __GFP_NOFAIL)) ||
			 !gfpflags_allow_blocking(gfp_mask) || in_atomic() ||
			 irqs_disabled()))
		return NULL;

	/* Small orders need reclaim without reaching __alloc_pages_may_oom(). */
	if (order <= PAGE_ALLOC_COSTLY_ORDER)
		gfp_mask |= __GFP_RETRY_MAYFAIL;
	page = alloc_pages(gfp_mask, order);
	if (page && unlikely(mali_cma_contains(manager, page))) {
		/* Preserve unambiguous range-based provenance at free time. */
		WARN_ON_ONCE(1);
		__free_pages(page, order);
		page = NULL;
	}

	if (!page) {
		/* Reclaim pool pages freed from atomic contexts before testing CMA. */
		flush_work(&manager->release_work);
		page = cma_alloc(manager->area, 1UL << order, order,
				 gfp_mask | __GFP_RETRY_MAYFAIL | __GFP_NOWARN);
		if (!page)
			return NULL;
		if (WARN_ON_ONCE(!IS_ALIGNED(page_to_pfn(page), 1UL << order) ||
			page_to_pfn(page) < manager->first_pfn ||
			page_to_pfn(page) + (1UL << order) > manager->end_pfn)) {
			cma_release(manager->area, page, 1UL << order);
			return NULL;
		}
		/* Unlike alloc_pages(__GFP_ZERO), cma_alloc does not clear pages. */
		if (gfp_mask & __GFP_ZERO)
			for (i = 0; i < (1UL << order); i++)
				clear_highpage(page + i);
	}

	if (IS_ENABLED(CONFIG_MTK_IOMMU_V2))
		for (i = 0; i < (1UL << order); i++)
			SetPageIommu(page + i);

	return page;
}

static void mali_cma_release_work(struct work_struct *work)
{
	struct mali_cma_mgm *manager =
		container_of(work, struct mali_cma_mgm, release_work);
	struct page *page;
	unsigned long flags;
	unsigned int order;

	for (;;) {
		spin_lock_irqsave(&manager->release_lock, flags);
		if (list_empty(&manager->release_list)) {
			spin_unlock_irqrestore(&manager->release_lock, flags);
			break;
		}
		page = list_first_entry(&manager->release_list, struct page, lru);
		list_del_init(&page->lru);
		spin_unlock_irqrestore(&manager->release_lock, flags);

		order = page_private(page);
		WARN_ON_ONCE(!cma_release(manager->area, page, 1UL << order));
	}
}

static void mali_cma_free_page(struct memory_group_manager_device *mgm,
			int group_id, struct page *page, unsigned int order)
{
	struct mali_cma_mgm *manager = mgm->data;

	if (WARN_ON_ONCE(!page || group_id < 0 ||
			 group_id >= MEMORY_GROUP_MANAGER_NR_GROUPS ||
			 order >= MAX_ORDER))
		return;

	if (!mali_cma_contains(manager, page)) {
		__free_pages(page, order);
		return;
	}

	if (WARN_ON_ONCE(!IS_ALIGNED(page_to_pfn(page), 1UL << order) ||
		page_to_pfn(page) + (1UL << order) > manager->end_pfn))
		return;
	/* Kbase can drop a pool page while holding its spinlock. */
	if (in_atomic() || irqs_disabled()) {
		unsigned long flags;

		set_page_private(page, order);
		spin_lock_irqsave(&manager->release_lock, flags);
		list_add_tail(&page->lru, &manager->release_list);
		spin_unlock_irqrestore(&manager->release_lock, flags);
		schedule_work(&manager->release_work);
	} else {
		/* free_contig_range() clears PageIommu via free_pages_prepare(). */
		WARN_ON_ONCE(!cma_release(manager->area, page, 1UL << order));
	}
}

static vm_fault_t mali_cma_vmf_insert(struct memory_group_manager_device *mgm,
		int group_id, struct vm_area_struct *vma, unsigned long addr,
		unsigned long pfn, pgprot_t pgprot)
{
	return vmf_insert_pfn_prot(vma, addr, pfn, pgprot);
}

static u64 mali_cma_update_gpu_pte(struct memory_group_manager_device *mgm,
		int group_id, int mmu_level, u64 pte)
{
	return pte;
}

static struct platform_driver mali_cma_mgm_driver;

bool mali_cma_mgm_matches(struct device *dev,
			  struct memory_group_manager_device *mgm)
{
	struct mali_cma_mgm *manager;

	if (!mgm || dev->driver != &mali_cma_mgm_driver.driver)
		return false;
	manager = mgm->data;
	return manager && manager->area && dev->cma_area == manager->area &&
		mgm->ops.mgm_alloc_page == mali_cma_alloc_page;
}

static int mali_cma_mgm_probe(struct platform_device *pdev)
{
	struct device_node *region;
	struct reserved_mem *rmem;
	struct mali_cma_mgm *manager;
	struct cma *area;
	int err;

	region = of_parse_phandle(pdev->dev.of_node, "memory-region", 0);
	if (!region)
		return -ENODEV;

	if (!of_device_is_compatible(region, "mediatek,mali-cma") ||
	    !of_device_is_compatible(region, "shared-dma-pool") ||
	    !of_property_read_bool(region, "reusable") ||
	    of_property_read_bool(region, "no-map") ||
	    of_property_read_bool(region, "linux,cma-default")) {
		err = -EINVAL;
		goto put_region;
	}

	rmem = of_reserved_mem_lookup(region);
	if (!rmem || !rmem->priv || !rmem->base || !rmem->size) {
		err = -ENODEV;
		goto put_region;
	}
	area = rmem->priv;
	if (area == dma_contiguous_default_area ||
	    cma_get_base(area) != rmem->base ||
	    cma_get_size(area) != rmem->size) {
		err = -EINVAL;
		goto put_region;
	}

	manager = devm_kzalloc(&pdev->dev, sizeof(*manager), GFP_KERNEL);
	if (!manager) {
		err = -ENOMEM;
		goto put_region;
	}

	err = of_reserved_mem_device_init(&pdev->dev);
	if (err)
		goto put_region;
	if (pdev->dev.cma_area != area) {
		err = -EINVAL;
		goto release_region;
	}

	spin_lock_init(&manager->release_lock);
	INIT_LIST_HEAD(&manager->release_list);
	INIT_WORK(&manager->release_work, mali_cma_release_work);
	manager->area = area;
	manager->first_pfn = PHYS_PFN(rmem->base);
	manager->end_pfn = PHYS_PFN(rmem->base + rmem->size);
	manager->mgm.ops.mgm_alloc_page = mali_cma_alloc_page;
	manager->mgm.ops.mgm_free_page = mali_cma_free_page;
	manager->mgm.ops.mgm_vmf_insert_pfn_prot = mali_cma_vmf_insert;
	manager->mgm.ops.mgm_update_gpu_pte = mali_cma_update_gpu_pte;
	manager->mgm.owner = THIS_MODULE;
	manager->mgm.data = manager;
	platform_set_drvdata(pdev, &manager->mgm);
	dev_info(&pdev->dev, "dedicated Mali CMA %s at %pa, %llu MiB\n",
		 cma_get_name(area), &rmem->base,
		 (unsigned long long)(rmem->size >> 20));
	of_node_put(region);
	return 0;

release_region:
	of_reserved_mem_device_release(&pdev->dev);
put_region:
	of_node_put(region);
	dev_err(&pdev->dev, "dedicated Mali CMA binding failed: %d\n", err);
	return err;
}

static int mali_cma_mgm_remove(struct platform_device *pdev)
{
	struct mali_cma_mgm *manager =
		container_of(platform_get_drvdata(pdev), struct mali_cma_mgm, mgm);

	flush_work(&manager->release_work);
	WARN_ON_ONCE(!list_empty(&manager->release_list));
	platform_set_drvdata(pdev, NULL);
	of_reserved_mem_device_release(&pdev->dev);
	return 0;
}

static const struct of_device_id mali_cma_mgm_match[] = {
	{ .compatible = "mediatek,mali-cma-mgm" },
	{ }
};
MODULE_DEVICE_TABLE(of, mali_cma_mgm_match);

static struct platform_driver mali_cma_mgm_driver = {
	.probe = mali_cma_mgm_probe,
	.remove = mali_cma_mgm_remove,
	.driver = {
		.name = "mali-cma-mgm",
		.of_match_table = mali_cma_mgm_match,
		.suppress_bind_attrs = true,
	},
};

static int __init mali_cma_mgm_init(void)
{
	return platform_driver_register(&mali_cma_mgm_driver);
}
subsys_initcall(mali_cma_mgm_init);

static void __exit mali_cma_mgm_exit(void)
{
	platform_driver_unregister(&mali_cma_mgm_driver);
}
module_exit(mali_cma_mgm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MT6833 Mali dedicated CMA fallback memory group manager");
