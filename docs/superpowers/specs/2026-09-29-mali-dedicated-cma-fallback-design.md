# Mali 物理内存 / 虚拟内存协同与专用 CMA Fallback 设计

- **日期：** 2026-09-30
- **适用目标：** MT6833P / Aqua 4.14.x / Mali Valhall r32p1
- **状态：** 候选设计规范，供后续实现与设备验证；不表示源码修改、内核构建或刷机已获批准或完成。

本设计让 Kbase 优先使用普通 RAM，保留内核 reclaim 及 swap/zram 对可交换工作集的间接腾挪能力；普通 GPU 物理页分配失败后，才尝试独立于 SSMR/ZMC 的 Mali CMA。两路都失败时，该 Mali 请求返回 `-ENOMEM`，而不由其主动发起全局 OOM。GPU backing 本身不交换。专用池容量和运行时效果必须在实际设备上验证，本文不预设数值。

## 1. 问题背景与证据边界

在 `tmp/KernelSU_bugreport_2026-09-29_03_39/pstore.tar.gz` 的 `console-ramoops` 中，`Renderer invoked oom-killer` 的调用栈经过 `kbase_api_mem_alloc → kbase_mem_alloc → kbase_mem_pool_alloc_pages → kbase_native_mgm_alloc → __alloc_pages_nodemask`，对应普通 `BASE_MEM_ALLOC`；另有 `mali-cmar-backe invoked oom-killer` 的栈经过 `kbase_jit_allocate`。两者的页请求均为 `GFP_HIGHUSER|__GFP_ZERO`、order-0。这些是 Mali 请求进入内核 OOM 路径的直接证据，但 OOM 请求者不等于最终被杀的进程，也不能将日志中的其它非 Mali OOM 都归因于 GPU。

普通分配事件的 `Mem-Info` 报告 Normal free 3504 KiB、min 4276 KiB；Movable free 47108 KiB，其中 `free_cma` 44248 KiB。同一事件还报告 4194300 KiB total swap、2985980 KiB free swap。它们说明当时仍有其它区域和交换空间，不证明该次 GPU 分配已通过 swap 成功回收内存，也不证明这部分 `free_cma` 都可直接供 Mali 使用。主 `dmesg.txt` 中没有同等完整的目标调用栈，排查该事件应以 pstore 为准。

目标源码 `drivers/misc/mediatek/gpu/gpu_mali/mali_valhall/mali-r32p1/drivers/gpu/arm/midgard/mali_kbase_mem_pool.c` 以 `GFP_HIGHUSER | __GFP_ZERO` 向 MGM 请求物理页，随后调用 `dma_map_page()`；native MGM 则调用 `alloc_pages()`。该目标配置的普通请求不带 `__GFP_MOVABLE`，不会自动从 `MIGRATE_CMA` 获取页。已映射的 GPU backing 也没有与通用 movable 页匹配的安全迁移协议。由此推断，Normal 压力与可用 Movable/CMA 空间并存，是本次 Mali 分配进入 OOM 的重要机制；仍需通过实施后的定向压力测试确认修复效果。

## 2. 设计目标

目标是让可交换的 CPU 工作集在内核策略允许时通过 reclaim 和 swap/zram 释放真实物理页，供不可交换的 GPU backing 使用；普通页最终不可得时再使用 Mali 专用 CMA：

```text
Kbase 已缓存页
    ↓
普通物理页分配（内核允许的 reclaim；必要时交换其它工作集）
    ↓ 仍失败
Mali 专用 CMA fallback
    ↓ 仍失败
Kbase 回滚，调用方得到 -ENOMEM
```

这不是显式按顺序执行“先 swap 完再分配 CMA”的协议：reclaim 是否扫描匿名页、是否发生 swap-out、何时回收或终止均由目标内核和当时压力决定。图中的“普通分配仍失败”特指经过**允许 reclaim、但耗尽时以非 OOM 方式返回失败**的 GFP/order 策略；并非将 CMA 简单接在原生分配器返回 `NULL` 后。设计不保证有空闲 swap 时 GPU 分配必定成功，也不改变非 Mali 请求、Android LMKD 或整个系统的 OOM 策略。

方案须覆盖所有经选定 Kbase MGM/page-pool 的请求，包括普通 backing、JIT、CSF firmware/IO 和内部页池，而不只处理触发上述日志的 order-0 路径。保持 Kbase 原有 DMA 映射、page pool、GPU VA、内存对象生命周期和失败回滚契约。

## 3. 设计原则

### 3.1 GPU backing 本身不做 swap

不将 Mali backing 页直接写入 zram、swapfile 或其它交换后端。当前目标驱动没有覆盖 GPU page fault、swap-out、swap-in 与重新映射的完整协议；使用期间这些页可能处于 CPU、DMA/IOMMU、GPU 映射状态。swap/zram 只通过交换其它可交换工作集间接腾出物理 RAM。

### 3.2 普通 RAM 优先，CMA 仅为 fallback

常态继续使用现有普通页路径；普通分配在合理 reclaim 后仍失败，才调用专用 CMA。新区域不是所有 GPU 页的默认 heap，更不是永久划走的一块静态显存。未被 Mali 持有的 CMA 页可按 CMA 规则供可迁移系统页面临时使用；这不意味着其它设备也可直接从 Mali 专用 area 申请连续内存，亦不保证有空闲位图时迁移一定成功。增加 CMA 仍会减少普通 unmovable 分配可依赖的物理空间：可迁移页能借住，不代表不可移动的内核分配能以它作为通用后备池；过大的 CMA/Movable 占比可能加剧 Normal zone 压力。

### 3.3 分配失败不主动升级为全局 OOM

普通分配须保留 reclaim 能力，但不得由该请求触发 OOM killer；高 order 还须限制重试和 compaction 延迟。普通路径和 CMA 都失败后返回 `-ENOMEM`，不能无限等待或借用 secure memory。其它并发请求仍可能独立引发 kernel OOM；LMKD 也可能按 PSI、swap、thrashing 或 ROM 策略杀进程，两者不属于本设计所能禁止的行为。

## 4. 总体架构与接入范围

```text
Kbase page pool → Mali 专用 MGM ┬→ alloc_pages()（普通 RAM、内核 reclaim）
                              └→ dma_alloc_from_contiguous()（仅普通路径失败时）
```

MGM 按现有接口向 Kbase 返回页块或 `NULL`。Kbase 仍负责 `dma_map_page()` / `dma_unmap_page()`，并在映射失败、部分分配失败时归还已取得的页。新 manager 不改变 DMA address、GPU VA 或 Kbase 内存对象模型。

目标 `mali_kbase_mem.c` 在找不到 `physical-memory-group-manager` phandle 时默认使用 native MGM；即使 phandle 指向的 platform device 没找到，也可能仅报错并沿用 native，只有已找到设备而 manager drvdata 未就绪时才走 `-EPROBE_DEFER`。接入后必须防止缺失或查找失败造成静默回退，并在运行设备上确认新 MGM 确实被选中。

**阻塞与锁上下文约束：** 在将同步 CMA isolation/migration/compaction 应用于全部 MGM/page-pool 请求前，逐一审计实际可达调用者（含 backing、JIT、firmware/IO、内部池）：是否可 sleep、是否在 atomic/IRQ 上下文、当时持有的 Kbase/GPU 锁，以及 deeper reclaim/CMA migration 是否可能造成锁反转或 reclaim recursion。不可 sleep 或存在不可接受锁依赖的路径不得盲目进入同步 CMA fallback；由实现方案保证调用上下文和错误契约均安全，不在本文预设规避方式。

## 5. 普通物理内存与虚拟内存协同

普通页分配让目标内核按 GFP 和 order 的既有规则执行 direct reclaim、compaction 和可能的 swap；不在 MGM 内单独实现 GPU 页交换，也不以修改全局 swappiness 或 LMKD 为前提。预期的**可验证机会**是可回收 cache 释放、可交换匿名页进入 swap/zram，随后普通分配取得物理页；实际是否发生必须记录而非假设。

目标 `GFP_HIGHUSER` 带 `__GFP_RECLAIM`，但原生 order-0 慢路径在回收失败后仍可能走 `out_of_memory()`；仅增加 CMA fallback 并不能避免其先触发 OOM。order-0 保留调用方 GFP 所允许的 direct/kswapd reclaim、再增加 `__GFP_RETRY_MAYFAIL`，是依据当前 `mm/page_alloc.c:__alloc_pages_may_oom()` 跳过该请求 OOM killer 的候选策略，而非已验证的设备行为；实施时须分别对各 order 核实有限重试、可控失败与实际分配延迟。LMKD 或其它内核分配者仍可独立终止进程，验收必须分别归类。

## 6. 专用 CMA 与设备树

新增独立于默认 CMA 和 ZMC/SSMR 的 `shared-dma-pool` reserved-memory area：带 `reusable`，不带 `no-map` 或 `linux,cma-default`。MGM platform device 通过 `memory-region` 绑定该 area；Mali 节点的 `physical-memory-group-manager` 指向 MGM。先完成 reserved-memory/device 关联，再让 Kbase 使用 manager；关联失败、area 未就绪或绑定错误时明确失败或延迟探测，不允许以 native MGM 伪装启用。

**不变量：** 启用 CMA fallback 前，必须正向核实 MGM device 绑定的是预期 Mali 专用 area（身份及物理范围），未绑定或绑定错误时禁止调用可能退入默认 CMA 的分配接口。目标 `include/linux/dma-contiguous.h:dev_get_cma_area()` 在 `dev->cma_area` 缺失时返回 `dma_contiguous_default_area`；因此 `dma_alloc_from_contiguous()` 成功本身不能证明拿到的是 Mali 专用页。验收须检查实际分配来源，并覆盖缺失/错误绑定时的失败行为。

`everpal_defconfig` 指定 `CONFIG_MTK_PLATFORM="mt6853"`、`CONFIG_ARCH_MTK_PROJECT="k6833v1_64"` 和 appended base DTB `mediatek/mt6833`。源码中的 `mt6833.dts` 候选 `zmc-default` size 为 `0x35000000`，还存在 `evergo.dts`、`k6833v1_64.dts` 等候选 overlay；**这些不证明实际设备加载的 DTB/DTBO 组合或有效区域大小**。实施前核实镜像与运行 FDT 的有效树、物理范围、DMA/IOMMU 可寻址范围、reserved-memory 之间的重叠情况及 area 数量上限。Mali 新 area 不借用、缩小或重划既有 ZMC/SSMR。

该树 `drivers/base/dma-contiguous.c` 的 `rmem_cma_setup()` 要求 area 的 base **和** size 都按 `PAGE_SIZE << max(MAX_ORDER - 1, pageblock_order)` 对齐。4 KiB 页、`MAX_ORDER=11` 且 `pageblock_order<=10` 时是 4 MiB；有效配置不同则按公式重新计算。这一 reserved-area 约束与返回 order-9 页块的 PFN 对齐是两项不同要求。池的 base/size 不在本设计中预设；容量选择见第 13 节。

目标 `mali-r32p1/drivers/base/arm/memory_group_manager/Kbuild` 在 `CONFIG_MALI_MEMORY_GROUP_MANAGER=y` 时仍构建独立 `.ko`，而当前内核的 `drivers/base/dma-contiguous.c` 未导出 `dma_alloc_from_contiguous()` / `dma_release_from_contiguous()`。MGM **必须合法取得所需 CMA API**；若沿用独立模块及这些接口，`EXPORT_SYMBOL_GPL` 是已知候选改法。实现 Agent 可依据目标树选择最小的符号导出、链接方式或等效接入，但必须通过最终 link/modpost 验证，不能假设 `.ko` 已能调用未导出的符号。

## 7. 大页与不同 order

目标 Kbase 同时使用 order-0（4 KiB）与 order-9（512 页、2 MiB）页池；不能只实现小页 fallback。**order-9 返回给 Kbase 的页块必须满足 2 MiB 对齐。** 目标 `dma_alloc_from_contiguous()` 会把 `align` 截断到 `CONFIG_CMA_ALIGNMENT`，Kconfig 默认值为 8，不保证直接返回 order-9 所需对齐。将最终 `CONFIG_CMA_ALIGNMENT` 提高到至少 9 是当前 API 下的已知候选方案；若采用其它分配/对齐策略（包括保留较低对齐配置），必须说明并验证它如何在碎片化和长期负载下保证 2 MiB 对齐，而不能依赖偶然对齐。对任何方案均须核验返回 PFN 的 `1 << order` 对齐，并评估对其它 CMA 使用者的影响。

order-0 普通路径以保留 `GFP_HIGHUSER | __GFP_ZERO` 等调用方标志并增加可控重试标志为基线。目标 `mm/page_alloc.c` 对大于 `PAGE_ALLOC_COSTLY_ORDER` 的请求本来就不靠 OOM killer 求得成功，但 `__GFP_RETRY_MAYFAIL` 会改变高 order 的重试/compaction 决策。实现时依目标 allocator 代码、真实 order 使用情况和延迟测量，分别确定普通路径的 retry 策略；既不能让 Mali 请求主动发起全局 OOM，也不能为“尽量成功”引入无界或过长 stall。高 order 普通路径失败后仍尝试专用 CMA，order-9 验收不得省略。

## 8. CMA 页生命周期与初始化

CMA 页在交给 Kbase 前必须获得与 native MGM 等价的内容初始化及平台逐页状态；释放时也须镜像 native 的 per-page 状态转换，避免遗留 vendor page flag。当前 `mm/cma.c:cma_alloc()` 不保证调用方要求的 `__GFP_ZERO`，目标 native MGM 在 `CONFIG_MTK_IOMMU_V2` 下逐页设置 `PageIommu`；实现 Agent 必须核查清零（例如逐页 `clear_highpage()`）、设置状态以及普通页/CMA 页各自释放时的对称清理。目标 native free 使用 `__free_pages()`，CMA release 经 `free_contig_range()`；应核实既有页分配器的标志清理是否足够，必要时补全，而不是预先假定必须显式 `ClearPageIommu` 或释放侧天然安全。

页交给 Kbase 后，沿用现有 `dma_map_page()`；真正归还时，仍由 Kbase 先 `dma_unmap_page()` 再调 MGM free。普通页归还 buddy，专用 CMA 页回到原 area；两路都须保持上述页状态清理与来源对称。DMA 映射失败、部分分配回滚、GPU reset 和 probe/remove 都须覆盖；manager 不得在 GPU 持有映射时擅自迁移或释放页。MGM device 的 CMA association 要覆盖 Kbase 的完整使用期，移除时先停止 Kbase 分配并清空 pool，再拆除 association。

## 9. 页来源识别

释放时必须可靠区分普通 allocator 与专用 CMA。当前 `cma_release()` 判断的是 CMA 物理范围，并不能单独证明同范围的页块由本 MGM 占用。若用专用 area 的物理范围判定来源，必须维持可核验不变量：MGM 的普通分配仍采用非 movable GFP，不能意外从该专用 CMA area 得到页。专用 area 允许其它可迁移页暂住，不意味着它们能被 MGM 当成自身分配页释放；这些页必须经 CMA 正常迁移后才能交给 MGM。

若目标 allocator、GFP 策略或后续修改无法保证来源无歧义，则记录显式 allocation provenance，再执行对应释放；不能仅因 `cma_release()` 做了范围检查就将普通页交给它。

## 10. Kbase page pool 与实际池占用

Kbase 可缓存已经退出活跃 GPU 对象的页。GPU process 用量下降不等于页已回到 buddy/CMA；只有 pool 归还到底层 MGM 时，专用 CMA 的占用才下降。压力测试须同时标记活跃 GPU 用量、Kbase pool 回收和 CMA area 占用，容量选择须计入缓存滞留与高 order 连续块需求。

小页与大页必须联合观察：长期 order-0 fallback 可能被 Kbase pool 缓存，造成 CMA 位图出现分散占用；即使总 free pages 仍多，order-9 也可能缺少可用的 2 MiB 块。是否通过容量 headroom、pool 行为或其它策略应由实际测试决定，本文不预定实现。

## 11. 失败语义

普通 MGM/page allocator 路径须先按本设计中允许 reclaim、但在耗尽时**不调用 OOM killer 而返回 `NULL`** 的 GFP/order 策略失败，之后才尝试专用 CMA；原生 order-0 `GFP_HIGHUSER` 可能在返回前进入 OOM，不能只在其 `NULL` 后接 fallback。若 CMA 也失败，MGM 返回 `NULL`，Kbase 依现有路径回滚部分分配并向适用调用方传播 `-ENOMEM`。对 CSF firmware/IO 等内部调用者，须单独确认其错误传播、恢复和清理行为，不应假设所有调用者都有用户态 ioctl。

CMA 容量耗尽、碎片化、迁移受阻或对齐无法满足都允许导致这一局部失败。失败语义不承诺游戏继续运行，也不禁止由其它分配者独立触发 global OOM 或由 LMKD 终止进程；只要求**该 Mali 分配路径**不通过普通重试或 CMA fallback 主动发起全局 OOM。

该约束也涵盖 CMA 回退的页迁移：目标树的普通迁移目的页通过 `new_page_nodemask()` 使用 `__GFP_RETRY_MAYFAIL`，但实现 Agent 仍须核对大页及其它迁移分支，并在双来源耗尽测试中观察实际 OOM 栈；不能仅凭普通 `alloc_pages()` 避开 OOM 就推断整条 fallback 路径安全。

## 12. SSMR / ZMC 隔离

SSMR、SVP、secure-video、WFD 及其它平台连续内存区域保持原配置和生命周期。Mali 不从其 area 取页，不改变其 DTS 属性、大小或初始化顺序；新 reserved-memory 的 base/size 与之不重叠。目标 `memory_ssmr.c` 将 ZMC CMA 用于这些功能，不能因候选 DTS 的 `zmc-default` 看似富余就借用它。实施后还须进行功能和连续分配回归测试，排除 CMA 布局或全局对齐配置的间接影响。

## 13. 容量选择

本文不指定 Mali CMA 大小。先在真实设备上运行代表性游戏、长时间图形压力以及高 RAM/swap 压力组合，再结合该 **Mali 专用 CMA area** 的峰值占用、Kbase pool 缓存、高 order 连续块需求和审定的 headroom 选取容量；`used` 峰值只是下限参考，不是单独的容量决策依据。新增 CMA 会侵蚀 Normal/unmovable 可用 headroom；必须同时比较增加前后的 Normal 水位和非 GPU 不可移动分配结果，并进行“GPU 高负载 + 非 GPU kernel/unmovable 压力”的组合测试。容量配置应满足第 6 节 area 对齐、第 7 节 order-9 要求，且不能压缩现有安全多媒体区域；未经这些实测不得声称池已满足真实负载。

容量评估还须结合第 15 节 order-0 retention 后持续 order-9 的混合压力结果，不能只把独立 order 测试通过或 `used` 峰值可容纳当作连续大页能力的证明。

测试内核开启 `CONFIG_CMA_DEBUGFS` 后，对应该 area 的 `used` 是 CMA 位图中被分配的**页数**（包括仍在 Kbase pool 缓存的块），是池持有量的主指标；同时记录 `base_pfn`、`count`、`maxchunk`。`maxchunk` 是位图中的最大未占用连续页数，不保证这些页都能被迁移并成功分配。可采集 `kprcs/<TGID>/total_gpu_mem`、`dma_buf_gpu_mem` 和 `gpu_mem_total` tracepoint 建立工作负载时间线；这些计数混合 native 与 dma-buf imports，且涉及 MMU 页表页，不能反推出专用 CMA 占用。常驻遥测不是本设计的前提。

## 14. 运行时观测与归因

至少按统一时间线记录：

| 信号 | 核查重点 |
| --- | --- |
| 物理内存 | 新增 CMA 前后 Normal/unmovable headroom、Normal/Movable 水位、buddy 碎片、direct reclaim、非 GPU kernel 分配失败与 stall |
| swap/zram | 实际后端和容量、swap-in/out、zram 占用及压缩数据量；区分“存在 swap”与“该次请求确实回收” |
| Mali/CMA | 专用 area `used`、峰值、`maxchunk`、order-0/order-9 fallback 成败及 pool shrink 后恢复 |
| 终止/错误 | pstore/kernel OOM 栈、Android LMKD 事件与 Mali allocation failure，分别归因 |

记录普通重试和 CMA compaction 的延迟，不能仅因分配最终成功就认为游戏性能符合要求。保留一次性定向故障注入与压力测试的可重复方法；不要把当前已有的总 GPU 计数误当作每次 ioctl 的 commit pages 或专用池分配量。

LMKD 不属于本次内核 MGM 修改范围，但属于系统级目标的验收门槛。若实机上 LMKD 在预期 reclaim/swap/CMA 资源阶梯发挥作用之前持续终止目标 workload，即使 MGM 的分配、回退与错误传播均通过功能测试，仍不能宣称整体目标完成；应将 VM/LMKD 策略作为独立后续问题分析，不能把提前杀进程算作成功。

## 15. 验收场景

1. **正常负载：** 普通页仍是主要来源；专用 CMA 不被无故大量占用；GPU 功能和分配延迟无明显退化。
2. **普通 RAM 与非 GPU 压力：** 实测 reclaim 与可交换工作集的行为，确认 swap/zram 在配置允许且确实发生时可间接腾出 RAM；组合“GPU 高负载 + 非 GPU kernel/unmovable 压力”，对比新增 CMA 前后的 Normal 水位、失败与延迟，确认没有为 GPU 池把其它不可移动分配逼入失败。记录是否仍有 Mali 请求主动触发 kernel OOM，不能只看系统 `MemFree`。
3. **CMA fallback：** 定向令 MGM 普通分配步骤失败，不干扰 CMA 迁移目标；正向确认分配来自预期 Mali 专用 area，而非默认 CMA，且 order-0 和 order-9 页块满足初始化、对齐及 DMA/IOMMU 契约。
4. **混合 order 碎片化：** 先制造长期 order-0 CMA fallback 和 Kbase pool retention，再持续触发 order-9；同时记录 dedicated area 剩余页数、`maxchunk`、order-9 成功率及 allocation latency，不能仅以总空闲量判断大页可用。按实测决定容量或缓存策略，不预设解决手段。
5. **双来源耗尽：** 普通路径和专用 CMA 均不可用时，检查适用用户请求得到 `-ENOMEM`、已分配页回滚、内部调用者错误传播及恢复；没有由该 Mali 请求主动发起的 global OOM、死锁或泄漏。
6. **回收：** 工作负载释放并触发 Kbase pool shrink 后，专用 area `used` 回到基线；多轮运行无持续增长，映射失败和部分分配回滚也归还到真实来源。核对普通页及 CMA 页在释放和再次分配后的 per-page 平台状态，不能遗留 stale vendor flag。
7. **平台兼容：** 运行设备有效 DTB/DTBO 确有独立 area、MGM phandle 与绑定；缺失或错误绑定不得静默落入 native MGM 或 default CMA；所选链接方式通过编译/link，若使用模块则通过 modpost。逐一审计实际可达 MGM 调用者的 sleep/atomic/IRQ 条件、锁依赖及 reclaim recursion，并验证不会在不安全上下文同步执行 CMA。SSMR/SVP/secure-video、IOMMU、suspend/resume、GPU reset、probe/remove 均通过回归检查。
8. **真实负载与 LMKD 门槛：** 在测定容量后，以真实游戏和长时间系统压力核查 CMA 峰值、swap/reclaim、分配延迟、Mali 错误、kernel OOM 和 LMKD。若 LMKD 持续在这些资源阶梯发挥作用前杀死目标 workload，分别报告 MGM 功能验证结果与尚未达成的系统级目标，不将早杀计为设计通过。

## 16. 不采用的方案

- **把所有 Mali 页改为 `__GFP_MOVABLE`：** 当前 DMA/GPU 映射生命周期没有安全的页迁移协议。
- **直接交换 GPU backing：** 当前驱动没有对应的 GPU fault、swap 和重映射机制；仅考虑间接交换其它工作集。
- **借用 SSMR/ZMC：** 安全多媒体功能和生命周期不同，不能挤占。
- **只调整 JIT 限额：** pstore 同时显示普通 `BASE_MEM_ALLOC` 和 JIT 路径。
- **所有 GPU 页永久从 CMA 分配：** 普通 RAM 仍应优先，CMA 仅为 fallback。
- **无限 reclaim/compaction 重试：** 长时间 allocation stall 本身可能损害游戏，耗尽时须可控失败。

## 17. 后续实现 Agent 的核查边界

实施前以运行时证据和目标 Aqua 4.14.x 源码重新核对：Kbase r32p1 MGM/page-pool 调用者、阻塞与锁上下文、native 初始化和错误回滚、当前 allocator 的 GFP/order/reclaim/OOM 行为、CMA API 与符号导出、实际 DTB/DTBO/FDT、reserved-memory/DMA/IOMMU 绑定、zram/swap 与 LMKD 配置，以及真实 order 分布。若目标事实与本文假设冲突，按**运行时证据 → 目标源码 → 有效平台配置 → 本文设计假设**处理，并记录取舍。

可针对不同 order 调整普通分配的具体 retry 策略，但不得改变核心约束：GPU backing 不 swap；普通 RAM 优先；reclaim/swap 可间接腾 RAM；隔离的 CMA 仅在普通来源失败后使用；不借用 SSMR/ZMC；该 Mali 请求不主动触发 global OOM；双来源耗尽允许 `-ENOMEM`；Kbase 的 DMA、page-pool、初始化与回滚语义得到保留。实施计划、源码修改、内核构建及设备写入均不属于本文已经完成的工作；设备刷写还需单独批准。

## 18. 完成定义

只有普通 RAM、内核 reclaim 与实际 swap/zram 机制按目标配置参与压力场景，Mali 能在普通页失败时使用独立 CMA（包括 order-9），CMA 耗尽时可控返回 `-ENOMEM`，该请求不主动发起 global OOM，且 SSMR/DMA/IOMMU/Kbase 生命周期及真实游戏长测均通过，才能认定实施验证完成。若 LMKD 持续在资源阶梯发挥作用前终止工作负载，则可单独判定 MGM 功能，却不能宣称系统级目标完成。当前文档仅定义这些验收条件，不代表已经实现或通过设备测试。
