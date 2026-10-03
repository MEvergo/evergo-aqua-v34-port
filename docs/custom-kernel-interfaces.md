# 自定义内核接口：MT overlay 与硬件断点

本文记录本仓库相对上游增加或改变的内核消费者接口。它面向调用方，集中说明可用边界、状态语义、错误码与生命周期；不是用户空间 ABI，也不属于 upstream 稳定用户 ABI。

MT overlay 与硬件断点接口均为内核接口，并通过 GPL-only 符号导出。用户空间不能通过新增 ioctl、perf 属性或 evdev 元数据使用这些能力。参考源码：[MT 公共声明](../include/linux/input/mt.h)、[MT slot 初始化](../drivers/input/input-mt.c)、[MT overlay 实现](../drivers/input/input-mt-overlay.c)、[input core](../drivers/input/input.c)、[evdev](../drivers/input/evdev.c)、[硬件断点公共声明](../include/linux/hw_breakpoint.h)、[硬件断点通用实现](../kernel/events/hw_breakpoint.c) 和 [ARM64 硬件断点实现](../arch/arm64/kernel/hw_breakpoint.c)。既有消费者文档见 [Input Subsystem](../Documentation/driver-api/input.rst)、[Kernel hardware-breakpoint stepping](../Documentation/driver-api/basics.rst)；MT type-B 协议背景见 [Multi-touch Protocol](../Documentation/input/multi-touch-protocol.rst)。

## A. 多点触控 overlay

Overlay 仅适用于已初始化 MT slots 的 input device。`input_mt_init_slots()` 为设备建立 overlay 状态；驱动仍用原有 input API 报告物理事件，overlay 消费者用下列接口发布合成触点。

### API 数据与接口

```c
struct input_mt_overlay_axis {
	unsigned int code;
	int value;
};

struct input_mt_overlay_contact {
	u64 id;
	unsigned int tool_type;
	const struct input_mt_overlay_axis *axes;
	unsigned int num_axes;
};

struct input_mt_overlay;

int input_mt_overlay_reserve_slot(struct input_dev *dev, unsigned int slot);
int input_mt_overlay_attach(struct input_dev *dev,
			    struct input_mt_overlay **session);
int input_mt_overlay_update(struct input_mt_overlay *session,
		const struct input_mt_overlay_contact *contacts,
		unsigned int num_contacts);
void input_mt_overlay_detach(struct input_mt_overlay *session);
void input_mt_overlay_reset(struct input_dev *dev);
void input_mt_overlay_suspend(struct input_dev *dev);
void input_mt_overlay_resume(struct input_dev *dev);
```

| 字段 | 调用方契约 |
|---|---|
| `input_mt_overlay_contact.id` | 调用方提供的稳定身份，不是输入 tracking ID。一次快照中身份必须唯一；身份在触点存续期间保持不变。 |
| `tool_type` | `MT_TOOL_*` 类型。设备未声明 `ABS_MT_TOOL_TYPE` 时只接受 `MT_TOOL_FINGER`。 |
| `axes`、`num_axes` | 指向本次要更新的已声明 `ABS_MT_*` 轴值。`ABS_MT_SLOT`、`ABS_MT_TRACKING_ID`、`ABS_MT_TOOL_TYPE` 由内核管理，不可作为普通轴提交。轴值必须属于设备已声明的 ABS_MT 能力；实现不替调用方夹取或验证这些轴值的数值范围。 |

每次 `input_mt_overlay_update()` 都是当前活动合成触点的**完整快照**：未列出的旧触点抬起；已有身份未列出的轴保留此前值；新身份未列出的轴从对应轴的配置最小值开始。已有身份不能在更新中改变 `tool_type`。内核分配输出 slot 和 tracking ID。

### R、L、S、M 与事件发布

Overlay 在 input core 中区分物理、legacy 注入与隔离 session 三类来源，另维护已发布的合并状态：

| 状态 | 含义 |
|---|---|
| **R** | 物理设备最近一个完整帧的影子状态。物理按键、ABS 值和 MT slots 的待处理变化先进入未提交帧；只有真实 `EV_SYN/SYN_REPORT` 才提交为 R。 |
| **S** | 调用方通过 session 提交的合成触点完整快照。它独立于驱动的 `dev->mt`、tracking counter 和 frame counter。 |
| **L** | 已接受的 legacy `input_inject_event()` / evdev KEY、ABS、MT 注入状态及逐字段覆盖标记。它不是 S，也不提交物理 R。 |
| **M** | 对 handler/evdev 发布的合并状态：先以 L 的有效覆盖合并最近完整 R，再合并当前 S。 |

物理帧提交前，overlay 不把未完成的物理 key/ABS/MT 状态泄漏到 M。input core 的值缓冲区满时可以产生人工同步并刷新无关事件，但该刷新不是物理 `SYN_REPORT`，不会提交未完成的 R。合成更新会立即合并最近完整 R、有效 L 与新 S 并发布 M，不需要等待下一次硬件中断。core 直接向 handler 分发有界的合并值，不递归调用 `input_event()` 或 `input_inject_event()`。

Overlay 不改写驱动的原始 `dev->mt` slots、trkid/frame、raw key 或 raw ABS 状态。`EV_REL`、`EV_MSC` 等无关事件沿原有 input dispatch 路径处理。Legacy `input_inject_event()` / evdev 注入仍走 input core 的既有事件接受与 raw 状态更新规则，但不是隔离的 S 输入，也不提交物理 R。

Evdev 查询读取 M 的已发布快照：

| 请求 | Overlay 行为 |
|---|---|
| `EVIOCGKEY` | 返回 M 的按键位图。 |
| `EVIOCGABS` | 返回 M 中查询轴的值；查询 `ABS_MT_*` 时使用 M 最近发布的选中 slot。minimum、maximum、fuzz、flat、resolution 和能力位保持原值。 |
| `EVIOCGMTSLOTS` | 返回 M 中指定 MT 轴的逐 slot 值。 |

这些查询在锁内复制状态快照，再在解锁后向用户空间复制；不在 event lock 内执行 uaccess。

### Legacy 注入的持久性与覆盖

已接受的 legacy KEY、ABS 与 MT 字段保留到后续对应物理字段提交；单独的物理 `SYN_REPORT` 不撤销这些注入值。真实设备先报告某个字段、再报告 `SYN_REPORT` 后，该字段的物理值覆盖 L；其他尚未被物理报告覆盖的注入字段继续保留。该规则在 attach 前后均适用，evdev 事件流与状态查询使用相同的已提交结果。

物理未完成帧仍不得进入合成发布结果。`ABS_MT_SLOT` 只选择 legacy MT 元数据对应的 slot，不把无效或被拒绝的普通 ABS 值当成已接受注入。`EV_KEY` 的 repeat（value `2`）是瞬时事件，不改写持久按键状态；core 保留 repeat 与其他瞬时事件，并让它们与合并状态共用一次帧结束。

MT tracking identity 与字段覆盖分开处理：真实生命周期重启会清除对应旧 legacy 覆盖；普通物理帧结束不制造注入触点的抬起、重按或坐标回退。reset/suspend 丢弃未完成的物理待提交帧并按既有规则使 S session 失效，不借此把物理未提交值冒充已提交 R。设备 shutdown 清除来源状态与覆盖标记。


### 容量、优先级与 slot 保留

Overlay 不扩展设备公告的 slot 数。新合成 DOWN 只能使用未保留且未被物理触点占用的空闲容量；无可用容量时更新以 `-ENOSPC` 失败，不发布部分更新。物理触点优先：既有物理触点在其生命周期内保持输出 slot 和 tracking identity；物理新触点可占用空闲 slot，容量耗尽时可淘汰 S 中的合成触点。物理触点不会因 overlay 被丢弃或更改坐标，attach/detach 也不重启物理手势或制造全抬起/全按下序列。

被物理触点淘汰的合成身份会成为 tombstone，不会在真实触点抬起后自行复现。若调用方在一次成功的完整快照中省略该身份后再重新提交，可将其作为新的 DOWN；在省略前再次提交被淘汰身份返回 `-EPIPE`。tracking ID 与调用方的 `id` 分离，同一合并状态中的活动输出 tracking ID 不重复；指针兼容 ABS_X/Y/PRESSURE、BTN_TOUCH 和设备已声明的手指数/触摸状态从合并触点推导，指针选择按触点年龄而不是 tracking-ID 数值排序。Overlay 不新增设备未声明的 key 或 axis。

设备初始化阶段可先保留需维持物理 slot identity 的特殊 slot：

```c
int input_mt_overlay_reserve_slot(struct input_dev *dev, unsigned int slot);
```

保留的 slot 始终供同索引物理触点使用，不作为合成触点或 remapped 物理触点的目标。该调用必须发生在第一次 attach 前；无 overlay 状态时返回 `-EOPNOTSUPP`，slot 越界返回 `-EINVAL`，已 attach、设备 shutdown 或 slot 有活动/待处理物理触点时返回 `-EBUSY`。本仓库 GT9886 初始化将 `panel_max_id * 2` 作为最终 pen slot 保留，见 [GT9886 input setup](../drivers/input/touchscreen/GT9886/goodix_ts_core.c)。

### 生命周期、复位与错误

每台设备同时只允许一个 session。`attach()` 可睡眠；它保留 input device 引用直到 `detach()`。Overlay 的同步内部处理，调用方不得持有 `dev->event_lock` 调用这些接口。`update()` 不分配、不睡眠，可在 atomic context 调用；core 用 event lock 串行化更新，session 所有者必须确保 `detach()` 不与该 session 的 `update()` 并发。

| 接口 | 错误/效果 |
|---|---|
| `input_mt_overlay_reserve_slot()` | `-EINVAL`：slot 越界；`-EBUSY`：已 attach/shutdown 或 slot 有物理活动/待处理触点；`-EOPNOTSUPP`：设备没有 overlay 状态。 |
| `input_mt_overlay_attach()` | 成功时返回 session；失败时 `*session` 为 `NULL`。`-EINVAL`：输出参数为 NULL；`-ENODEV`：无法取得设备引用；`-ENOMEM`：分配失败；`-EOPNOTSUPP`：设备没有 overlay 状态；`-EBUSY`：已有 session；`-ESHUTDOWN`：设备已 shutdown 或 suspended。 |
| `input_mt_overlay_update()` | `-EINVAL`：session 为 NULL、非零数量但 contacts 为 NULL、重复身份/轴、`tool_type > MT_TOOL_MAX`、已有身份更换工具类型或其他格式错误；`-EOPNOTSUPP`：设备未支持的轴，或设备未声明工具类型轴却请求非 finger；`-ERANGE`：工具类型超出设备声明范围；`-ENOSPC`：触点数量或可用 slot/内部身份容量不足；`-EPIPE`：触点身份仍处于 tombstone；`-ESHUTDOWN`：session 已因 reset、suspend 或设备移除失效。任何错误都不发布部分更新，既有触点状态不变。 |
| `input_mt_overlay_detach()` | NULL 为 no-op。一次发布中释放该 session 的合成触点并解除 session；仍映射的物理触点继续使用原输出 slot/identity，直到物理抬起。返回类型为 `void`。 |
| `input_mt_overlay_reset()` | 释放合成触点并使当前 session 失效；不重新激活 session。所有者须 detach，恢复后再 attach。 |
| `input_mt_overlay_suspend()` / `resume()` | suspend 释放合成触点并使当前 session 失效；resume 只允许设备再次 attach，不恢复旧 session。按 suspend/resume 次数平衡调用。 |

Input core 的 `input_reset_device()`、suspend、freeze、poweroff、disconnect/unregister 路径会清除或使 session 失效；resume、thaw、restore 不复活旧 session。驱动在 input core 之外复位硬件或做显示电源管理时，也必须在相应边界调用 overlay reset/suspend，并在恢复时平衡 resume。调用方拥有 session 生命周期，必须在自己的 session/release 路径调用 `input_mt_overlay_detach()`；reset/suspend 后仍应 detach 失效 handle，再创建新 session。

GT9886 除保留 pen slot 外，在 sysfs reset、`goodix_ts_hw_init()`、ESD recovery、MTK power reinit、固件更新 reset、`GTP_DEV_RESET` ioctl 和 display/PM suspend/resume 路径接入 reset/suspend/resume。固件更新准备阶段的 GPIO 硬复位在拉低 reset GPIO 前调用 reset；更新完成路径在 `hw_ops->reset()` 前也调用 reset。Probe 的 `goodix_ts_dev_confirm()` GPIO reset 发生在 input device 初始化与 session 创建之前。

`goodix_ts_suspend()` 由 PM、framebuffer 和 early-suspend 路径调用，在进入硬件睡眠/断电前使 session 失效；若扩展模块随后取消 suspend，旧 session 仍保持失效。NORMANDY `goodix_hw_resume()` 在硬件恢复中会 reset 芯片，Goodix resume 路径只在恢复成功且设备未保持 suspended 时平衡 overlay suspend。该 balance 不重新激活旧 session。具体边界见 [GT9886 core](../drivers/input/touchscreen/GT9886/goodix_ts_core.c)、[I2C reset implementation](../drivers/input/touchscreen/GT9886/goodix_ts_i2c.c)、[tools ioctl](../drivers/input/touchscreen/GT9886/goodix_ts_tools.c) 和 [firmware updater](../drivers/input/touchscreen/GT9886/goodix_gtx8_update.c)。

### 最小调用函数

下面的函数消费现有 session/event 与调用方已构造的触点快照，不假设某种驱动或设备。调用前确保 session 有效、event 存活，且未持有 `dev->event_lock`；查询配置期间还须与 event 修改、rollback、remove 串行化。它不是跨 MT/HWBP 的原子事务：若后续查询失败，已经成功发布的触点快照不会回滚。

```c
#include <linux/hw_breakpoint.h>
#include <linux/input/mt.h>

static int publish_and_inspect(struct input_mt_overlay *session,
			       struct perf_event *bp,
			       const struct input_mt_overlay_contact *contacts,
			       unsigned int num_contacts,
			       struct hw_breakpoint_resources *resources,
			       struct hw_breakpoint_config *config)
{
	int ret;

	ret = input_mt_overlay_update(session, contacts, num_contacts);
	if (ret)
		return ret;

	ret = hw_breakpoint_get_resources(resources);
	if (ret)
		return ret;

	return hw_breakpoint_get_config(bp, config);
}
```

### 已有运行证据范围

此前 ARM64 QEMU smoke 覆盖了 overlay 的物理帧提交与人工 flush 隔离、更新即时发布、raw MT/key/ABS 保持、evdev 状态快照与 metadata、slot/tracking identity 稳定、容量拒绝、物理优先级/tombstone，以及硬件断点既有 stepping、watchpoint、uaccess callback skip、modify/rollback 和 callback inheritance 路径。这不代表在实体 GT9886 设备上完成 reset/display-PM 验证；新增查询的运行证据另见下文。

## B. 硬件断点 STEP_ON_HIT

新增 kernel-only flag 与注册 helper 位于 [`include/linux/hw_breakpoint.h`](../include/linux/hw_breakpoint.h)，实现位于 [`kernel/events/hw_breakpoint.c`](../kernel/events/hw_breakpoint.c)；ARM64 hit/step 路径位于 [`arch/arm64/kernel/hw_breakpoint.c`](../arch/arm64/kernel/hw_breakpoint.c)。

```c
#define HW_BREAKPOINT_FLAG_STEP_ON_HIT (1UL << 0)

struct perf_event *register_user_hw_breakpoint_flags(
	struct perf_event_attr *attr,
	perf_overflow_handler_t triggered,
	void *context,
	struct task_struct *tsk,
	unsigned long flags);
```

`HW_BREAKPOINT_FLAG_STEP_ON_HIT` 为单个 event 的内核 flag，不属于 `perf_event_attr`。ARM64 上，自定义 overflow callback 可请求 execute breakpoint 或 watchpoint hit 后自动单步越过下一条指令；callback 不需要自行推进 PC 或建立 stepping。默认 overflow handler 的既有自动单步行为不变；未设置 flag 的旧注册 helper、自定义 callback 的既有行为、ptrace 路径与用户 ABI 均不变。watchpoint 在 kernel uaccess 命中 user watchpoint 时仍保留原有 callback skip 与 stepping 路径。

注册 helper 校验未知 flag（`ERR_PTR(-EINVAL)`），复制调用方 attr，不修改原 attr；创建时先禁用 event、保存 flags，再恢复 attr 指定的 enabled/disabled 状态并发布到 task，避免并发 fork 或 enable-on-exec 看见缺少 flags 的 event。Flags 在 `modify_user_hw_breakpoint()`、调用方 rollback 和 fork callback inheritance 中保留。无 `CONFIG_HAVE_HW_BREAKPOINT` 时 helper 返回 `ERR_PTR(-ENOSYS)`。释放仍使用 `unregister_hw_breakpoint()`。既有说明见 [Driver Basics: Kernel hardware-breakpoint stepping](../Documentation/driver-api/basics.rst)。

```c
#include <linux/hw_breakpoint.h>

static struct perf_event *
register_step_on_hit(struct perf_event_attr *attr,
		     perf_overflow_handler_t triggered,
		     void *context, struct task_struct *tsk)
{
	return register_user_hw_breakpoint_flags(attr, triggered, context,
					 tsk, HW_BREAKPOINT_FLAG_STEP_ON_HIT);
}
```

## C. 硬件断点只读查询

两个新增查询声明于 [`include/linux/hw_breakpoint.h`](../include/linux/hw_breakpoint.h)，通用接口实现于 [`kernel/events/hw_breakpoint.c`](../kernel/events/hw_breakpoint.c)，配置快照从 ARM64 arch breakpoint 配置生成，见 [`arch/arm64/kernel/hw_breakpoint.c`](../arch/arm64/kernel/hw_breakpoint.c)。

```c
struct hw_breakpoint_resources {
	unsigned int brps;
	unsigned int wrps;
};

struct hw_breakpoint_config {
	u64 address;
	u32 bas;
};

int hw_breakpoint_get_resources(struct hw_breakpoint_resources *resources);
int hw_breakpoint_get_config(struct perf_event *bp,
			     struct hw_breakpoint_config *config);
```

| 字段 | 语义 |
|---|---|
| `brps` | ARM64 perf 使用的每 CPU breakpoint（BRP，指令断点）总容量。 |
| `wrps` | ARM64 perf 使用的每 CPU watchpoint（WRP，数据观察点）总容量。 |
| `address` | event 最近一次完整成功验证后缓存的规范化 arch breakpoint 地址；包括架构检查和通用权限/`exclude_kernel` 检查。它不是直接读取 `attr.bp_addr` 或在线 CPU debug register。 |
| `bas` | 最近成功验证配置的 8-bit Byte Address Select 掩码；`u32` 仅是字段容器，不是字节长度，也不是 `attr.bp_len`。 |

资源值来自初始化后的 perf sanitized `nr_slots` 容量，表示每 CPU 总槽位，不是当前剩余空闲槽位，也不对在线 CPU 数量求和。约束尚未初始化时 `hw_breakpoint_get_resources()` 返回 `-EAGAIN`。

ARM64 的 `hw_breakpoint_get_config()` 返回最后一次完整成功验证并缓存的架构 `address` 与 BAS，而不是原始 attr 或瞬时硬件寄存器值。仅把 event 修改为 disabled 的操作不会触发验证，因此保留之前的缓存值；启用态修改成功验证后才更新缓存。架构检查或后续通用校验失败时恢复此前缓存，故失败修改不会破坏旧查询结果。需要配置与当前请求 attr 一致时，调用方应成功完成 enabled modify 后再查询。

### Native 地址边界校验

ARM64 native execute breakpoint 要求指令地址 4 字节对齐。native watchpoint 的地址 offset 与 BAS 必须完整落在同一 8 字节硬件粒度内；验证不能先截掉跨粒度字节、再把残余掩码视为成功。

| Native 请求 | 结果 |
|---|---|
| `W` / `RW`，address `0x100005`、len `2` | 合法；规范化 address `0x100000`、BAS `0x60`。 |
| `W` / `RW`，address `0x100007`、len `1` | 合法；规范化 address `0x100000`、BAS `0x80`。 |
| `W` / `RW`，address `0x100007`、len `2` 或 `8` | `-EINVAL`；不得截断后注册，也不得改变已成功缓存的配置。 |
| `X`，address `0x100009` | `-EINVAL`；不得向下对齐后注册。 |

上述严格校验作用于使用该 arch validator 的注册/修改路径，不新增用户 ABI 字段。compat ARM/Thumb 的既有验证与长度规范化规则不变；disabled-only modify 的缓存规则也不变。


| 失败条件 | 返回值 |
|---|---|
| 任一必需指针为 NULL，breakpoint 指针为 `ERR_PTR()`，或 event 不是 `PERF_TYPE_BREAKPOINT` | `-EINVAL` |
| perf breakpoint 约束尚未初始化（resources 查询） | `-EAGAIN` |
| 架构提供 `CONFIG_HAVE_HW_BREAKPOINT`，但未实现本查询的 ARM64 支持 | `-EOPNOTSUPP` |
| 未配置 `CONFIG_HAVE_HW_BREAKPOINT` | `-ENOSYS` |

未配置 `CONFIG_HAVE_HW_BREAKPOINT` 时，header stub 直接返回 `-ENOSYS`，不先进行参数校验；表中的 `-EINVAL` 适用于已配置硬件断点的接口实现。

每个查询失败时都不写调用方输出结构。查询不分配、不睡眠、不启停 event、不写硬件寄存器，也不读取在线 CPU debug registers。调用方必须保证 `bp` 在查询期间保持存活，并将 `hw_breakpoint_get_config()` 与该 event 的 modify、rollback、remove 串行化；查询接口本身不替调用方取得 event 引用或建立这类同步。

## D. 本次新增查询的验证记录

使用 ARM64 QEMU `virt`、Cortex-A57、2 个 CPU 启动当前内核，并加载调用真实公开接口的临时 GPL 消费者模块。模块逐项检查返回值与输出；用户空间 loader 的 `finit_module()` 返回 `0`，并打印 `USER QUERY SMOKE PASS`。

- 内核报告 6 个 BRP、4 个 WRP；资源查询同样返回 `6/4`，而不是两个 CPU 相加后的 `12/8`。分别注册到 BRP/WRP 总容量时查询值保持不变，下一次注册返回 `-ENOSPC`；释放后总量仍为 `6/4`。
- 验证 enabled execute event 与 disabled watchpoint event 的规范化结果：

  | 请求 | 查询 address | 查询 BAS |
  |---|---|---|
  | native `X`，address `0x100008`，len `8` | `0x100008` | `0x0f`（native execute 规范化为 4 字节） |
  | `RW`，address `0x100005`，len `2` | `0x100000` | `0x60` |
  | `RW`，address `0x100007`，len `1` | `0x100000` | `0x80` |

- disabled-only modify 保留旧缓存；enabled modify 更新缓存；非法长度 `9` 的早期架构拒绝、per-task kernel-address 的后期架构拒绝及通用 `exclude_kernel` 拒绝均保留旧缓存，随后显式 rollback 成功。
- NULL/`ERR_PTR()`/真实非 breakpoint perf event 的错误路径符合 `-EINVAL` 契约，并保持输出不变；成功和失败查询均不改变 event attr、arch hwinfo、state 或 flags。
- 单独编译并运行未定义 `CONFIG_HAVE_HW_BREAKPOINT` 的公开 header stub，确认 `-ENOSYS` 与输出不变；这不是一次无 HWBP 配置的完整内核启动。
- 本文两个调用函数均已编译，并在真实注册的虚拟 MT input device、有效 overlay session 与真实 perf event 上执行成功。
- 目标配置执行 `bash build.sh` 成功，产物为 `out/arch/arm64/boot/Image.gz`；生产 `System.map` 包含两个查询的导出项。

本次运行不覆盖 constraints 初始化前的 `-EAGAIN`、非 ARM64 的 `-EOPNOTSUPP` 或实体 GT9886 reset/display-PM。查询调用方的生命周期与串行化义务仍须由消费者保证，运行验证不替代该契约。

## E. 标准能力回移与后续变更记录

上文 D 保留此前查询接口的运行记录，不代表之后新增的依赖回移已经通过构建。全部标准能力回移、配置、内部调用方迁移、来源版本和新的验证范围集中记录在 [标准内核能力与变更清单](standard-kernel-backports.md)。新增能力只有在该清单给出实际成功的编译/运行证据时才算验证完成。
