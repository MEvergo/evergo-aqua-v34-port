# 标准内核能力回移与自定义适配清单

本文面向本仓库的内核维护者与调用方，记录 ARM64 vendor Linux `4.14.357-Aqua` 的标准能力回移、内部接口迁移及行为修复。它与 [MT overlay / HWBP 接口契约](custom-kernel-interfaces.md) 配套；所有新增和改动均按下面的文件清单、语义边界与验证记录登记，不以开启 CONFIG 代替完整实现。

## 实现范围与验证状态

| 能力 | 实现边界 | 验证状态 |
|---|---|---|
| HWBP native 地址验证 | watchpoint 必须完整落在 8 字节粒度内；execute 地址须 4 字节对齐；失败不污染配置缓存 | 修复后 ARM64 QEMU 验证边界拒绝、失败修改回滚、配置缓存保留及 slot 清理。 |
| Legacy input / evdev 注入 | 已接受注入在空物理 SYN 后保留；后续对应物理字段在完整帧提交后覆盖；R/L/S 来源与瞬时事件分离 | ARM64 QEMU 验证注入持久性，以及真实 evdev 读写、EVIOCGKEY/EVIOCGABS、物理状态替换和 repeat。 |
| ftrace / function hook | ARM64 patchable entry、regs、IPMODIFY、direct call 及模块 PLT 路径 | ARM64 QEMU 验证 hook 参数、IPMODIFY 返回值及卸载；目标构建状态见下文。 |
| ARM64 BPF tracing / BTF | 真实 trampoline、fentry/fexit 与 DWARF 生成的内核 BTF | ARM64 QEMU 验证真实 BTF 读取、fentry/fexit 附着、参数/返回值计数及 detach。 |
| io_uring | 固定来源的完整实现、io-wq、三个 syscall 与 native/compat 分发；不是 opcode 裁剪版 | ARM64 QEMU native/compat、socket/epoll、NVMe raw block/ext4/XFS IOPOLL 与 THP 生命周期 smoke 全部通过。目标配置关闭 THP，详见验证限制。 |
| Landlock | 固定来源的 ABI 1、三个 syscall、文件系统/ptrace hooks、credential 继承与堆叠 | ARM64 QEMU native/ARM32 compat 验证 ABI 1、deny/allow、策略堆叠及 fork 继承。 |

验证消费者是临时 native/compat 程序，不替代内核实现。表中结论只覆盖列明且实际执行的路径；QEMU 结果不替代实体 MTK/GT9886 硬件验证。

## 固定上游来源

| 子系统 | 来源 | 本仓库适配 |
|---|---|---|
| io_uring / io-wq / XArray / pinning 依赖 | [stable Linux 5.10.270](https://github.com/gregkh/linux/commit/1797d8bf8d0c2e74defad605d14e3553d43a3caf)，SHA `1797d8bf8d0c2e74defad605d14e3553d43a3caf` | 接入 4.14 的任务、VFS、block、GUP/CMA 和 syscall 架构；保留完整来源 opcode/注册接口。 |
| io_uring 顶层目录布局 | [上游目录迁移](https://github.com/torvalds/linux/commit/788d0824269bef539fe31a785b1517882eafed93) | 使用顶层 `io_uring/`，不是添加第二份 `fs/io_uring.c`。该 stable 分支包含较新的 IO 实现，不能假定它只需要初始 5.10 的依赖。 |
| Landlock | [stable Linux 5.15.221](https://github.com/gregkh/linux/tree/0248c33e835ecbec3a591f93fdaae53f7b90a4d6/security/landlock)，SHA `0248c33e835ecbec3a591f93fdaae53f7b90a4d6` | 完整 ABI 1，适配共享 LSM blobs、旧 superblock 生命周期和已有 mount 路径。 |
| LSM blob pointer alignment | [上游修复](https://github.com/torvalds/linux/commit/b9f5ce27c8f8be409d6afca9797a2da01e5cebbb) | 每个 LSM 的对象偏移按指针对齐，保留已有 major LSM 的实际对象。 |
| ARM64 ftrace regs | [上游实现](https://github.com/torvalds/linux/commit/3b23e4991fb66f6d152f9055ede271a726ef9f21) | 适配旧汇编宏、编译器探测、模块/内核 trace-site 表与寄存器布局。 |
| ARM64 BPF text poke / PLT | [上游实现](https://github.com/torvalds/linux/commit/b2ad54e1533e91449cb2a371e034942bd7882b58) | 使用本树 instruction generators 与 ftrace 分工，不把任意非 BPF text 交给 JIT 修改。 |
| ARM64 BPF trampoline | [上游实现](https://github.com/torvalds/linux/commit/efc9909fdce00a827a37609628223cd45bf95d0b) | 适配本树 `struct bpf_tramp_progs` 与 enter/program/exit ABI，不伪装为更新的 link/cookie/run-context ABI。 |

这些来源固定了可声明的接口版本；后续上游能力不会因为同名 CONFIG 或 syscall 存在而自动成为本树能力。

## 用户 ABI 与配置

### 系统调用

ARM64 native 使用 generic syscall 表，ARM64 compat 使用 ARM32 表。两者均登记以下号码，syscall-count 上界均为 `447`；未分配的号码保留既有 `sys_ni` 行为。

| 号码 | syscall | 版本边界 |
|---|---|---|
| `425` | `io_uring_setup` | pinned io_uring UAPI。 |
| `426` | `io_uring_enter` | native/compat 参数与 sigmask 路径。 |
| `427` | `io_uring_register` | pinned buffer/file/resource registration UAPI。 |
| `444` | `landlock_create_ruleset` | ABI 查询返回 `1`；来源 errata 表为空。 |
| `445` | `landlock_add_rule` | ABI 1 path-beneath 规则。 |
| `446` | `landlock_restrict_self` | 需要 `no_new_privs` 或来源实现要求的 capability；策略只能继续收紧。 |

`IORING_OP_OPENAT2` 使用新增的真实 `open_how` 和 pathname resolve 内部实现；本次没有另行增加 `openat2` syscall。Landlock 不声明 ABI 2+ 的 `REFER`、`TRUNCATE`、网络规则或 ioctl 限制。

### 目标配置与宿主工具

目标 `arch/arm64/configs/everpal_defconfig` 与已有 `out/.config` 启用 `IO_URING`、`BPF_SYSCALL`、`BPF_JIT`、`BPF_EVENTS`、`FUNCTION_TRACER`、`DYNAMIC_FTRACE`、`DEBUG_INFO`、`DEBUG_INFO_DWARF4`、`DEBUG_INFO_BTF`、`SYSFS`、`SECURITY` 与 `SECURITY_LANDLOCK`。Landlock 加入已有 `CONFIG_LSM` 列表，不替换其他已配置 LSM；`SECURITY_PATH` 由实际依赖选中。保留 vendor/GT9886 配置及已有 CMA/MIGRATION/GENERIC_GUP 选择。

- 4.14 Kconfig 不支持在表达式内使用新版 `$(cc-option,...)`。根 Makefile 用现有 compiler probe 导出 `CC_HAS_PATCHABLE_FUNCTION_ENTRY`，隐藏 Kconfig 从环境读取结果。只有编译器实际接受 `-fpatchable-function-entry=2` 才选择新 ARM64 路径。
- 新路径省去 `-pg`、`recordmcount` 与 `BUILD_C_RECORDMCOUNT`；不支持 patchable entry 的编译器保留既有 `-pg` 路径。`notrace` 使用显式零个 patchable entries 的属性。
- BTF 构建要求 `pahole >= 1.32`。生成时跳过 `ENUM64`、`DECL_TAG` 与 `TYPE_TAG`，因为本树 BTF parser 只支持到 `DATASEC`；没有开启 float BTF 编码。不能把无法解析的宿主新类型编码直接塞进旧内核。
- `DEBUG_FS=n` 不等于 function tracing 不可用；本树 `CONFIG_TRACING` 构建独立 `tracefs`。验证消费者挂载 `tracefs`，不依赖替开启 debugfs 来掩盖配置错误。
- 目标构建入口为 `bash build.sh`，使用 ZyC clang/LLD `22.0.0`，复用已有 `out/.config` 并构建 `vmlinux Image.gz dtbs modules`。bpfilter helper 单独使用 `BPFILTER_CC` / `BPFILTER_LDFLAGS`；脚本优先寻找 AArch64 GCC，默认静态链接，避免 Android 上依赖不存在的 glibc 动态解释器。缺少目标 libc 的工具链会明确报错，不再静默跳过 bpfilter。

## 行为与生命周期适配

### 事件与硬件断点

Legacy 注入由 L 的逐 KEY/ABS/MT 覆盖标记持久化，不与真实物理 R 或隔离 session S 混用。物理 SYN 只提交对应 pending R；没有对应物理字段更新的 SYN 不清除 L。已接受注入和 `ABS_MT_SLOT` 元数据选择分开处理，被拒绝的普通事件不伪造成新注入。repeat 和 REL/MSC 等瞬时事件仍分发，不重复生成 SYN。MT generation/restart、reset/suspend/shutdown 的语义见 [接口契约](custom-kernel-interfaces.md#legacy-注入的持久性与覆盖)。

HWBP 在地址规范化和 BAS 左移之前拒绝 native 不对齐 execute 和跨 8 字节粒度 watchpoint；修改失败保留此前查询缓存。compat ARM/Thumb、既有 STEP_ON_HIT、权限验证和 rollback 机制保留。

### Tracing、模块与 BTF

ARM64 两个 patchable NOP 中的第二个是实际 ftrace callsite；第一条初始化为保存入口 LR 的等价指令。BTF 仍保留原始 function entry，查找/安装 ftrace filter 时必须经 `ftrace_call_adjust()` 与 `ftrace_location()` 规范化；调用 original/跳过 trampoline frame 时不能把两种地址混用。

模块保留 ftrace 与 ftrace-regs 专用 PLT。远距 direct trampoline 经 regs entry 的完整地址 dispatch；普通近距跳转仍用合法的 ARM64 branch 编码。`S_FP` 的实际寄存器偏移、旧汇编 `.globl` labels、`A64_NOP` 与 instruction-generator 头文件均作为真实编译依赖接入。

通用 direct ftrace 使用同一有序 record lookup 与搬移 hash 原语；扩容保留完整 entry，包括 direct target，不能用只复制 IP 的 filter-copy 路径丢掉目标。BPF trampoline 在 enter helper 调用之后重新建立 caller-clobbered `x0` context；`__bpf_prog_enter()` 返回零只表示本树统计未启用，不表示可以跳过程序执行。可执行内存权限设置失败会释放分配并返回错误。

本树 ARM64 trampoline 的标准边界为最多 8 个 native 参数、每个参数不超过 8 字节、返回值不超过 8 字节；不支持的签名返回实际错误，不生成错误代码或提供假成功。

vmlinux BTF 由链接脚本导出 `__start_BTF` / `__stop_BTF` 边界；`btf_parse_vmlinux()` 直接读取真实 `.BTF` section，不依赖不存在的 `_binary__btf_vmlinux_bin_{start,end}` 符号。

Tasks Trace RCU 使用固定 5.10 的真实 trace reader nesting/special 状态、callback queue 与专用 worker、IPI/holdout grace-period 检查及 exit reader 清理；接入 task 初始化、scheduler 和 dynticks quiescent-state 支持，并选择 IRQ_WORK。旧 classic Tasks RCU 的独立行为保留，不把 trace read-side protection 替换成 SRCU，也不把 callback API 替换为普通 RCU 同步。真实 fentry attach 曾卡在 `synchronize_rcu_mult()`：旧 trace callback 没有 worker，是本次运行发现并补齐的依赖。

### IO 任务、pinning 与计费

- Task work 增加真实通知模式、ARM64 `TIF_NOTIFY_SIGNAL` 和退出/exec 取消流程；保留 vendor `TIF_FSCHECK`、原有 NEED_RESCHED/NOTIFY_RESUME flags。io-wq 使用实际 IO worker 创建和 scheduler sleeping/running hooks。ARM64 `copy_thread()` 与固定 5.10 来源一致，将 `PF_IO_WORKER` 与 kernel-entry 路径一起初始化 x19/x20 和 EL1h 寄存器，而不把 worker 函数指针当用户 stack；它仍是共享用户 mm 的 IO worker，不伪装为 `PF_KTHREAD`，真实 worker 退出路径执行 `do_exit()`。
- 本树 `task_struct.usage` 仍是 `atomic_t`。`get_task_struct()` 返回被加引用的指针，bulk get/put 使用对应 atomic 原语，不把旧字段指针 cast 成 `refcount_t *`。
- `signal_pending()` 包含 IO notify，`task_sigpending()` 只检查真实 pending signal。native/compat 临时 sigmask 在等待前保存并阻塞，所有返回路径按是否 interrupted 恢复；安装临时 mask 不要求已经存在待处理信号。
- FOLL_PIN 使用加权普通页引用和 compound pin 计数；slow/fast/huge/devmap/hugetlb 路径按相同所有权配对 unpin。long-term pin 共用 DAX 检查和 CMA 迁移；隔离无法取得页面时释放已获取 pin 并返回真实错误，不无限重试。
- CMA 目标分配使用既有 migration/page-isolation 接口及 `PF_MEMALLOC_NOCMA`，保持 source node、THP/HugeTLB 与 GFP 策略。ARM64 `arch_make_page_accessible()` 对本 4.14 普通 RAM 没有 private/encrypted 状态转换要求；这不是用于其他架构的通用假 fallback。
- Cached `dev_pagemap` 引用在 slow/fast GUP 中有共同归一化与 unwind；speculative compound-head acquisition 验证并发 split。USNIC chunk 分配失败释放尚未入链的本批 pin；V4L2 partial pin / DMA map 失败正确 unpin，DMA 未发生时不脏化页面。
- 移除旧 `get_user_pages_longterm()` 并迁移其四类消费者：RDMA core、USNIC、V4L2 videobuf、VFIO。既有其他 GUP 使用不因同名 pin 计费统计迁移就被宣称全部转换成 FOLL_PIN。
- `mm_struct.pinned_vm` 改为 `atomic64_t`，同步迁移 fork 初始化、perf、proc/debug 与所有旧字段访问方。RDMA/USNIC 成功计费增加实际 pin 页数；不以此前读取的 snapshot 做 `atomic_set()` 覆盖其他并发计费。USNIC 保留循环递减前的不可变页数。
- 注册缓冲区的 compound-page charge 由 ring 内 PFN-keyed XArray 管理。共享/替换同一 THP 的存活资源引用共同维持一次完整 charge，最后引用退休后才 unaccount；普通页按原有 buffer 页数计费。按 compound-head run 精确分配引用数组，避免对所有 base pages 分配冗余 head 指针和二次线性去重。
- 每个 compound charge 持有额外普通 head reference，防止 deferred unpin 和 account retirement 之间 PFN 被回收后误认成同一资源；最后退休同时释放该 reference。分配/插入失败回滚 charge/reference，ctx 回收在资源 work 排空后销毁 XArray。

上游资源 tag CQE 在旧资源的实际 unpin/unaccount **之前**提交。本树不为验证改变此顺序，也不添加测试专用生产回调。THP 消费者用旧 buffer 独占普通页 charge 的消失证明 retirement 已发生，再检查仍存活 THP 的 `VmPin` 与 memlock 拒绝；不能仅等到 tag CQE 就认定资源已释放。

### VFS、poll 与 socket 依赖

`open_how` builder、pathname resolve、iov iterator save/restore、async page waits 与 `IOCB_WAITQ` 是真实旧内核依赖迁移。Buffered read 已取得部分数据后切到 NOWAIT 行为，不能把已取得的数据丢掉或把未完成读取冒充 EOF。Per-CPU reference 明确支持 allow-reinit/resurrect，并迁移需重启的 MD initializer；普通/init-atomic/init-dead 消费者保留对应生命周期。

`..` 到达当前 root 时只终止向上遍历，RCU/refwalk 都继续检查覆盖该 root 的 mount，并保持 `RESOLVE_BENEATH` 的越界拒绝及 `RESOLVE_NO_XDEV` 的跨 mount 拒绝。不能提前返回并跳过旧 VFS 必需的向下 mount 遍历：实际 `devtmpfs` 启动中 `/..` 被错误解析到被覆盖的 rootfs，导致 NVMe/evdev 节点创建在错误文件系统，挂载 `/dev` 后不可见；此缺口由真实 QEMU 存储/evdev 消费者发现。

Poll 的 `__poll_t` key、key conversion、VFS poll helpers、native mask mangling 与 `EPOLL_URING_WAKE` 保持实际 wake 信息。`eventfd_signal_mask()` 传播 caller mask 并保留递归检测；`eventfd_signal()` 仍是标准现有 API。`epoll_event.events` 仍为 32-bit，用户布局不变。

Native/compat sendmsg/recvmsg、shutdown、accept 与 connect syscall 共享真实 file/socket core，IO workers 使用捕获的 file/address/control context而非重新查 worker 的用户 FD。内部 `msghdr` 区分用户和内核 control buffer；native/compat CMSG 都按该模式写入，不能对内核 buffer 执行 uaccess，也不能把不能交付的 SCM_RIGHTS 引用遗留。内部结构变化要求一起重编所有消费者，用户 `msghdr` ABI 不变。

`MSG_WAITALL` 的 IO分段重试将此前真实输出的 `MSG_CTRUNC` 显式传给recv core，协议读取后再合并到最终用户flags；普通recvmsg/recvmmsg传零，不能把用户输入的msg_flags冒充截断状态。eventfd消费者在 `eventfd_signal_count()` 为真时须把再次signal延后，避免嵌套wake递归。

`iov_iter_kvec()`、`iov_iter_bvec()` 和 `iov_iter_pipe()` 统一采用固定 5.10 的纯方向参数约定：前两者接受 `READ` / `WRITE`，pipe 接受 `READ`，构造函数本身添加对应 `ITER_*` 类型。旧文件系统、网络与驱动调用者全部迁移；不在 IO caller 加旧编码，也不让构造函数兼容两套约定。保留本 vendor 的 iterator 类型位值和 pipe 环形布局。实际 fixed-buffer worker 的 `iov_iter_bvec` BUG 是此次跨版本 API 缺口的运行证据。

Blockdev 的 `IOCB_NOWAIT` 独立于 `IOCB_HIPRI` 设置 `REQ_NOWAIT`。XFS NOWAIT direct read 使用 trylock，unaligned write 的已有 DIO 检查失败经公共退出路径解锁。Ext4 的 unaligned IOPOLL write 在保持 inode 串行化锁的同时主动驱动真实 block completion 与 unwritten extent conversion，避免等待只能由本次 polling 完成的请求。共享 `do_tee()` core 对输入 `FMODE_READ` 和输出 `FMODE_WRITE` 做实际 `EBADF` 校验，syscall 与 IO opcode 不分叉。

### Landlock 与已有 LSM

完整 ruleset/object/credential/filesystem/ptrace 实现使用共同的 LSM 对象 blob。SELinux/Smack 的 superblock 私有状态改为各自的对齐 offset，移除旧独占 allocation/free 所有权，而不是禁用这些 LSM。`sb_delete` 在 `evict_inodes()` 之后、`put_super()` 之前 detach Landlock inode objects，并用真正的 hashed `wait_var_event` / `wake_up_var` 等待未完成释放。

已有 `do_move_mount()` 在取得精确来源 path 后、mount attachment 前执行 `security_move_mount()`；本次不为此新造另一个 mount syscall。既有 `security_sb_mount` 检查不删除。ABI 1 的 filesystem topology 限制、规则交集、fork 继承及 ptrace 层级检查均保留固定来源语义。

## 文件级新增与改动登记

下列清单记录本轮标准回移及相关自定义接口变化；同一文件可服务多个能力，但不重复维护第二套实现。生成的 `out/` 产物不是手写标准功能替代物。已有无关 KernelSu/KPM 改动保持不动，不归入本轮回移。

| 范围 / 文件 | 新增或改动 | 对外影响 |
|---|---|---|
| `arch/arm64/kernel/hw_breakpoint.c`, `kernel/events/hw_breakpoint.c`, `kernel/events/internal.h`, `include/linux/hw_breakpoint.h`, `include/linux/perf_event.h`, `Documentation/driver-api/basics.rst` | native range/alignment 拒绝顺序、已验证 address/BAS 查询、kernel-only event flags/counter 入口与失败修改的缓存/属性/启用状态回滚 | 非法请求不再被截断后接受；失败的跨类型修改保留原 W event 与其最后成功配置；契约与 flags 保持内核接口边界。 |
| `drivers/input/input-mt-overlay.c`, `drivers/input/input-mt-overlay.h`, `drivers/input/input.c`, `drivers/input/input-mt.c`, `drivers/input/evdev.c`, `drivers/input/Makefile`, `include/linux/input.h`, `include/linux/input/mt.h`, `Documentation/driver-api/input.rst` | R/L/source、字段覆盖、generation/restart、accepted/physical 分离、查询/evdev 发布与单次帧 flush；零事件帧只更新状态、不发布 SYN_REPORT | Legacy 持久性修复；原 overlay 公共接口保留，自定义接口与驱动生命周期见配套契约。 |
| `drivers/input/touchscreen/GT9886/goodix_gtx8_update.c`, `drivers/input/touchscreen/GT9886/goodix_ts_core.c`, `drivers/input/touchscreen/GT9886/goodix_ts_tools.c` | 既有自定义 overlay 的 firmware update、reset、display-PM/shutdown 调用方 | 保留 reset/generation 与 suspend/resume 的原接口；本轮不以 QEMU 代替实体 GT9886 验证。 |
| `Makefile`, `arch/arm64/configs/everpal_defconfig`, `out/.config` | 顶层 IO 对象、compiler probe、真实功能依赖 | 目标配置、编译参数及产物变化。 |
| `build.sh` | 固定clang/LLD验证、保留existing config、实际compiler下执行olddefconfig再构建vmlinux/Image.gz/dtbs | 不下载/重打补丁、不删除输出目录；新Kconfig默认值自动同步，不因非交互输入在silentoldconfig中止。 |
| `include/uapi/asm-generic/unistd.h`, `arch/arm64/include/asm/unistd.h`, `arch/arm64/include/asm/unistd32.h`, `include/linux/syscalls.h`, `kernel/sys_ni.c` | 六个 syscall 声明、分发、禁用配置 fallback 与 count 上界 | 上述 native/compat 用户 ABI。 |
| `arch/arm64/Kconfig`, `arch/arm64/Makefile`, `include/linux/compiler_types.h` | patchable tracing 的真实配置/编译支持与 notrace 属性 | 编译器能力决定 tracing 后端。 |
| `arch/arm64/include/asm/ftrace.h`, `arch/arm64/kernel/ftrace.c`, `arch/arm64/kernel/entry-ftrace.S`, `arch/arm64/kernel/asm-offsets.c`, `arch/arm64/kernel/arm64ksyms.c` | regs、entry LR、direct dispatch、IPMODIFY 与真实寄存器偏移；仅legacy编译模式导出真实存在的_mcount | Function tracer / hook；patchable模式不保留不存在的旧入口导出。 |
| `arch/arm64/include/asm/insn.h`, `arch/arm64/kernel/insn.c` | unsigned-offset load/store 与 literal-load generators | JIT/trampoline 真实指令编码。 |
| `arch/arm64/include/asm/module.h`, `arch/arm64/kernel/module.c`, `arch/arm64/kernel/module-plts.c`, `kernel/module.c` | patchable site loader 与专用 PLT | 模块 tracing 与远距目标。 |
| `arch/arm64/net/bpf_jit.h`, `arch/arm64/net/bpf_jit_comp.c`, `kernel/bpf/trampoline.c` | BPF text poke/PLT 失败回滚、trampoline emitter、context/权限错误处理；更新失败时隔离 trampoline 并保留可能仍在执行的 image 引用 | 原有 BPF ABI 的真实 ARM64 tracing 实现；无法确认 text patch 状态时拒绝后续 attach/detach。 |
| `kernel/trace/Kconfig`, `kernel/trace/ftrace.c` | 能力依赖、patchable 初始 NOP、record lookup/hash move | Generic 与 ARM64 使用同一 trace records/direct targets。 |
| `kernel/rcu/tasks.h`, `kernel/rcu/tree.c`, `kernel/rcu/tree_plugin.h`, `kernel/rcu/tree.h`, `kernel/rcu/rcu.h`, `kernel/rcu/Kconfig`, `include/linux/rcupdate_trace.h`, `include/linux/sched.h`, `include/linux/init_task.h`, `kernel/fork.c`, `kernel/exit.c`, `kernel/sched/core.c` | 真实 Tasks Trace RCU 的队列/worker、IPI/holdout、reader/exit、task初始化和 scheduler/dynticks 支持；可选 `CONFIG_TASKS_TRACE_RCU_READ_MB` 下的 EQS enter/exit 钩子与 possible-CPU postscan；移除旧 SRCU trace state | BPF sleepable/non-sleepable trampoline 的真正 grace-period 与释放保护；不绕过实际 callback 等待。 |
| `include/asm-generic/vmlinux.lds.h`, `kernel/bpf/btf.c`, `include/linux/btf.h`, `include/uapi/linux/btf.h`, `lib/Kconfig.debug`, `scripts/Makefile.build`, `scripts/link-vmlinux.sh` | trace-site/BTF sections、vmlinux BTF 解析和真实生成/链接流程；采用标准 20-bit type ID / 24-bit name offset 上限 | 内核 BTF 与 trace 表进入最终镜像，运行时使用链接器 section 边界；不扩大所支持的 BTF kind。 |
| `io_uring/io_uring.c`, `io_uring/io-wq.c`, `io_uring/io-wq.h`, `io_uring/Makefile`, `include/uapi/linux/io_uring.h`, `include/linux/io_uring.h`, `include/trace/events/io_uring.h`, `init/Kconfig`, `fs/Kconfig` | 完整 pinned IO source/UAPI/worker/trace integration及 compound charge 生命周期 | IO mmap/SQE/CQE、所有来源 opcode 与 registration API。 |
| `include/linux/xarray.h`, `lib/xarray.c`, `lib/Makefile`, `lib/radix-tree.c` | 用完整 XArray 替换旧 stub；共享 radix 节点 layout checks/cache/RCU | 真实 XArray API，无第二套节点分配器。 |
| `include/linux/task_work.h`, `kernel/task_work.c`, `include/linux/tracehook.h`, `include/linux/sched/signal.h`, `kernel/signal.c`, `arch/arm64/include/asm/thread_info.h`, `arch/arm64/kernel/signal.c` | 通知模式、signal return、临时 sigmask 与 vendor flags保留 | IO task-work/等待/返回用户态的实际推进。 |
| `fs/file_table.c`, `fs/namespace.c`, `kernel/events/uprobes.c`, `kernel/sched/fair.c`, `kernel/irq/manage.c`, `security/keys/keyctl.c`, `security/yama/yama_lsm.c` | 迁移旧 task-work notification callers | 保持原有 resume 行为。 |
| `include/linux/sched.h`, `include/linux/sched/task.h`, `kernel/fork.c`, `kernel/exit.c`, `fs/exec.c`, `kernel/sched/core.c` | IO worker、生命周期取消、task 引用与 scheduler hooks | 真实异步工作与资源退出。 |
| `arch/arm64/kernel/process.c` | 标准 IO worker 的 kernel-entry 寄存器启动适配 | 用户 mm/IO worker 身份不变，真实函数执行与退出而非错误返回用户态。 |
| `include/linux/mm_types.h`, `include/linux/mm.h`, `include/linux/sched/mm.h`, `include/linux/memremap.h`, `mm/gup.c`, `mm/page_alloc.c`, `mm/huge_memory.c`, `mm/hugetlb.c`, `arch/arm64/include/asm/page.h`, `mm/frame_vector.c` | FOLL_PIN/DAX/CMA、devmap/unwind、compound split protection、allocation checks 与 obsolete API 移除；frame_vector 使用 long-term pin/unpin，gigantic compound page 初始化 pincount | Pin 生命周期和 migration 语义；THP unmap 使用本 vendor 的三参数 rmap API。 |
| `drivers/infiniband/core/umem.c`, `drivers/infiniband/hw/usnic/usnic_uiom.c`, `drivers/media/v4l2-core/videobuf-dma-sg.c`, `drivers/vfio/vfio_iommu_type1.c` | 四类 long-term pin 消费者与失败 unwind | pin/unpin 配对及适当 dirty release。 |
| `kernel/events/core.c`, `fs/proc/task_mmu.c`, `mm/debug.c`, `drivers/infiniband/hw/hfi1/user_pages.c`, `drivers/infiniband/hw/qib/qib_user_pages.c`, `drivers/misc/mic/scif/scif_rma.c` | 与上行 RDMA/USNIC/fork 一起迁移 pinned_vm atomic 访问 | `VmPin` 用户输出格式保留；内部并发计费不覆盖 snapshot。 |
| `fs/internal.h`, `fs/namei.c`, `fs/open.c`, `fs/proc/base.c`, `fs/proc/namespaces.c`, `include/uapi/linux/openat2.h`, `include/linux/namei.h`, `include/linux/fs.h` | open_how 与 resolve/pathwalk，以及相关 VFS caller 迁移；root 的 dotdot 保持覆盖 mount 的 RCU/refwalk 遍历 | IO openat2 semantics；proc magic-link 跳转保留失败所有权；devtmpfs 不在被覆盖 rootfs 创建节点。 |
| `include/linux/pagemap.h`, `include/linux/uio.h`, `lib/iov_iter.c`, `mm/filemap.c` | iterator state 与标准纯方向构造 API、async page wait/read | 异步读取状态、部分读取与真实 fixed-buffer 类型语义。 |
| `include/linux/percpu-refcount.h`, `lib/percpu-refcount.c`, `drivers/md/md.c` | allow-reinit/resurrect 与可重启 caller迁移 | 原子/per-CPU mode 及 kill/reinit 生命周期。 |
| `kernel/trace/trace_event_perf.c` | 移除FUNCTION_TRACER分支既有的重复局部 `event` 声明 | 修复真实perf/ftrace消费者的编译阻塞；不删除功能。 |
| `kernel/compat.c`, `include/linux/compat.h` | 标准 user sigset提取，共用已有big-endian转换与fault路径 | native/compat IO temporary-mask保持正确位序。 |
| `fs/file.c`, `include/linux/file.h`, `fs/read_write.c`, `include/linux/uio.h`, `lib/iov_iter.c`, `include/uapi/linux/openat2.h` | captured nofile fd分配、close capture、显式compat iovec import与open_how版本尺寸 | IO worker不按自身syscall模式误读用户iovec；保留fd/文件所有权。 |
| `fs/splice.c`, `mm/page_io.c`, `fs/cifs/misc.c`, `fs/cifs/transport.c`, `fs/cifs/connect.c`, `fs/cifs/smb2ops.c`, `fs/afs/rxrpc.c`, `fs/9p/vfs_addr.c`, `fs/9p/xattr.c`, `fs/9p/vfs_dir.c`, `fs/orangefs/inode.c`, `fs/ncpfs/sock.c`, `fs/nfsd/vfs.c` | 27 个已有 FS/MM iterator constructor callsites 迁移到纯 READ/WRITE，pipe 使用 READ | 原同步/异步、socket 与 page IO 方向保留，没有旧参数编码 shim。 |
| `net/ceph/messenger.c`, `drivers/block/loop.c`, `drivers/block/nbd.c`, `drivers/block/drbd/drbd_main.c`, `drivers/target/target_core_file.c`, `drivers/usb/usbip/usbip_common.c`, `net/bluetooth/a2mp.c`, `net/bluetooth/6lowpan.c`, `net/bluetooth/smp.c`, `net/tls/tls_device.c`, `net/rxrpc/recvmsg.c`, `net/9p/client.c`, `net/socket.c`, `drivers/target/iscsi/iscsi_target_util.c`, `drivers/staging/lustre/lnet/lnet/lib-move.c`, `drivers/staging/lustre/lnet/lnet/lib-socket.c`, `drivers/staging/lustre/lnet/klnds/o2iblnd/o2iblnd_cb.c`, `drivers/staging/lustre/lnet/klnds/socklnd/socklnd_lib.c` | 已有 NET/driver iterator constructor 迁移到纯方向；loop 的 rw 与 target 的 is_write 保留真实方向判断 | 与同一标准构造 API 一起重编；既有 CMSG 和 saved MSG_CTRUNC 修复保持。 |
| `fs/namei.c`, `fs/stat.c`, `fs/splice.c`, `fs/sync.c`, `mm/fadvise.c`, `mm/madvise.c`, `fs/internal.h`, `include/linux/fs.h`, `include/linux/mm.h` | 提取并共用实际rename/rmdir/unlink/statx/splice/tee/sync/fadvise/madvise core；补全可选fadvise callback | 原syscall与IO opcode共享实现，不使用占位wrapper。 |
| `block/bio.c`, `block/blk-core.c`, `block/ioprio.c`, `include/linux/blk_types.h`, `include/linux/blkdev.h`, `include/linux/ioprio.h` | NOWAIT/HIPRI、queue capability、bio clone/request初始化及ioprio检查/传播 | 真正block提交；CONFIG_BLOCK禁用时不会调用不可用队列helper。 |
| `fs/aio.c`, `fs/block_dev.c`, `fs/direct-io.c`, `fs/iomap.c`, `fs/ext4/file.c`, `fs/xfs/xfs_file.c`, `fs/fuse/passthrough.c`, `include/linux/fs.h`, `include/linux/iomap.h` | 实际blockdev/ext4/XFS DIO poll，cookie/queue、multi-bio引用、write freeze和prio/hint；ext4/XFS buffered async opt-in | 只有实际iopoll-capable文件后端接受对应请求；其他文件系统不伪造poll支持。 |
| `fs/seq_file.c`, `include/linux/seq_file.h`, `include/linux/percpu-refcount.h` | 标准hex字段输出与bulk ref获取 | IO fdinfo/批量引用配合真实上下文。 |
| `include/linux/poll.h`, `include/uapi/linux/eventpoll.h`, `include/linux/eventfd.h`, `fs/eventfd.c` | typed poll keys、mask转换、真实 wake/递归处理 | Poll/eventfd ABI 布局保持，新增 IO wake 信息。 |
| `include/linux/net.h`, `include/linux/socket.h`, `include/net/compat.h`, `include/linux/compat.h`, `net/socket.c`, `net/compat.c`, `net/core/scm.c` | Native/compat socket共享 core、CMSG buffer模式及 saved-mask声明 | 内部 msghdr 布局迁移；用户消息 ABI 保持。 |
| `net/ipv4/ip_sockglue.c`, `net/ipv6/ipv6_sockglue.c`, `include/linux/keyslot-manager.h` | legacy packet-options CMSG明确标记用户control buffer；keyslot参数显式前向声明device | 保留getsockopt uaccess语义和真实crypto device类型；旧eventfd fileget声明同时恢复供既有消费者使用。 |
| `fs/eventpoll.c`, `include/linux/eventpoll.h` | 共享实际epoll_ctl core与event需求判断；IO nonblock只trylock，复杂拓扑完整检查交给正常worker | 不让初次IO提交在旧recursive topology锁中睡眠；原syscall与worker执行完整环路/容量检查。 |
| `tools/bpf/resolve_btfids/{main.c,Makefile,Build,.gitignore}`, `tools/lib/zalloc.c`, `tools/include/linux/zalloc.h`, `tools/lib/ctype.c`, `tools/include/linux/ctype.h`, `Makefile` | 接入固定5.10来源的真实ELF/BTF ID解析宿主工具、allocation/ctype helpers；本树tools框架、installed libbpf public API/type计数及生成工具依赖 | 实际填充.BTF_ids，不跳过BTF ID解析；宿主需pkg-config/libbpf/libelf/zlib开发文件。 |
| `security/landlock/common.h`, `cred.c`, `cred.h`, `errata.h`, `fs.c`, `fs.h`, `Kconfig`, `limits.h`, `Makefile`, `object.c`, `object.h`, `ptrace.c`, `ptrace.h`, `ruleset.c`, `ruleset.h`, `setup.c`, `setup.h`, `syscalls.c` | 完整 Landlock 18文件；本行短文件名均位于 `security/landlock/` | ABI 1 实现，不是后来 ABI 的占位。 |
| `include/uapi/linux/landlock.h`, `security/Kconfig`, `security/Makefile` | UAPI与对象/LSM配置连接 | 显式 ABI 1 与实际选择。 |
| `include/linux/wait_bit.h`, `kernel/sched/wait_bit.c` | 标准 hashed wait-var基础设施 | Landlock sb teardown 的真实等待/唤醒。 |
| `include/linux/lsm_hook_defs.h`, `include/linux/lsm_hooks.h`, `include/linux/security.h`, `security/security.c`, `fs/super.c`, `fs/namespace.c` | shared blob accounting/alignment、sb_delete/move_mounthooks及VFS调用 | 与既有 LSM 共存并正确回收。 |
| `security/selinux/include/objsec.h`, `security/selinux/hooks.c`, `security/selinux/ss/services.c`, `security/smack/smack.h`, `security/smack/smack_lsm.c` | 原 major LSM对象改用各自blob offset | 不禁用SELinux/Smack，不遗留旧独占free所有权。 |
| `docs/custom-kernel-interfaces.md`, `docs/standard-kernel-backports.md` | 接口契约、完整变更登记、来源/ABI与验证边界 | 自定义内核差异有明确维护入口；不改 `docs/superpowers/`。 |
| `arch/arm64/configs/everpal_defconfig`, `out/.config`, `kernel/usermode_driver.c`, `kernel/params.c`, `fs/nomount.c`, `Makefile`, `net/Makefile`, `net/bpfilter/Makefile`, `build.sh` | 启用 FAULT_INJECTION/BPFILTER；补齐 usermode driver 声明及 const 初始化；修正工具链探测、目标 helper 编译与模块构建入口 | `BPFILTER_UMH=m`；helper 使用目标 libc 静态链接，链接失败显式终止。保留 STATIC_USERMODEHELPER 安全路由。 |
| `scripts/Makefile.modpost` | ThinLTO 模块在 `HAVE_PATCHABLE_FUNCTION_ENTRY=y` 时跳过旧 `recordmcount` 步骤，与 vmlinux 链接规则一致 | 干净输出目录不再依赖遗留的 `scripts/recordmcount` 可执行文件；非 patchable-entry 路径保持原行为。 |
| `kernel/bpf/verifier.c`, `tools/bpf/resolve_btfids/main.c` | 按实际 error-injection 白名单与配置生成 BTF set；区分零成员集合和未解析普通 ID | 不为不存在的函数写入伪 ID；合法空集合不再误报警，真正缺失的类型仍报警。 |
| `include/linux/perf_event.h`, `kernel/events/internal.h`, `kernel/events/core.c`, `kernel/events/ring_buffer.c` | perf 内部 `struct ring_buffer` 更名为 `struct perf_buffer` | 消除与 tracing ring buffer 的异构同名 BTF 冲突；布局、字段及用户 ABI 不变。 |
| `lib/lz4/lz4.c`, `lib/lz4/lz4.h`, `lib/lz4/lz4hc.c`, `lib/lz4/lz4hc.h`, `crypto/lz4hc.c` | kernel/freestanding 不提供隐含大栈 workspace 的普通 wrapper；HC optimal table 移入调用者 workspace；crypto 调用者改用现有 `LZ4HC_CLEVEL_DEFAULT` | HC workspace 增至 327,784 bytes；调用者必须用 `LZ4HC_MEM_COMPRESS` 或 `LZ4_sizeofStateHC()` 分配，不能硬编码旧大小。保留压缩等级、流式及字典语义。 |
| `drivers/kernelsu/kpm/kpm.c`, `drivers/kernelsu/kpm/compat.c` | user-load 路径缓冲区改为动态分配；小批次 hotpatch 使用有界栈 workspace，大批次一次分配 | 保留复制边界、锁与回滚顺序；分配失败返回 `-ENOMEM`。nosync 不新增 workspace 睡眠分配。 |
| `drivers/misc/mediatek/connectivity/wlan/core/gen4m/common/wlan_lib.c` | 对统计循环局部禁止 Clang 展开 | 保持统计内容和遍历次序，避免展开使调用者栈帧膨胀。 |

## 已执行的验证与限制

以下第 1–8 项是此前完成的基线验证，早于后续代码修改，不覆盖新增行为。第 9 项起按执行先后记录后续构建与修复；最新条目覆盖此前已修复的问题，第 10 项的 QEMU 成功推断已撤回。

1. 在真实 ARM64 QEMU `virt` / Cortex-A57 / 2 CPU 的旧行为上复现两个错误：跨粒度 watchpoint 被接受，以及 legacy KEY/ABS 在物理 SYN 后丢失。消费者返回具体失败 stage，不用源文本检查代替行为。
2. 实际 Kconfig 生成确认 `HAVE_PATCHABLE_FUNCTION_ENTRY`、`IO_URING` / `IO_WQ`、Landlock、BPF events、BTF 等选择；THP 消费者配置使用 4 KiB 页、真实 THP、COMPACTION/MIGRATION 与 proc page monitor。最终 THP 场景使用 1 GiB guest RAM：现有 4.14 `hugepage_init()` 在可用总页不足 512 MiB 时自动禁用 THP，512 MiB guest 扣除保留页后会触发此真实策略；没有为测试修改生产策略。
3. 执行 ARM64 `headers_install`，并用导出的用户头而非内核内部 include 编译 BPF消费者；native evdev、BPF、IO、THP、Landlock，以及 ARM32 compat IO/Landlock 消费者与 init 均编译成功。
4. 集成 QEMU smoke 验证 HWBP 边界/缓存回滚/slot 清理、function hook 参数/IPMODIFY/detach、BTF 读取及真实 fentry/fexit 参数/返回值计数和 detach；真实 evdev 读写/ioctl、物理帧持久性/替换/repeat/overlay 前后；io_uring native/compat 的异步 fixed file/buffer、poll/cancel、timer、temporary sigmask 与 pending-request close/exit；Landlock native/compat ABI 1、普通 UID/NNP、deny/allow、stack/fork。独立 1 GiB THP 配置在不改内核策略的情况下验证真实 THP registration/update/deferred retirement、精确 VmPin、ordinary-user memlock 和最终 unpin。
5. 扩展同一 QEMU 到 PCI/NVMe，分别挂载真实 ext4/XFS scratch filesystems，并用第三块已验证未挂载的专用 raw scratch disk。`IORING_SETUP_IOPOLL` 完成 raw block、ext4（offset 512 与 8192）和 XFS 的直接写入/读回及逐字节内容验证；`IORING_OP_TEE` 验证 write-only source/read-only destination 的 `-EBADF`、合法 copy 与源数据保留。
6. 同一 native socket 消费者验证 IPv4/IPv6 legacy packet-options 用户 CMSG、UNIX stream 的 SCM_RIGHTS/`MSG_WAITALL` 分段接收和先前 `MSG_CTRUNC` 保留，以及真实异步 epoll ADD/DEL、嵌套 topology worker 重试与环路 `-ELOOP`。完整集成消费者报告 `STANDARD SMOKE TOTAL failures=0`，所有用户程序 wait status 为 `0`；kernel ring log 同时包含 HWBP/input/function-hook PASS。
7. 当时的 `bash build.sh` 重新编译 `fs/namei.o`，完成 LTO/MODPOST、BTF/BTFIDS、vmlinux/Image/Image.gz 与 dtbs 目标，入口返回成功。`gzip -t` 验证最终镜像完整性；production ELF 包含真实 `.BTF` / `.BTF_ids`，`System.map` 包含六个标准 syscall、BTF 边界和 ftrace 表边界。宿主 `bpftool` 完整解析最终 BTF 的 133,602 个 types，kind 仅到 `DATASEC`，无新增不受支持的 kind。
8. 当时构建日志仍有 `resolve_btfids` 的同名重复 type ID 告警，以及 `should_failslab`、`should_fail_alloc_page`、`__add_to_page_cache_locked` 未解析告警；GNU `elfedit` probe 与 bpfilter 宿主 executable probe 也有诊断。它们没有阻断当时构建；没有通过隐藏日志或跳过 BTFIDS 把告警伪装为消失。上述 QEMU 结果证明已列明的 tracing/BPF 路径，不宣称这些未解析函数也可附着。
9. 本轮以既有产品配置 `out/.config` 和 ZyC clang/LLD 22.0.0、`-j2` 完成 `vmlinux`、`Image.gz`、`dtbs` 目标构建；`out/vmlinux` 为 AArch64 ELF，`gzip -t out/arch/arm64/boot/Image.gz` 通过。BPF JIT/syscall/trampoline、RCU tree、frame_vector 与 input overlay 对象均在本轮重编译；其中 `frame_vector_create()` 现将 `got_ref` 和 `is_pfns` 初始化为 `false`。产品配置关闭 `CONFIG_HUGETLBFS`，因此另用隔离配置启用 `HUGETLBFS` 并成功编译 `mm/hugetlb.o`；产品配置未启用 READ_MB，另在隔离配置启用 `RCU_EXPERT` / `CONFIG_TASKS_TRACE_RCU_READ_MB` 后成功编译 `kernel/rcu/tree.o`。BTFIDs 仍输出重复类型 ID 和未解析符号告警；`aarch64-linux-gnu-elfedit` 缺失和 bpfilter host-link probe skipped 诊断也未阻断构建。
10. 此前使用 QEMU 11.1.1、产品 `Image` 和临时 `frame_vector` 模块，检查两个初始化 flags 及失败后的清理路径；但当时只观察到 `qemu_rc=0`，没有捕获模块 PASS marker 或 guest poweroff 事件。后续 QMP 复核证明，产品内核在 MTK 初始化中 panic 后产生的 `guest-reset` 同样能让带 `-no-reboot` 的 QEMU 以 0 退出。因此撤回该次 `frame_vector` runtime smoke 成功的推断：不能确认 `/init` 或模块曾执行，也没有建立 RED/GREEN 回归。运行成功必须同时具备测试路径的明确 PASS 证据和预期 guest shutdown，不能只检查宿主退出码。
11. 本轮配置确认 `CONFIG_BPFILTER=y`、`CONFIG_BPFILTER_UMH=m`、`CONFIG_USERMODE_DRIVER=y`、`CONFIG_FAULT_INJECTION=y`；`CONFIG_FAILSLAB`、`CONFIG_FAIL_PAGE_ALLOC` 未启用，`CONFIG_DEBUG_FS` 未启用因而 `FAULT_INJECTION_DEBUG_FS` 不会生效，ARM64 也未提供 `HAVE_FUNCTION_ERROR_INJECTION`，所以打开的是 fault-injection 框架，不代表已启用实际 slab/page/function 注入器。BPFILTER 选择 `USERMODE_DRIVER` 后暴露 `task_tgid()` 缺声明，补 `linux/sched/signal.h` 后对象编译通过。
    `CC_CAN_LINK` 已改为运行 `scripts/cc-can-link.sh` 并传入目标 Clang flags；独立探针显示宿主 Clang 可链接、AArch64 目标探针失败。该构建启动时 `aarch64-linux-gnu-elfedit` 尚未安装，Kbuild 因而推导出错误的 `/` 工具链根；安装 binutils 后 elfedit 位于 `/usr/bin`，但复测仍因缺少 AArch64 GCC/libc sysroot 而读到宿主 `/usr/include/stdio.h` 并在 `__float128` 处失败。`build.sh` 只构建 `vmlinux Image.gz dtbs`，而 UMH 配置仍为 `m`，故本轮没有构建/验证 bpfilter 模块或其运行时功能。
    最终 `vmlinux` BTFIDs 仍告警重复的 `path`、`file`、`task_struct`、`seq_file` 类型及未解析的 `should_failslab`、`should_fail_alloc_page`、`__add_to_page_cache_locked`；`resolve_btfids` 对重复名字保留首个 ID，对未解析项写入 0 并继续链接。前两个未解析项分别受 `CONFIG_FAILSLAB`、`CONFIG_FAIL_PAGE_ALLOC` 关闭影响；第三项的具体消失阶段未确认，抽查的重复类型布局相同但未穷尽比较。
    最终 ELF 反汇编显示 ARM64 4 KiB 页、KASAN 关闭时线程栈为 16 KiB；`LZ4_compress_fast` 和 `LZ4_compress_destSize` 各自保留 16,464-byte 栈帧（freestanding LZ4 在栈上分配 stream），超过单线程栈，但未找到它们的 in-tree 调用者，故记为潜在风险而非已复现故障。`wlanDumpAllBssStatistics` 为 3,648 bytes，位于 TX 统计超时触发的路径；KPM `kpm_dispatch` 为 5,264 bytes，包含 user-load 路径缓冲区，均是可达路径的栈压力告警，未证明实际栈溢出。`kernel/params.c` 的临时 `kernel_param` 与 `fs/nomount.c` 的 const actor 初始化告警已修复并做对象编译验证。
12. 后续修复与已运行的专项验证：
    - bpfilter 工具链正例产出静态 AArch64 helper 与 `bpfilter.ko`；`BPFILTER_CC=false` 负例明确报错。`HOSTLDFLAGS` 命令行覆盖曾吞掉 `-static`，修复后同一场景仍产生无动态解释器的目标 ELF。用 QEMU user-mode / Cortex-A57 执行真实目标 helper，验证 get(0) 返回 0、get(1) 与 set(0) 返回 `-ENOPROTOOPT`，关闭请求管道后正常退出；这不是内核模块或 Android forwarder 策略的运行证明，也不表示实验性 bpfilter 已实现完整防火墙。
    - verifier 的两个 fault-injection BTF ID 现在同时受函数白名单能力与各自配置约束；本树 `__add_to_page_cache_locked` 没有对应白名单项，最终 ELF 也没有可解析的独立 FUNC，因此移除该项。真实 ELF fixture 证明 resolver 修复前把合法空 set 误报为 unresolved，修复后空集合写入 count=0、单成员与乱序多成员集合正确写入/排序，而真正缺失的普通类型仍保留告警。
    - 首轮整合 ELF 的 BTF 图验证 `perf_event.rb` 与 `perf_output_handle.rb` 指向 `perf_buffer`，`trace_buffer.buffer` 指向 tracing `ring_buffer`，两者保留不同布局。剩余 `seq_file`、`file`、`path`、`task_struct` 重名变体递归比较未发现不同 aggregate 布局，差异归结于 `bool` typedef 与直接 `_Bool` 的等价表示；没有强行合并或隐藏这些诊断。
    - 宿主直接编译实际 LZ4 源码，完成 extState roundtrip 与 destSize 部分消费验证。HC 的 ASan fixture 覆盖等级 2/9/10/11/12、1–8,192-byte 输入、workspace 大小边界、destSize、流式与超过 4 KiB 的 attached dictionary 路径，逐字节校验解压结果，全部通过。destSize=1 合法地产生不消费输入的空块，不将其误判为压缩故障。

13. 用户允许测试插桩后，独立 `ARCH_VEXPRESS` 配置在 QEMU `virt` / Cortex-A57 / 2 CPU / 1 GiB RAM 中完成核心 smoke；产品配置与产品源码未加入测试桩，也未继续使用 initcall blacklist：
    - 测试镜像关闭 MTK 硬件路径，保留 KSU/KPM、BPFILTER、perf/tracing、LZ4/LZ4HC、crypto、ThinLTO、BTF、4 KiB 页与 VMAP_STACK。仅补齐两个未启用的 vendor 调度依赖：fork ramp 返回源码默认值 0；uclamp 钩子若被调用立即 panic，避免用空实现掩盖依赖。另在测试镜像的核心 text 中放置专用指令靶点，满足 hotpatch 原有地址范围约束，没有放宽生产验证。
    - KPM 用户接口验证 NULL/无效路径、PATH_MAX 边界、1023/1024-byte 参数边界及可选 NULL 参数。hotpatch 验证 4 项与 64 项成功写入、逐项读回、执行与恢复；65 项、64 项重复地址、部分准备后失败及 nosync 非法参数按契约拒绝。第二项 expected 不匹配触发 `-EBUSY`，第一项已经写入的内容被实际回滚；nosync 合法写入与恢复也通过。
    - 仅执行拒绝/回滚场景的模块实例可以卸载；成功 raw hotpatch 后即使恢复原指令，模块仍因 `ever_patched` 安全标记拒绝卸载并返回 `-EBUSY`。测试保留该策略，未为了通过测试清除 pin。没有覆盖 `-EUCLEAN` 修复分支或 slab/page 分配故障注入。
    - perf mmap ring 在该次执行中读取 100 个有效 IP samples / 1,600 bytes；tracing ring 验证真实 payload 写入/消费及空队列。普通 LZ4 完成 roundtrip/容量边界，HC 等级 9–12 的 roundtrip 通过，其中 10–12 覆盖实际 optimal-workspace 路径；crypto LZ4HC 完成压缩/解压及不足输出容量的错误路径。
    - 实际加载 `bpfilter.ko` 并启动嵌入 helper，通过真实管道协议验证健康检查和不支持的命令。保留 `STATIC_USERMODEHELPER=y` 与 `/system_ext/bin/aee_core_forwarder` 路径，测试 rootfs 提供按 argv/cwd 契约执行的 forwarder；这不等于已验证实体 Android forwarder 的策略。
    - 最终同时观察到各项 PASS、`KERNEL_FIXES_SMOKE PASS`、两个用户消费者 wait status=0、smoke 模块加载返回 0，以及 QMP `guest-shutdown`。独立干净输出目录还复现并修复 ThinLTO 模块误调用不存在的 `recordmcount`；bpfilter 与 smoke 模块随后均链接并实际加载成功。

14. 最终使用原产品 `out/.config`、ZyC clang/LLD 22.0.0、AArch64 GCC 静态 helper 和 `make -j4` 完成 `vmlinux Image.gz dtbs modules` 目标。BTF 编码的前次运行超过命令时限；最终通过临时 PAHOLE wrapper 使用 `--jobs=4` 完成，没有关闭 BTF 或跳过 BTFIDS。
    - `gzip -t out/arch/arm64/boot/Image.gz` 通过；`out/vmlinux`、`out/net/bpfilter/bpfilter.ko` 均为 AArch64 ELF，helper 为静态 AArch64 ELF。
    - 最终 BTF 全量解析及 perf/tracing 引用检查通过；不再出现上述三个函数或空集合的 unresolved 告警。`seq_file`、`file`、`path`、`task_struct` 仍有第 12 项所述的重名变体诊断，没有将其屏蔽。
    - 最终 ELF 反汇编得到以下栈帧大小，单位 bytes；没有提高 FRAME_WARN 或扩大线程栈：

    | 函数 | 修复前 | 修复后 |
    | --- | ---: | ---: |
    | `LZ4HC_compress_optimal` | 66,032 | 416 |
    | `kpm_dispatch` | 5,264 | 1,200 |
    | `kpm_compat_hotpatch` | 3,728 | 384 |
    | `kpm_compat_hotpatch_nosync` | 3,696 | 160 |
    | `wlanDumpAllBssStatistics` | 3,648 | 144 |

    完整 ELF 符号表确认两个各占 16,464-byte 栈帧的普通 LZ4 wrapper 不再出现在内核，也没有隔离测试的 `stack_smoke_patch_target`。WLAN 只做了编译与最终机器码验证，未宣称实体 WLAN 运行通过。

此前 QEMU 成功记录只覆盖当时临时消费者实际执行的场景；目标产品配置关闭 `CONFIG_TRANSPARENT_HUGEPAGE`，因此 THP 由独立启用 THP 的 1 GiB guest 验证。NVMe/block/ext4/XFS 均使用 QEMU 提供的真实内核驱动和文件系统路径，不代表实体 UFS/eMMC/DMA 行为。

此前 QEMU 最小启动环境只为未启用的 MTK scheduler 提供两个 vendor 链接符号，不模拟 tracing、IO、Landlock、HWBP 或 input 能力。实体 MTK/GT9886 reset/display-PM、实际 UFS/eMMC 与硬件 DMA、多种 major LSM 的实体策略共存仍须平台验证；不将这些未执行路径计入成功记录。
