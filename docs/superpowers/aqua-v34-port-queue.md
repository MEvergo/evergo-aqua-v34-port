# AquaV3.4 逐提交移植队列

目标：将官方 AquaV3.3（`8ffca656f1f7bb1c9953aa053f8233a8543540dc`）至 AquaV3.4（`d81fee89be1c86979a2421933a0741f55918cc44`）的 **48 条线性提交**逐项审查、移植至当前 evergo 定制内核。私有仓库的完整源码根快照为 `c06481269a1113dc439f7c74b92059af8691221f`（从本地 `fbcac3e375a014823fbe39255e0674740dfdc5c9` 的源码快照导出）；它已包含原始工作树的未提交修改、`mm/vmscan.c` 的 per-zone 修复，以及从外链实体化的本地改动版 SukiSU 内核源码。`lineage-24.0` 默认开发分支是另一条重写历史，不能把它的历史提交混进这 48 条队列。

## 执行约定

- **一条上游提交对应一个新的实现 subagent**。按下面顺序和依赖分批安排；只把文件互不冲突且没有先后依赖的提交放入同一批。每位 agent 只负责自己的 SHA，不得擅自扩展到其他上游提交。控制者拥有集成分支，逐个核对变更并记录状态。
- 比对当前 **实际源码内容**（含已经保存的原未提交修改），而非仅依赖 `git log`。已存在同等修正记为「等价」，不得重复应用。尤其 `mm/vmscan.c` 的 per-zone 修复已在基线快照，不属于以下 48 个待移植提交。
- 必须保留现有 SUSFS、NoMount、SukiSU 的语义和钩子，以及 MTK/XGF/GPU/CMA 的本地定制。遇到会破坏前三者且稍复杂或有实际取舍的冲突时，**停止该冲突部分并向控制者报告**：具体路径/上下文、原补丁意图、本地不变量、可行选项及其代价。控制者先自行分析处理；仍无法可靠裁决则将该提交精确标记「暂缓：原因/路径/依赖」，继续独立任务，最后将所有真正需要用户选择的问题集中询问。禁止伪装成功、删去钩子、以关闭 SELinux 等手段掩盖问题。
- 每一批 subagent **不得运行构建、测试、lint 或格式化器**；控制者集成后统一验证。禁止设备操作、刷写、重启和 ROM 构建。上游 `a184e7d6` 必须以当前 Git 可解析的 **精确 SHA 及其实际父提交**为依据，不用第三方内容代理替代。
- 状态取值：`待派发`、`处理中`、`已合入`、`已有等价实现`、`暂缓（写明原因）`；每条完成后记录本地提交 SHA 或精确阻塞原因。后续任务若依赖暂缓补丁，先标明依赖而不能凭空引入不完整接口。

| # | 上游 SHA | 主题 | 必须满足的前置提交 | 状态 |
|---:|---|---|---|---|
| 01 | `9387a4e13dab74c017379a691061a4c0d06354f5` | power_supply: Create input_suspend node | — | 已合入：`87f07b7faa37`（无效输入明确返回解析错误） |
| 02 | `28123b05c48f3a3f68bd2880799d163817510b1d` | binder: Checkout to android-4.19-stable | — | 已合入：`ca6b8849caa5`，保留已存在的 4.14 Binder API 形式 |
| 03 | `5afd363a10c1e44187095efdabd3cafdd001e884` | binder: Fix 4.19 binder compilation on 4.14 | 02 | 已合入：`6a482eb6ddb6`，补足 eventpoll 头；其余适配已存在且保留 allocator 调试类别 |
| 04 | `7042fefca96282acdaa6d1c89ff28eb59b5f3bb6` | netprio: use css ID instead of cgroup ID | — | 已合入：`6ba8e00c1d1a` |
| 05 | `a184e7d6c259c73c66cc884f65a06e7891508cf8` | BPF-5.10 large import (one-parent, substantive) | 04 | 已合入：`7275a911666a`，855 条上游路径+两处 SukiSU hlist 适配；保留 6 处本地重叠 |
| 06 | `2a866e985f5ee69dd2795860fe5f83f747a612d8` | cgroup ID access via kernfs node | 05 | 已合入：`8db92e04bb9b`，MTK 读取移至原有 RCU 范围内 |
| 07 | `71ceef5bb220e8718181ee583191f67f15cf7bf0` | kernfs inode attribute access | 05 | 已合入：`6cbdbecd42c4` |
| 08 | `0e0433bce60876b0b417e0fd187ed6e2c15ca0e4` | MTK LPM kernfs_create_file arguments | 05、07 | 已合入：`30236ac670a5` |
| 09 | `fe798968a81f74e49e9eda6cf777e32950e5fc56` | Mali redundant __poll_t typedef | — | 已有等价实现：4.14 头文件未定义 `__poll_t`，保留局部兼容 typedef；删除会使 `reader_poll()` 无法编译，未改动源码 |
| 10 | `e5efe77b90f2720465383603156f99b2e817c767` | Drop exit_umh inline; local caller must be resolved | 05 | 已合入：`4db2333f3bf6`、`b243b3600ca0`；仅 USERMODE_DRIVER 启用时清理已注册驱动 |
| 11 | `7b3a94ec99fc5ef73d811e0a01e29d2015ddbc8e` | Cortex-A76 compiler optimization | 05 | 已合入：`32f139228b71`，与上游 Makefile 标志一致 |
| 12 | `0fdc8173e96f5d36597357305b4cbb6f0c319826` | Move stat attributes into vfs_getattr_nosec | — | 已合入：`f18f8abfbffd`，保留 SUSFS 提前返回属性 |
| 13 | `04af80e5f5120a14503c0a8039e249fe33e474d2` | statx DAX attribute | 12 | 已合入：`35b56f571089`，后续 17 将修正属性位重叠 |
| 14 | `c71cfde70ff87617fb8049d3c7cbac4e7f0215af` | Deprecate STATX_ALL | 13 | 已合入：`575a529d5178`，OrangeFS 显式保留原有掩码 |
| 15 | `7c0b56ad9ab9d2c8e7f547b2a3b69f1c7a322274` | statx mount ID | 14 | 已合入：`ebbf9faef8e2`，SUSFS 复用既有挂载 ID 伪装 |
| 16 | `0fd1ca0ee73e8c6ca280e2f2e1f000d5d755eaa0` | statx mount_root | 15 | 已合入：`97592d30891c`，不暴露 SUSFS 伪装挂载边界 |
| 17 | `29a7465fd2653ea835d5cc1fc2961d744d4d97ce` | Fix DAX/MOUNT_ROOT attribute-bit overlap | 16 | 已合入：`383e2c167b49`，NoMount 仅屏蔽 MOUNT_ROOT 不再误屏蔽 DAX |
| 18 | `5ab3aca066f999562b8b8a1e80f8fff546dd1321` | Remove Maple IO Scheduler | — | 已合入：`5e1395830391`，默认 CFQ |
| 19 | `3fc2c50a33860a55370be83c22883ca34860be39` | modpost NOFAIL strndup | — | 已合入：`e4df607c0046`，目标文件与上游一致 |
| 20 | `0aab45864e4950a0c05da0aa5d5e776d24b2c9cf` | modpost match() const qualifier | 19 | 已合入：`e18d05c39975` |
| 21 | `a3970ca73e102de6912deb3c84a8b4d4dcf11511` | Remove stale x86 syscall prototype | — | 已合入：`a83e33309492` |
| 22 | `afab5249b866ba2abe3b7ea6726c9a92a8d883e4` | x86 compat syscall macros | 21 | 已合入：`03df1bca365c`，对应迁移 15 个兼容系统调用入口 |
| 23 | `da9a810b2c77de53ccb0798b0e8f5a3bfe35a867` | x86 compat clone entry | 22 | 已合入：`0d1c1077bcad` |
| 24 | `412c5c2fd76ac1348931d5f712dea065d3f9ac0f` | x86 compat clone _do_fork | 23 | 已合入：`78c24ab2a571`，与上游代码一致 |
| 25 | `fef4466bd4ae7aa2ec66d01f6a1bda57e5beb082` | pidfd creation and cleanup | 05 | 已合入：`ae9c9204b718`，FD 安装延后至最后失败点后 |
| 26 | `ee66522755e6cef28769925bff19b565e4a87af7` | fork early error return | 25 | 已合入：`bcf054fdaeb9`，保留 cpufreq→trace 和 MGLRU 顺序 |
| 27 | `70e60fffbda9782a33dc284f91032fdedaa8fe96` | CLONE_PIDFD parent_tidptr validation | 26 | 已合入：`9b9a0937ce18` |
| 28 | `7084c333e121567533255371aa67f687b01ef5ff` | clone3 core and clone_args | 27、24 | 已合入：`39257675eba0`，补足 x86 compat/do_fork 的 legacy PIDFD 指针和冲突校验 |
| 29 | `38273f9fbd74be179f77106707bc2fc8a844b52b` | Wire clone3 syscall 435 | 28 | 已合入：`1d1bde75fa3d`、`b76e5fe33f84`；补齐 x86 compat_sys_clone3 |
| 30 | `7ed966f471a802cfc8156f2513e7995a885f7a74` | Unsupported-arch clone3 guards | 29 | 处理中：AquaCommit30Clone3Guards |
| 31 | `12f2b25517ca85edad063f480d8f3e6be8f27c5d` | Legacy CLONE_PIDFD with clone3 | 30 | 待派发 |
| 32 | `d32a118be5e77328057c18be352931d0b3bb1aed` | clone_args __ASSEMBLY__ guards | 28 | 已合入：`e22be4939bf9` |
| 33 | `306a9638758d34039eb632779d42c2c170ca35e7` | clone_args kernel-doc | 32 | 已合入：`d916da60c6d1` |
| 34 | `e363cc3a6ae4d9b214704e57dc8613e6fea5970d` | CLONE_CLEAR_SIGHAND | 31、33 | 待派发 |
| 35 | `72dd3629520f194eba24240b6d8143f5f990fd5f` | CLONE_CLEAR_SIGHAND selftest | 34 | 待派发 |
| 36 | `a1ae3900cf263692ba599b7f720f6868165783ae` | clone3 base selftests | 35 | 待派发 |
| 37 | `41abee1fff4bab468da9845c7e0318f5f7417cbd` | clone3 set_tid PID selection | 34 | 待派发 |
| 38 | `050736f6dc5098359427233407a1d6afa0f4f0e1` | clone3 set_tid selftests | 36、37 | 待派发 |
| 39 | `2d2a57e68a5c8d6529efdaf5165945f1e8efeb38` | CAP_CHECKPOINT_RESTORE; include prerequisite CAP_PERFMON=38/CAP_BPF=39 and SELinux classmap entries | 05、37 | 待派发 |
| 40 | `ff1d5976899fbb96aa5aec58a1da1f160df5a4a6` | set_tid checkpoint capability | 39 | 待派发 |
| 41 | `3545eccf9d6ec00ca8f05bfef814dc3afa2fc4a8` | ns_last_pid checkpoint capability | 39 | 待派发 |
| 42 | `5737cbe0f89cdb0f9f15e1ae804c6f7da39229ac` | map_files checkpoint capability | 39 | 待派发 |
| 43 | `c7aa02fede4a47b1ba892b454a6fcfe97d04fab4` | prctl_set_mm permission refactor | — | 已合入：`dfe868e9e237`，保留旧权限检查与 auxv 的错误码优先级 |
| 44 | `01f7e68b52c3f2a5e50a8153d2caa65851039009` | /proc/self/exe checkpoint capability | 39、43 | 待派发 |
| 45 | `150963f8969fb8b257a8af6721a333be23268523` | prctl exe error -EPERM | 44 | 待派发 |
| 46 | `161299f028ca879642c4d85af8f8fd32f1989932` | clone3 checkpoint capability selftest | 38、40 | 待派发 |
| 47 | `4c0d87767fb95c0dc201c5495f5102019baa0df3` | TIOCSLCKTRMIOS checkpoint capability | 39 | 待派发 |
| 48 | `d81fee89be1c86979a2421933a0741f55918cc44` | Enable WALT in everpal defconfig | 18 | 已合入：`9ce4a2b4ad44` |

第一批候选：**01、02、04、09**（上游 diff 的路径集合两两不交集）。下一批依赖实际集成和冲突报告决定，绝不因为后续提交存在就假定复杂前置提交已成功。首次私有备份与最后一次内核构建由控制者验证，不由 subagent 宣称成功。
