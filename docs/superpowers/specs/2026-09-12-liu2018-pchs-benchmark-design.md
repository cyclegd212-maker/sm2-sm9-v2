# Liu 2018 PCHS 同机基准设计规格

日期：2026-09-12

## 1. 目标

在不修改现有 V2 方案源码、也不覆盖 2026-09-09 正式实验数据的前提下，为 Jingwei Liu 等人在 IEEE Access 2018 论文 *Mutual Heterogeneous Signcryption Schemes for 5G Network Slicings* 中的 PCHS（PKI→CLC）方向新增一个独立、可审计、可重复运行的原生 C 参考实现与 benchmark。

主要目标是取得与 V2 同一台 Ryzen 7 8845H、同一 GmSSL 固定提交、同一 Release 构建及同一计时方法下的真实原始计时数据，从而回答：V2 的消息到达后在线签密时延相对于一个同方向 PKI→CLC 基准究竟降低多少。

本基准只用于性能比较，不把 Liu 2018 PCHS 的安全模型视为与本文拟采用的任意合法公钥替换 Type-I–Ext 模型完全相同。

## 2. 固定文献算法

PCHS 原文方向：PKI 发送者 → CLC 接收者。

### 2.1 Setup

在阶为素数 q 的加法群 G 上取生成元 P。主私钥为 s，主公钥为

`P_pub = [s]P`。

哈希函数：

- `H1 : {0,1}* × G -> Z_q*`
- `H2 : {0,1}^n × G -> Z_q*`
- `H3 : G -> {0,1}^n`

### 2.2 PKI-KG

发送者选择 `x_p in Z_q*`，私钥 `sk_p = x_p`，公钥按论文记法为

`PK_p = [x_p^{-1}]P`。

实现中必须保留该论文关系，不能为了与常见公钥定义一致而改成 `[x_p]P`。

### 2.3 CLC-KG

KGC 随机选择 `t in Z_q*`：

- `T = [t]P`
- `gamma = H1(ID_c, T)`
- `d = t + s*gamma mod q`

用户选择 `x_c in Z_q*`：

- 完整私钥 `(x_c, d)`
- 公钥 `(T, PK_c1)`，其中 `PK_c1 = [x_c]P`

并验证恒等式：

`[d]P = T + [gamma]P_pub`。

### 2.4 PCHS Signcrypt

对消息 `m`：

1. 随机选择 `k in Z_q*`；
2. `R1 = [k]P`；
3. `h = H2(m, R1)`；
4. `R2 = [h]P`；
5. `c = m XOR H3(R2)`；
6. `u = (h-k)*x_p mod q`；
7. `V = [k]PK_c1 + T + [gamma]P_pub`；
8. 输出 `sigma = (c,u,V)`。

### 2.5 PCHS Unsigncrypt

接收者使用 `(x_c,d)` 与发送者 `PK_p`：

1. `R1 = [x_c^{-1}](V - [d]P)`；
2. `R2 = R1 + [u]PK_p`；
3. `m = c XOR H3(R2)`；
4. `h = H2(m,R1)`；
5. 接受当且仅当 `R1 = [h]P - [u]PK_p`。

正确性必须通过原文三条等式逐项测试，而不是只检查一次端到端返回值。

## 3. 实现口径

### 3.1 曲线与库

- 使用现有固定 GmSSL 提交 `24ae482701a7b124826c382fffc55c19f76d475d`。
- 使用 GmSSL SM2 的 256-bit 素数阶椭圆曲线群作为论文抽象群 G 的具体实例。
- 该选择是“相同安全量级下的工程实例化”，不是声称 Liu 原论文规定必须使用 SM2 曲线。
- 不使用 SM9 配对接口实现 PCHS，因为 PCHS 本身是无配对方案。

### 3.2 哈希实例化

- `H1`、`H2`：SM3 哈希后按 SM2 曲线阶归约到非零标量；采用固定 domain separation 字符串。
- `H3`：SM3-KDF，从规范编码的 `R2` 派生与消息等长的掩码。
- domain separation 必须固定并写入源码，防止 `H1/H2/H3` 误用。

### 3.3 规范编码

所有点在进入哈希或 KDF 前使用同一种 GmSSL 公共编码接口。实现不得把 C 结构体内存布局直接作为哈希输入。

### 3.4 独立性

新增 PCHS 文件，原则上不修改 V2 生产逻辑：

- `native/include/pchs_liu2018.h`
- `native/src/pchs_liu2018.c`
- `native/tests/test_pchs_liu2018.c`
- `native/bench/bench_pchs_liu2018.c`

只修改 `native/CMakeLists.txt` 以增加独立 target。

## 4. 正确性与负向测试

### 4.1 正确性

消息长度：`0, 1, 20, 128, 1024, 4096` B。

必须验证：

- `Unsigncrypt(Signcrypt(m)) == m`
- `[d]P == T + [gamma]P_pub`
- `R1_recovered == [k]P`
- `R2_recovered == [h]P`
- 最终验证等式成立

### 4.2 篡改拒绝

分别修改：

- `c`
- `u`
- `V`
- 发送者 `PK_p`
- 接收者 `x_c`
- 接收者 `d`

均必须导致拒绝或恢复结果不被接受。

## 5. Benchmark 口径

保持与 2026-09-09 V2 正式实验尽可能一致：

- Windows 11 / Ryzen 7 8845H；
- GmSSL 固定提交不变；
- Release 构建；
- `warmup = 1000`；
- 每组 `iterations = 1000`；
- 消息长度 `20, 128, 1024, 4096` B；
- Windows 使用 `QueryPerformanceCounter`；
- raw CSV 不删除异常值。

PCHS phase 至少包括：

- `pchs_sender_signcrypt`
- `pchs_unsigncrypt`

并可额外记录：

- `pchs_setup`
- `pchs_receiver_keygen`

论文主比较只使用已预先定义的两个协议关键阶段：发送者 signcrypt 与 unsigncrypt。

## 6. 公平比较规则

### 6.1 预先固定主要指标

主要指标：V2 的消息到达后在线签密时延 vs PCHS 完整 Signcrypt 时延。

计算：

`online_reduction = (T_pchs_signcrypt - T_v2_online) / T_pchs_signcrypt * 100%`。

### 6.2 同时公开不利指标

必须同时报告：

- V2 `sender_total` vs PCHS `signcrypt`
- V2 `unsigncrypt` vs PCHS `unsigncrypt`
- 两方案序列化通信开销

不得因为某一项对 V2 不利而省略。

### 6.3 不进行的比较

- 不把文献公开的 Raspberry Pi 毫秒数与 Ryzen 7 8845H 结果直接混算；
- 不把“操作数 × V2 基础操作时间”的估算伪装成完整协议实测；
- 不把 PCHS 视为与本文 Type-I–Ext 模型安全能力完全相同；
- 不静默添加 online/offline 预计算改造来降低 PCHS 的发送时延。

PCHS 第一轮 benchmark 必须忠实实现原文 Signcrypt 算法。

## 7. 数据与证据

新结果必须写入新的 artifact 目录，禁止覆盖：

`artifacts/ryzen8845h-ieee-20260909-152244/`

建议新 run id：

`ryzen8845h-liu2018-pchs-YYYYMMDD-HHMMSS`

每条 raw 数据必须含：

- run_id
- implementation (`liu2018_pchs`)
- source_id (`doi:10.1109/ACCESS.2018.2797102`)
- gmssl_commit
- message_bytes
- phase
- iteration
- ns

汇总输出 `n/mean/median/stdev/P95`。

## 8. 停止条件

遇到以下情况不得产生“真实优势”百分比：

- GmSSL 公共 SM2 底层 API 无法忠实实现论文所需任意点标量乘/点加减/标量逆；
- PCHS 正确性等式无法通过；
- benchmark 与正确性测试使用不同算法路径；
- 本机运行时 GmSSL 提交、构建配置或计时方法发生未记录改变；
- 只有云端或其他机器数据，而没有用户 Ryzen 7 8845H 原始样本。

只有全部正确性与证据检查通过后，才允许计算并写入跨方案百分比。