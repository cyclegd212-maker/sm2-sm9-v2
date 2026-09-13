# Gong 2025 PKI→CLC 同机基准设计规格

日期：2026-09-13

## 1. 目标

在不修改现有 V2 方案实现、不覆盖 2026-09-09 V2 正式实验数据、也不改动已冻结的 Liu 2018 PCHS 证据包的前提下，为 Bei Gong 等人在 IEEE Transactions on Network Science and Engineering 2025 论文 *Multi-Heterogeneous Signcryption Scheme for Next Generation Slicing Networking* 中的 PKI→CLC 分支建立独立、可审计、可重复运行的原生 C 同机基准。

主要目标是取得与 V2、Liu 2018 PCHS 相同 Ryzen 7 8845H、相同固定 GmSSL 提交、相同 GCC/Release 构建和相同原始计时方法下的真实数据，从而量化 V2 在线签密阶段相对于一个近期 PKI→CLC 基准的真实时延差异。

本基准仅用于性能比较。Gong 2025 正式安全证明选择 PKI→IBC 作为案例，并未为 PKI→CLC 分支单独建立 CLC Type-I/Type-II 归约，因此不得把该方案表述为与本文拟采用安全模型等价的安全基准。

## 2. 固定文献算法

### 2.1 群与系统密钥

论文在素数阶加法循环群 G 上定义生成元 P，系统主密钥 s∈Zq*，系统公钥：

`P_pub = [s]P`。

### 2.2 PKI 发送者

发送者选择 `x_S ∈ Z_q*`：

- 私钥：`SK_S = x_S`
- 公钥：`P_S = [x_S^{-1}]P`

该逆元公钥关系必须严格保留，不得改写为常见的 `[x_S]P`。

### 2.3 CLC 接收者

接收者选择 `x_R ∈ Z_q*`，生成：

- `P_R = [x_R]P`

KGC 选择 `r_R ∈ Z_q*`：

- `R_R = [r_R]P`
- `h_R = H1(ID_R, R_R, P_R)`
- `d_R = r_R + s*h_R mod q`
- `X_R = [h_R^{-1}]R_R`

接收者完整私钥：

- `SK_R = (x_R, d_R)`

公开信息：

- `PK_R = (P_R, R_R, X_R)`

必须验证密钥关系：

`[d_R]P = R_R + [h_R]P_pub`。

### 2.4 PKI→CLC Signcryption

对消息 `m`：

1. 选择 `a ∈ Z_q*`；
2. `T1 = [a]P_S`；
3. 计算 `h_R = H1(ID_R, R_R, P_R)`；
4. 计算 `B_R = [h_R^{-1}]P_R + X_R + P_pub`；
5. 计算标量 `z = a*h_R*x_S^{-1} mod q`；
6. `T2 = [z]B_R`；
7. `c = m XOR H2(T2)`；
8. `h = H4_PKICLC(ID_S, ID_R, P_S, P_R, R_R, X_R, P_pub, c, T1)`，严格对应 Gong 2025 Equation (5) 中 `F(PK_S)=1, F(PK_R)=3` 的分支；
9. `S = a + h*x_S mod q`；
10. 输出 `sigma = (c, S, T1)`。

为保持与论文 Table IV 的 `2A+3M` 口径一致，基准实现必须执行论文给出的 PKI→CLC 路径，不得用正确性关系进行跨步骤代数化简以减少点乘或点加。

### 2.5 PKI→CLC Unsigncryption

接收者：

1. 重算 `h = H4_PKICLC(ID_S, ID_R, P_S, P_R, R_R, X_R, P_pub, c, T1)`；
2. `T1_prime = [S]P_S - [h]P`；
3. 检查 `T1_prime == T1`，失败则返回拒绝；
4. `T2_prime = [x_R + d_R]T1_prime`；
5. `m = c XOR H2(T2_prime)`；
6. 输出 m。

正确性测试必须显式验证：

- `T1_prime == T1`
- `T2_prime == T2`
- `Unsigncrypt(Signcrypt(m)) == m`

## 3. 工程实例化口径

### 3.1 固定密码库与曲线

- GmSSL commit 固定为 `24ae482701a7b124826c382fffc55c19f76d475d`。
- 使用 GmSSL SM2 256-bit 素数阶椭圆曲线群实例化 Gong 论文的抽象加法群 G。
- 该实现应描述为 Gong PKI→CLC 的 faithful algebraic reimplementation / adapted same-platform implementation，不得称为作者原平台或原代码复现。
- 不使用 SM9 pairing API，因为 Gong PKI→CLC 分支不需要 pairing。

### 3.2 哈希实例化

- `H1`: SM3 + 固定 domain separation，输入为规范编码后的 `ID_R || R_R || P_R`，输出归约为非零 SM2 标量。
- `H2`: SM3-KDF，对规范编码的 `T2` 派生与消息等长的掩码。
- `H4_PKICLC`: SM3 + 独立 domain separation，输入按固定顺序编码为 `ID_S || ID_R || P_S || P_R || R_R || X_R || P_pub || c || T1`，输出归约为非零 SM2 标量。
- 不把 C 结构体原始内存直接输入哈希；所有点均使用统一规范编码。

### 3.3 与既有基准的隔离

从 `benchmark-liu2018-pchs` 最新稳定提交创建：

`benchmark-gong2025-pki-clc`

新增文件原则上仅包括：

- `native/include/gong2025_pki_clc.h`
- `native/src/gong2025_pki_clc.c`
- `native/tests/test_gong2025_pki_clc.c`
- `native/bench/bench_gong2025_pki_clc.c`
- `scripts/summarize_gong2025.py`
- `scripts/compare_v2_gong2025.py`
- `scripts/run_gong2025_windows.ps1`
- `docs/benchmark/GONG2025_PKI_CLC_REPRODUCTION.md`

允许修改：

- `native/CMakeLists.txt`
- Gong 专用 CI workflow / `.gitignore`（仅为新增 build 目录）

禁止修改 V2 密码实现、PCHS 实现以及已冻结 artifact 目录。

## 4. 正确性与负向测试

消息长度：`0, 1, 20, 128, 1024, 4096` B。

必须验证：

- `[d_R]P == R_R + [h_R]P_pub`
- `T1_prime == T1`
- `T2_prime == T2`
- `Unsigncrypt(Signcrypt(m)) == m`

分别篡改并要求拒绝：

- `c`
- `S`
- `T1`
- PKI 发送者公钥 `P_S`
- CLC 接收者 `x_R`
- CLC 接收者公开分量 `P_R`
- CLC 接收者公开分量 `R_R`
- CLC 接收者公开分量 `X_R`

对密钥生成中的零分母/零标量情况执行重采样，不得把极小概率合法随机事件暴露为不可解释的崩溃。

## 5. Benchmark 口径

保持与 V2 和 Liu 2018 正式实验一致：

- Windows 11；
- AMD Ryzen 7 8845H；
- MSYS2 UCRT64 GCC 16.2.0；
- GmSSL 固定提交不变；
- Release；
- Windows `QueryPerformanceCounter`；
- `warmup = 1000`；
- 每组 `iterations = 1000`；
- 消息长度 `20, 128, 1024, 4096` B；
- raw CSV 不删除异常值。

Gong phase 固定为：

- `gong2025_sender_signcrypt`
- `gong2025_unsigncrypt`

因此正式 Gong 原始样本总数必须为：

`4 × 2 × 1000 = 8000`。

每个 `(message_bytes, phase)` 必须恰好 1000 条，`BAD_GROUPS=0`。

## 6. 公平比较规则

### 6.1 主要指标

预先固定：V2 消息到达后的 `online_signcrypt` 与 Gong 完整 PKI→CLC Signcrypt 对比。

`online_reduction = (T_gong_signcrypt - T_v2_online) / T_gong_signcrypt * 100%`。

### 6.2 强制公开的不利指标

同时报告：

- V2 `sender_total` vs Gong `signcrypt`
- V2 `unsigncrypt` vs Gong `unsigncrypt`
- V2 和 Gong 序列化通信开销

不得因为结果不利于 V2 而隐藏。

### 6.3 禁止事项

- 不把 Gong 论文 Pypbc/Python 实验时间与 Ryzen 8845H 的 V2 毫秒数直接混算；
- 不把理论操作数乘以单次基础操作时间伪装成完整协议实测；
- 不把 Gong PKI→CLC 说成与本文 Type-I/II 安全模型等价；
- 不静默优化 Gong 算法减少论文规定的点乘/点加；
- 不修改或重新生成已冻结的 Liu/V2 证据包。

## 7. 证据格式

新结果写入新的 timestamp artifact 目录，例如：

`artifacts/gong2025-pki-clc-ryzen8845h-YYYYMMDD-HHMMSS/`

至少保存：

- `raw.csv`
- `summary.csv`
- `comparison.csv`
- `environment.json`
- `build.log`
- `test.log`
- `benchmark.log`

每条 raw 必须包含：

- `run_id`
- Gong source commit
- `gmssl_commit`
- `message_bytes`
- `phase`
- `iteration`
- `ns`

环境记录额外固定：

- `implementation = gong2025_pki_clc`
- `source_id = doi:10.1109/TNSE.2025.3571867`

## 8. 停止条件

出现以下任一情况，停止并不得产生“真实提升百分比”：

- 无法用 GmSSL 公共/稳定低层 API 忠实实现论文 `2A+3M` / `A+3M` 路径；
- 密钥正确性、`T1`、`T2` 等式或端到端往返任一失败；
- benchmark 与正确性测试走不同算法实现路径；
- 需要通过代数化简改变 Gong 原算法才能运行；
- 本机正式运行时 GmSSL commit、GCC、Release 或计时方法发生未记录变化；
- 只有 CI/云端数据而没有用户 Ryzen 7 8845H 原始样本。

只有正确性、负向测试、版本记录与 8000 条本机样本全部核验通过后，才允许将跨方案百分比写入论文。
