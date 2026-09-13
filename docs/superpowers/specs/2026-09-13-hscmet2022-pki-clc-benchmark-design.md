# HSC-MET 2022 PKI→CLC 同机基准设计规格

日期：2026-09-13

## 1. 目标

在现有 V2、Liu 2018 PCHS、Gong 2025 基准工程基础上，增加 Yang et al. 2022 PLOS ONE HSC-MET 的 PKI→CLC 分支作为第三个同方向基准。该方案支持 multi-ciphertext equality test (MET)，因此仅作为“功能增强型补充基准”，不得宣称与本文功能集合完全相同。

正式比较仍使用同一 Ryzen 7 8845H、GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d`、MSYS2 UCRT64 GCC 16.2.0、Release、QueryPerformanceCounter、20/128/1024/4096 B、1000 warmup + 1000 measured。

## 2. 原论文构造

论文 DOI：`10.1371/journal.pone.0274695`。

### 2.1 Setup

- 素数阶加法群 `G=<P>`，阶 `q`。
- 主密钥 `s∈Z_q*`，系统公钥 `PK=[s]P`。
- 最大 MET 数 `n`。
- 哈希：`H1:{0,1}*→Z_q*`，`H2:G→{0,1}^{2l}`，`H3:G→{0,1}^{nl}`，`H4:{0,1}*→{0,1}^λ`。

本基准固定最小有意义 MET 配置：`n=2, k=2`。

### 2.2 PKI sender

发送者选择 `s_p∈Z_q*`：

- `SK_p=s_p`
- `PK_p=[s_p]P`

### 2.3 CLC receiver

KGC 选择 `s_1∈Z_q*`：

- `PK_c1=[s_1]P`
- `SK_c1=s_1+s·H1(ID_c) mod q`

用户选择 `s_2∈Z_q*`：

- `SK_c2=s_2`
- `PK_c2=[s_2]P`

完整私钥 `(SK_c1,SK_c2)`，完整公钥 `(PK_c1,PK_c2)`。

必须验证：`[SK_c1]P = PK_c1 + [H1(ID_c)]PK`。

### 2.4 n=k=2 的 Signcryption

原论文一般形式保留；在 `n=k=2` 时：

1. `f_0,2 = H1(m || 2)`。
2. `f_1,2 = H1(m || 2 || f_0,2)`。
3. `f_2(x)=f_0,2 + f_1,2·x mod q`。
4. 随机选 `r,X∈Z_q*`。
5. `Y=[SK_p](PK·H1(ID_c)+PK_c1)`。
6. `R=[r]PK_c2`。
7. `C1=[r]P`。
8. `C2=(m||r) XOR H2(Y) XOR H2(R)`。
9. `C3=(X||f_2(X)) XOR H3(R)`。
10. `C4=H4(C1||C2||C3||f_0,2||f_1,2||R||2)`。
11. 输出 `δ=(C1,C2,C3,C4,k=2)`。

不得通过代数化简跳过论文规定的点乘/哈希路径。

### 2.5 n=k=2 的 Unsigncryption

1. `Y'=[SK_c1]PK_p`。
2. `R'=[SK_c2]C1`。
3. 恢复 `m'||r'=H2(Y') XOR H2(R') XOR C2`。
4. 重算 `f'_0,2=H1(m'||2)`、`f'_1,2=H1(m'||2||f'_0,2)`。
5. 从 `C3 XOR H3(R')` 解析 `X'||v'`。
6. 验证 `C1=[r']P`。
7. 验证 `v'=f'_0,2+f'_1,2·X' mod q`。
8. 验证 `C4=H4(C1||C2||C3||f'_0,2||f'_1,2||R'||2)`。
9. 全部成立返回 `m'`，否则返回 `⊥`。

## 3. GmSSL 同平台实例化

- 抽象群 G 实例化为 GmSSL SM2 256-bit 素数阶群。
- 所有点使用 65-byte uncompressed canonical encoding 进入哈希。
- 所有标量序列化为固定 32-byte big-endian。
- `H1`：SM3 + domain separation + length framing，输出 rejection-sampled nonzero SM2 scalar。
- 原论文 `H2` 的输出长度按 `(message_len + 32)` 适配，以支持现有 20/128/1024/4096 B 测试消息；实现为 SM3-KDF(point)。这是“variable-message-length adapted same-platform implementation”，必须在文档中披露。
- `H3` 在 `n=2` 时固定输出 64 bytes，对应 `X || f_2(X)`。
- `H4` 使用 SM3，输出 32 bytes。
- 不实现/计时 Test 阶段；Signcrypt 仍完整生成 MET 所需 `C3,C4`，Unsigncrypt 仍完整验证这些字段，因此没有移除 MET 对 signcryption/unsigncryption 的真实成本。

## 4. API 和数据结构

新增：

- `native/include/hscmet2022.h`
- `native/src/hscmet2022.c`
- `native/tests/test_hscmet2022.c`
- `native/bench/bench_hscmet2022.c`

主要结构：master key、public params、PKI sender、CLC receiver、ciphertext。ciphertext 字段至少包含 `C1`, dynamic `C2`, fixed 64-byte `C3`, 32-byte `C4`, `k=2`。

## 5. 正确性与负向测试

消息长度：`0,1,20,128,1024,4096` B。

必须验证：

- `PK_p=[SK_p]P`
- `[SK_c1]P = PK_c1 + [H1(ID_c)]PK`
- `Y=Y'`
- `R=R'`
- `Unsigncrypt(Signcrypt(m))=m`

负向测试：分别篡改 `C1/C2/C3/C4/k`、sender `PK_p`、receiver `SK_c1/SK_c2`，必须拒绝或无法恢复原文。公钥分量不是 Unsigncrypt 的直接输入时，不强行增加原论文不存在的密钥一致性验证。

## 6. Benchmark

正式 phases：

- `hscmet2022_sender_signcrypt`
- `hscmet2022_unsigncrypt`

正式 raw：`4×2×1000=8000`，每组恰好1000，`BAD_GROUPS=0`。

主要指标：

`online_reduction=(T_hscmet_signcrypt-T_v2_online)/T_hscmet_signcrypt*100%`。

同时强制报告：

- V2 sender_total vs HSC-MET signcrypt
- V2 unsigncrypt vs HSC-MET unsigncrypt
- 功能差异：HSC-MET支持MET，V2不支持；不得把时延优势描述为同功能绝对优势。

## 7. 证据目录

`artifacts/hscmet2022-pki-clc-ryzen8845h-YYYYMMDD-HHMMSS/`

保存 `raw.csv`, `summary.csv`, `comparison.csv`, `environment.json`, `build.log`, `test.log`, `benchmark.log`。

环境记录固定：

- `implementation=hscmet2022_pki_clc_n2_k2`
- `source_id=doi:10.1371/journal.pone.0274695`
- `n=2`, `k=2`

## 8. 停止条件

若无法在不改变核心代数路径的前提下完成 roundtrip/验证，或需要删除 MET 字段才能运行，立即停止，不产生性能百分比。CI/云端结果不能替代用户 Ryzen 7 8845H 的正式原始样本。