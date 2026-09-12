# Liu et al. 2018 PCHS 同机复现实验说明

## 1. 比较目的

本目录中的 PCHS 实现只用于建立一个与本文 V2 **通信方向相同**的 PKI→CLC 性能基准。比较对象为 Jingwei Liu, Lijun Zhang, Rui Sun, Xiaoyong Du, Mohsen Guizani, *Mutual Heterogeneous Signcryption Schemes for 5G Network Slicings*, IEEE Access, 2018, 6: 7854–7863, DOI: 10.1109/ACCESS.2018.2797102 中的 PCHS（PKI sender → CLC receiver）。

该基准不用于声称 Liu 2018 与本文拟采用的任意合法公钥替换 Type-I–Ext 模型具有完全相同的攻击能力。安全模型差异必须在论文比较表和结果讨论中单独标记。

## 2. 忠实保留的论文代数关系

本实现保留下列 PCHS 关系：

- 系统主密钥 `s`，主公钥 `P_pub=[s]P`；
- PKI 发送者私钥 `x_p`，公钥 `PK_p=[x_p^{-1}]P`；
- CLC 接收者部分私钥关系：`T=[t]P`，`gamma=H1(ID,T)`，`d=t+s*gamma mod q`；
- 接收者自选秘密 `x_c`，公开分量 `PK_c1=[x_c]P`；
- 签密：
  - `R1=[k]P`；
  - `h=H2(m,R1)`；
  - `R2=[h]P`；
  - `c=m XOR H3(R2)`；
  - `u=(h-k)*x_p mod q`；
  - `V=[k]PK_c1+T+[gamma]P_pub`；
- 解签密：
  - `R1=[x_c^{-1}](V-[d]P)`；
  - `R2=R1+[u]PK_p`；
  - 恢复消息后重新计算 `h=H2(m,R1)`；
  - 验证 `R1=[h]P-[u]PK_p`。

测试代码独立检查 `dP=T+[gamma]P_pub`、上述 `R1` 恢复关系以及 `R2=[h]P`，不能仅以“明文能够恢复”代替公式一致性检查。

## 3. 工程实例化，不属于原论文新增功能

Liu 2018 用抽象素数阶椭圆曲线加法群描述 PCHS。为了与本文目标机上的固定 GmSSL 环境进行可重复的同机测试，本复现采用：

- GmSSL 的 256-bit SM2 曲线群作为论文抽象群 `G` 的具体工程实例；
- `H1/H2`：域分离 SM3，随后拒绝采样到非零 SM2 标量域元素；
- `H3`：域分离 SM3-KDF，输出与消息等长的掩码；
- 点的哈希输入统一使用 GmSSL 65-byte 非压缩规范编码。

以上是为了把论文抽象哈希/群接口落到与 V2 相同的软件栈；不得在论文中把它写成 Liu 2018 原作者规定的 SM2/SM3 实现，也不得把移植后的毫秒数冒充原论文实验数据。

本复现**没有**把 PCHS 改造成 online/offline 方案，也没有增加证书缓存、预计算、批处理或其他专门针对本文性能指标的优化。

## 4. 代码边界

PCHS 与 V2 使用独立 target：

- `native/include/pchs_liu2018.h`
- `native/src/pchs_liu2018.c`
- `native/tests/test_pchs_liu2018.c`
- `native/bench/bench_pchs_liu2018.c`

PCHS benchmark 不修改 V2 的 signcryption 代码路径，也不得覆盖 2026-09-09 的 V2 正式证据目录 `artifacts/ryzen8845h-ieee-20260909-152244/`。

## 5. 正确性与负向测试

在任何性能计时前必须通过：

1. 0/1/20/128/1024/4096 B 消息往返；
2. 部分私钥等式 `dP=T+[gamma]P_pub`；
3. PCHS `R1/R2` 代数关系；
4. 修改 `c` 后拒绝；
5. 修改 `u` 后拒绝；
6. 修改 `V` 后拒绝；
7. 错误发送者公钥后拒绝；
8. 错误接收者 `x_c` 后拒绝；
9. 错误接收者 `d` 后拒绝。

GitHub Actions 只承担功能可重复性检查，其云端耗时不进入论文同机性能表。

## 6. Windows 正式测试协议

目标是复用 V2 2026-09-09 正式测试的软件口径：

- AMD Ryzen 7 8845H；
- Windows 11；
- GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d`；
- GmSSL `ENABLE_SM9=ON`、`ENABLE_SM2_AMD64=OFF` 的既有安装；
- Release 构建；
- 消息长度 20/128/1024/4096 B；
- 每种消息长度先执行 1000 次完整 PCHS 往返预热；
- 每种消息长度正式执行 1000 次；
- 每次迭代分别记录完整 `pchs_sender_signcrypt` 和 `pchs_unsigncrypt` 的原始纳秒值；
- 不删除异常样本。

运行脚本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_pchs_liu2018_windows.ps1 `
  -GmsslRoot "<与9月9日V2实验相同的GmSSL安装前缀>" `
  -V2Raw "<9月9日artifacts\ryzen8845h-ieee-20260909-152244\raw.csv>"
```

脚本要求当前源码目录是干净的 Git checkout，以便将 PCHS 实现精确绑定到 commit；所有新文件写入新的 `artifacts/pchs-liu2018-ryzen8845h-<timestamp>/` 目录。

## 7. 原始数据结构

PCHS `raw.csv` 与 V2 使用同一列结构：

```text
run_id,commit,gmssl_commit,message_bytes,phase,iteration,ns
```

正式数据应包含：

`4 message sizes × 2 phases × 1000 iterations = 8000` 条样本。

`scripts/summarize_pchs_liu2018.py` 从 raw CSV 计算：

- n；
- mean；
- median；
- sample standard deviation；
- nearest-rank P95。

不允许手工把毫秒值写进 summary。

## 8. 预先固定的三个比较指标

### 8.1 主要指标：消息到达后的发送端时延

将 V2 `online_signcrypt` 与 PCHS 完整 `pchs_sender_signcrypt` 比较：

```text
online_reduction_pct
= (T_PCHS_signcrypt - T_V2_online) / T_PCHS_signcrypt × 100%
```

这是本文 online/offline 设计最直接对应的指标，因此在看到 PCHS 实测结果之前就预先固定，不能事后根据结果更换主指标。

### 8.2 发送端总成本

```text
sender_total_delta_pct
= (T_V2_sender_total - T_PCHS_signcrypt) / T_PCHS_signcrypt × 100%
```

正值表示 V2 发送端总成本更高，负值表示 V2 总成本更低。不得因为结果对本文不利而省略。

### 8.3 接收端解签密成本

```text
unsigncrypt_delta_pct
= (T_V2_unsigncrypt - T_PCHS_unsigncrypt) / T_PCHS_unsigncrypt × 100%
```

同样保留不利结果。

`scripts/compare_v2_pchs.py` 只从两个 raw CSV 计算上述指标，并强制检查两组原始数据的 `gmssl_commit` 相同。

## 9. 可以与不可以写入论文的结论

在 Ryzen 7 8845H 正式 PCHS raw CSV 产生并通过完整性核验之前，只能写：

- 已完成同方向基准实现和正确性验证；
- 比较指标、平台和计时边界已经预先固定；
- 跨方案提升百分比待本机正式实测。

不能写：

- “本文比 Liu 2018 快 X%”；
- “本文总成本优于 Liu 2018”；
- “本文安全模型与 Liu 2018 完全相同”；
- 云端 CI 的计时结果作为 Ryzen 7 8845H 论文性能数据。
