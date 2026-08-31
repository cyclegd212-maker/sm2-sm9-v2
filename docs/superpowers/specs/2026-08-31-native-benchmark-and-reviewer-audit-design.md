# SM2-SM9 V2 原生实现、实测与审稿攻击设计规格

日期：2026-08-31

## 1. 目标

在不改变 V2 论文核心密码构造的前提下，同时完成两条工作流：

1. **密码学审稿人级安全审计**：主动攻击 Type-I-KSR、Type-II、CCA 解签密 Oracle、HMAC 绑定、SM3-KDF/ROM 建模和不可伪造性定义，形成可直接回写论文的 Major/Minor Concern–Resolution 记录。
2. **投稿级完整密码实现与实测**：保留现有 Python 版本作为 reference implementation；新增基于 GmSSL 3.x 的 native C 实现、完整负向测试、GitHub Actions 真实运行、原始 CSV/环境/日志归档，并为后续 Ryzen 7 8845H 投稿平台实测提供同一套可复现入口。

成功标准不是“生成毫秒数”，而是：每一个性能数字都能够追溯到 **V2 仓库 commit + GmSSL commit + 编译参数 + 环境记录 + 原始 CSV + 汇总 CSV + 日志**。

## 2. 固定密码构造

论文方向保持：

`SM2/PKI sender A -> enhanced SM9 receiver B`。

V2 接收端：

- KGC 生成 SM9 身份私钥 `d_B`；
- 接收者独立生成用户秘密 `x_B`；
- `X_B = [x_B]Q_B`；
- 发送者离线选 `rho` 并计算：
  - `U = [rho]Q_B`
  - `Z_1 = g^rho`
  - `Z_2 = [rho]X_B`
- `SM3-KDF(Z_1 || Z_2 || ctx) -> K_E || K_M`；
- 消息加密使用域分离的 SM3-KDF 密钥流与 XOR；
- SM2 在离线阶段预计算完整 nonce `k` 和 `R=[k]G`；
- 在线阶段仅完成消息相关 SM3、SM2 标量模运算、XOR 和 HMAC-SM3；
- HMAC-SM3 绑定规范 signcryption transcript 与具体随机化 SM2 签名。

不重新引入 SM4、PoP、RA、epoch、时间戳、重放缓存。

## 3. 安全审稿工作流

### 3.1 Type-I-KSR

明确把论文安全声明限定为 **Known-Secret Replacement**：攻击者可选择 `x'_B` 并用 `X'_B=[x'_B]Q_B` 替换挑战用户公开因子，因此知道替换秘密值并能直接恢复 `Z_2=[x'_B]U`；机密性仅依赖其不能恢复 SM9 身份因子 `Z_1`。

必须在论文中增加：

- 与经典 certificateless Type-I ReplacePublicKey 的强弱比较；
- 明确本模型更弱，不得使用“standard Type-I”或“arbitrary public-key replacement”措辞；
- 解释其工程语义：攻击者完全控制替换记录对应的用户秘密，但替换可能造成 DoS；本文声明机密性，不声明替换后的可用性；
- 如不能进一步提升到经典任意替换模型，标题与摘要统一写成 `known-secret public-key replacement`。

### 3.2 Type-II CDH

保留当前缩放嵌入：诚实随机采样挑战 `h*=H_1(ID*)`，令 `c=h*+s mod q`，并嵌入：

- `Q_B*=cP`
- `U*=c[a]P`
- `X_B*=c[b]P`
- `Z_2*=c[ab]P`

当关键 KDF 查询命中真实 `Z_2*` 时，输出 `[c^{-1}]Z_2*=[ab]P`。

证明必须显式处理：

- `c=0` 的中止概率 `1/q`；
- 挑战身份猜测损失；
- 关键 KDF 查询索引猜测损失；
- 随机预言机表一致性；
- Type-II 已知主密钥 `s` 时挑战 `H_1` 输出仍与真实分布一致；
- 运行时间损失与查询次数上界。

### 3.3 解签密 Oracle 与 CCA

Type-II/Type-I 的 UnSC 模拟均分层处理：

1. 若规范消息 `mu` 从未由 signcryption oracle 签过，但出现新的有效 SM2 签名，则计入 SM2-EUF-CMA bad event；
2. 若 `mu` 已签过但出现不同的随机化 SM2 签名并同时通过 HMAC，则计入 HMAC 伪造 bad event；
3. 对 signcryption oracle 正常生成且记录过的 transcript 直接查表回答；
4. 挑战 ciphertext 本身及等价禁止查询按游戏新鲜性规则拒绝。

不得把“同一消息的新随机化 SM2 签名”错误归入普通 EUF-CMA；若论文不证明 strong ciphertext unforgeability，必须明确只声明普通消息级 EUF-CMA。

### 3.4 HMAC multi-key

每个会话产生独立 `K_M`，因此论文中的 HMAC 安全项不能直接写单密钥裸 advantage。两种允许写法：

- 使用 multi-user/multi-key PRF/UFCMA 定义；或
- 猜测被伪造会话，并显式给出至多 `q_sc` 量级的归约损失。

论文最终统一采用一种写法，避免混用。

### 3.5 SM3-KDF 与随机预言机

论文必须写成：

> domain-separated SM3-KDF instances are modeled as random oracles in the proof.

不得把“SM3-KDF 标准算法”本身陈述为已经被证明等价于随机预言机。

Type-I 对 `Z_1` 的安全基础必须继续下钻到已有 SM9 KEM/IBE 安全结果或相应 `q-BDHI` 类基础假设；若无法严密对接，则保留“模块化假设”标签并降低定理措辞，不得把需要证明的核心困难重新命名后当成标准假设。

## 4. 实现架构

### 4.1 双实现结构

保留：

- `src/v2_scheme.py`：Python reference implementation，仅用于方程对照、功能验证和研究原型。

新增：

- `native/include/v2_scheme.h`
- `native/src/v2_scheme.c`
- `native/tests/test_v2.c`
- `native/bench/bench_v2.c`
- `native/CMakeLists.txt`

native 版本以 **固定 commit 的 GmSSL 3.x** 作为正式实验密码库；不得使用当前旧 `gmssl-python` 的性能作为投稿数据。

### 4.2 GmSSL 接口原则

优先直接调用 GmSSL 已公开的 SM2/SM3/HMAC-SM3/SM9 API；V2 所需额外 SM9 运算通过公开 `sm9_z256` 群接口完成，包括：

- SM9 G1 点乘；
- SM9 GT 幂；
- SM9 pairing；
- 点/GT 的规范字节编码。

如果某个所需底层函数未在稳定公开头文件中暴露，则不得通过复制私有实现或未文档化符号“硬接”；优先：

1. 找到公开等价 API；
2. 在仓库内写最小 adapter；
3. 若仍不可行，记录为 blocker 并调整 native 方案，而不是伪造兼容性。

### 4.3 一次性 token

native API 明确实现 token 生命周期：

- `READY -> CONSUMED`；
- OnlineSigncrypt 在任何消息相关运算开始前原子消费；
- SM2 retry 条件触发也保持 `CONSUMED`；
- 任何重复使用返回错误；
- token 敏感数据用后清零。

不声明抵抗完整 offline-token 泄漏；论文和实现文档均写明该安全边界。

## 5. TDD 与测试设计

实现顺序必须先写测试、确认失败，再写 production code。

### 5.1 正确性测试

- `UnSC(SC(M)) == M`，消息长度覆盖 0/1/20/128/1024/4096 B；
- `Z_1' == Z_1`；
- `Z_2' == Z_2`；
- SM2 离线预计算签名与标准 SM2 verify 一致；
- Python reference 与 native 对固定测试向量的 transcript 字段保持预期结构一致（不要求随机值逐字节相同）。

### 5.2 负向安全测试

逐一修改后必须拒绝：

- `X_B`
- `U`
- `C`
- `sigma`
- `tau`
- 错误 `x_B`
- 错误 `d_B`
- 非法点
- 无穷远点
- token 重用
- KDF 域分离标签混用

### 5.3 攻击路径演示

Type-I-KSR demo：攻击者知道 `x'_B`，确认可计算 `Z_2=[x'_B]U`，但实验不把“无法计算 CDH/SM9 secret”误当作数学证明。

Type-II demo：KGC 具备 `s/d_B/Z_1`，但没有 `x_B` 时不能调用合法 decapsulation 完成 `Z_2`；同样只作为代码路径验证，不作为 CDH 困难性的经验性证明。

## 6. GitHub Actions 真实实测

新增 `.github/workflows/native-benchmark.yml`。

工作流：

1. checkout V2 commit；
2. checkout 固定 GmSSL commit；
3. Release 模式编译 GmSSL；
4. 运行其相关 SM2/SM3/SM9 测试；
5. 编译 native V2；
6. 执行 V2 correctness + negative tests；
7. benchmark warm-up；
8. 对 20/128/1024/4096 B 各执行固定迭代次数；
9. 生成 `environment.json`、`raw.csv`、`summary.csv`、`build.log`、`test.log`、`benchmark.log`；
10. 上传 Actions artifact。

CI 数据在论文中只能标记为 **CI reproducibility benchmark**，不能替代用户 Ryzen 7 8845H 的最终投稿平台数据。

## 7. Benchmark 统计协议

修复当前 Python benchmark 覆盖 CSV 的问题。无论 Python/native：

- raw CSV 采用追加或一次聚合写入，必须保留四种消息长度；
- 每个 phase 单独记录 raw `ns`；
- summary 报告 `n/mean/median/stdev/P95`；
- 固定 warm-up 和正式迭代；
- 不只报告最好一次；
- 性能图和论文表格只从归档 CSV 生成，不手工录入。

阶段至少包括：

- receiver key generation；
- offline signcryption；
- online signcryption；
- total sender cost；
- unsigncryption；
- 基础 SM2 fixed-base multiplication；
- SM9 G1 multiplication；
- SM9 pairing；
- GT exponentiation（若可独立测量）。

## 8. Ryzen 7 8845H 最终投稿实测

CI 完成后，使用与 CI 同一 V2 commit、同一 GmSSL commit 和 Release 配置，在目标 Windows 机器执行：

- 固定电源模式；
- 固定 CPU affinity（条件允许时）；
- 记录 Windows/BIOS/CPU/编译器/CMake/GmSSL commit/编译 flags；
- 每个基础操作预热至少 1000 次、正式至少 10000 次；
- 协议阶段按 20/128/1024/4096 B 测试；
- 保存 raw CSV、summary CSV、日志和 environment JSON。

只有这组结果作为论文“submission benchmark”。

## 9. 论文回写

论文增加或修改：

1. Type-I-KSR 与经典 Type-I 强弱关系小节；
2. HMAC multi-key 归约损失；
3. Type-II guess-and-abort / KDF query 编程细节；
4. SM9 identity-KEM 到已有 SM9/BDHI 安全结果的关系；
5. 公钥替换造成 DoS 的安全边界；
6. 实验可复现性与 GitHub commit；
7. CI benchmark 与 submission benchmark 的严格区分；
8. Reviewer Attack Matrix：Concern / Severity / Resolution / Residual Risk。

在真实 benchmark 结束之前，论文性能表继续保持“实测待填”，不得产生占位的伪数字。

## 10. 风险与停止条件

以下任一情况发生时停止声称“完整标准实现”，转为明确 blocker：

- GmSSL 公开 API 无法支持 V2 需要的标准 SM9 底层共享因子计算；
- 无法通过 GmSSL/权威 SM2、SM3、SM9 测试向量；
- native 与论文方程出现不可解释的不一致；
- GitHub Actions benchmark 环境不稳定到无法复现实验；
- Type-I-KSR 在正式安全模型中被发现存在直接攻击。

不得为了完成任务绕过以上条件。

## 11. 交付物

- GitHub native C 实现与测试；
- GitHub Actions workflow；
- CI 真实 artifact（若 Actions 权限与运行环境可用）；
- Reviewer Attack Matrix；
- 更新后的中文论文 PDF + LaTeX；
- 实验脚本、依赖 commit、CSV、环境 JSON、日志；
- Ryzen 7 8845H 最终实测执行说明；
- 对所有未完成/未验证项明确标记，不虚构数据。
