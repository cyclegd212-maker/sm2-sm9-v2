# Type-II 恶意 KGC 的 CDH 缩放嵌入与 Oracle 模拟

本文档记录 V2 的 Type-II 机密性证明应如何写，重点避免早期“特殊编程 `H1(ID*)`”可被已知主密钥的恶意 KGC 识别的问题，并严格区分 Type-II 的 plain-CDH query extraction 与 Type-I-KSR 的 Cheng Gap-BCAA reduction。

## 1. Type-II 能力

Type-II 攻击者获得 SM9 主私钥 `s`，因此能够计算任意身份私钥 `d_ID` 和身份因子 `Z_1`。但是：

- 不允许替换挑战用户的 `X_B`；
- 不知道挑战用户自行选择的 `x_B`；
- 目标是从 `Q_B, U=[rho]Q_B, X_B=[x_B]Q_B` 得到 `Z_2=[rho x_B]Q_B`。

因此 V2 将 Type-II 缺失因子与 `G1` 上 CDH 对齐。

## 2. 为什么不能强制 `Q_B^*=P`

早期想法若令 `H1(ID_B^*)=1-s`，则 `Q_B^*=(H1(ID_B^*)+s)P=P`。但 Type-II 已知 `s`，所以它看到挑战身份的 `H1` 输出时能够识别该特殊关系，模拟分布不再与真实随机预言机一致。

因此该嵌入必须弃用。

## 3. 缩放 CDH 嵌入

给归约算法 CDH 实例：

`(P, A=[a]P, B=[b]P)`，目标计算 `[ab]P`。

归约算法：

1. 正常选择 SM9 主私钥 `s` 并交给 Type-II 攻击者；
2. 猜测将承载 CDH public-key embedding 的挑战用户/身份；
3. 对该身份诚实均匀采样 `h* in Z_q`；
4. 令 `c=h*+s mod q`。若 `c=0` 则中止，该事件概率为 `1/q`；
5. 设置
   - `Q_B^*=cP`
   - `U^*=cA=c[a]P`
   - `X_B^*=cB=c[b]P`。

因为 `h*` 与真实随机预言机输出同分布，而且 Type-II 已知 `s` 后计算的 `Q_B^*=(h*+s)P` 正好等于 `cP`，因此挑战身份在 `H1` 层没有可识别的特殊编程。

真实挑战随机数在该嵌入中等价于 `rho=a`，挑战所缺用户因子为

`Z_2^*=[rho]X_B^*=c[ab]P`。

如果归约算法从正确 session-KDF 查询中获得 `Z_2^*`，则输出

`[c^{-1}]Z_2^*=[ab]P`。

## 4. 随机预言机与状态表

投稿版至少维护：

- `L_1`: `H1(ID)` 查询表；
- `L_K`: 会话密钥 KDF 查询表；
- `L_E`: 加密流 SM3-KDF 查询表；
- `L_SC`: signcryption oracle 输出记录；
- `L_PK`: 用户公开因子、challenge-embedding 标记和不可替换状态；
- `L_MAC`: 若不黑盒引用 multi-key HMAC 定理，则记录相关 MAC/PRF 查询。

所有随机预言机重复输入必须返回一致结果。

## 5. 为什么 plain CDH 下存在关键 KDF-query extraction 问题

Type-II simulator 知道 `s`，所以能算

`Z_1^*=g^rho=e(U^*,d_B^*)`，

但不知道

`Z_2^*=c[ab]P`。

挑战时因此不能真实调用

`H_K(Z_1^*,Z_2^*,ctx^*)`。

若归约目标是 **plain CDH**，simulator 没有 DDH/gap oracle 去测试任意候选 `Z_2` 是否等于真实 `Z_2^*`。一个保守且可审计的处理是：

1. 挑战时随机选择 `K_E^*,K_M^*`；
2. 用其生成 challenge ciphertext；
3. 预先猜测第 `j^*` 个相关 `H_K` 查询是第一次包含真实 `(Z_1^*,Z_2^*,ctx^*)` 的查询；
4. 在该索引提取候选 `Z_2`；
5. 若该 query 确为攻击者区分 challenge 所必需的正确 query，则输出 `[c^{-1}]Z_2` 解 CDH；否则归约失败。

这里的“猜 query”不是漂亮但多余的写法，而是 plain-CDH simulator 缺少候选检测能力的直接后果。

如果未来改用 Gap-CDH/DDH-assisted 假设，从而能够测试候选 `Z_2`，则可重新设计 reduction 并去掉 `1/q_K` 损失；但那是**不同安全假设**，不能把 Type-I 的 Gap-BCAA 技巧无条件搬来。

## 6. 挑战身份与关键查询损失

设：

- `N_ID`：可能承载 challenge user-key embedding 的候选数量上界；
- `q_K`：相关 session-KDF 查询上界；
- `E_id`：challenge embedding 猜测正确；
- `E_c`：`c != 0`；
- `E_K`：关键 KDF 查询索引猜测正确。

保守地有

`Pr[E_id] >= 1/N_ID`，

`Pr[E_c] = 1-1/q`，

`Pr[E_K] >= 1/q_K`。

因此 plain-CDH reduction 预期承受 `N_ID*q_K` 量级的 advantage loss，并额外支付 `c=0` 中止与 oracle bad events。最终常数必须在完整 game 序列冻结后由事件概率逐项推出。

## 7. Challenge-identity UnSC oracle 模拟

针对 challenge user，归约不知道 `x_B^*`，所以无法对任意新 ciphertext 直接计算 `Z_2=[x_B^*]U`。在坚持 plain-CDH 的 proof path 下，可利用 signcryption 认证层把接受的查询分解。

### 7.1 Signcryption-oracle 已记录的 ciphertext

对 `L_SC` 中由 simulator 自己生成的完整记录，直接查表回答；不需要重算 challenge user 的 `Z_2`。

### 7.2 新 canonical transcript `mu` 却通过 SM2 验签

若 `mu` 从未由 signcryption oracle 签过，却通过 SM2 verification，则这是 sender-authentication proof 中的 `Bad_sig`，可归入 SM2 EUF-CMA。

### 7.3 已签过 `mu`，但换成另一个随机化 SM2 signature

ordinary EUF-CMA 不覆盖同消息的不同合法随机化签名。由于 V2 的

`tau=HMAC_{K_M}(mu||sigma)`

绑定具体 `sigma`，要让 `(mu,sigma')` 成为新的可接受 ciphertext 还需要突破 session MAC binding；该事件归入 HMAC PRF/UFCMA 项。

### 7.4 Challenge equivalence

challenge ciphertext 本身及游戏定义的等价查询必须拒绝。等价关系必须基于 canonical encoding，而不是仅比较指针或某一个字段。

该路径使 simulator 在 `Bad_sig/Bad_mac` 未发生时，不必对任意新 challenge-user ciphertext 真实 decapsulate。

## 8. HMAC 与 SM2 项应该出现在哪里

与 Type-I-KSR 不同，当前 Type-II **plain-CDH** oracle simulation 利用了认证层来限制无法 decapsulate 的新查询，因此 confidentiality proof 本身可能支付 `Bad_sig/Bad_mac` 项。

若论文采用这种 proof path：

- 新 `mu` 的有效签名：SM2 EUF-CMA；
- 同 `mu` 新随机化签名或修改 transcript 后仍通过 tag：HMAC binding；
- 多个 signcryption session 具有独立 `K_M`，因此应使用 multi-key HMAC security，或猜目标会话后支付相应损失。

不能在 Type-I-KSR 中因为 Type-II 需要这些项，就机械地把相同 bad-event decomposition 重复放入 Type-I confidentiality 主界。两种 simulator 的能力不同。

## 9. Cheng SM9-KEM 定理与本 Type-II proof 的关系

Cheng, *Security Analysis of SM9 Key Agreement and Encryption*, Theorem 4（INSCRYPT 2018, DOI `10.1007/978-3-030-14234-6_1`）已经逐项核对：

- SM9-KEM 的隐藏 pairing value
  `t=e(C1,d_ID)`
  与 V2 的
  `Z_1=e(U,d_B)=g^rho`
  完全一致；
- Theorem 4 在 `H2RF1,KDF2` 作为随机预言机时，把 SM9-KEM ID-IND-CCA2 归约到 `Gap-q-BCAA1_{1,2}`；
- 其 Gap solver 具有 DBIDH oracle，因此挑战身份的 KDF-query 数 `q_K` 进入运行时间 `O(q_K*q_D*O_DBIDH)`，而不是 `1/q_K` advantage denominator。

这直接解决的是 **Type-I-KSR 的缺失身份因子 `Z_1`**，详见 `TYPE_I_KSR_REDUCTION.md`。

它**不能**自动解决当前 Type-II 的缺失用户因子 `Z_2`：Type-II 已知 KGC 主秘密，SM9 identity factor 对攻击者并不隐藏；真正未知的是 `G1` 上的 user-secret CDH 项。因此 Type-II 仍需独立的 CDH reduction。

## 10. 当前 Type-II 定理措辞

在当前 plain-CDH proof path 下，可接受的保守措辞是：

> In the random-oracle model, assuming CDH is hard in `G1`, SM2 satisfies the stated EUF-CMA property, and the session MAC satisfies the required multi-key PRF/UFCMA property, V2 satisfies IND-CCA confidentiality against the specified Type-II malicious-KGC adversary. The reduction uses a distribution-preserving scaled CDH embedding and incurs losses for challenge-user embedding, the negligible event `h*+s=0`, critical session-KDF query extraction, and authentication-layer bad events required to simulate challenge-user unsigncryption queries.

最终主界应具有如下结构，而不是提前冻结成未经核算的等式：

`Adv_TypeII(A)`
`<= N_ID*q_K/(1-1/q) * Adv_CDH(B)`
` + Bad_sig`
` + Bad_mac`
` + RO/encoding negligible terms`，

其中具体系数应从最终游戏逐项推导。注意该行只是**结构模板**；在没有完成事件条件概率整理之前，不应作为论文正式定理公式。

## 11. Reviewer checklist

- [x] 放弃可识别的 `H1(ID*)=1-s` 特殊编程；
- [x] 使用诚实 `h*` 与 `c=h*+s` 缩放 embedding；
- [x] 显式计入 `Pr[c=0]=1/q`；
- [x] 区分 Type-I Gap-BCAA 的 DBIDH 检测能力与 Type-II plain-CDH；
- [x] 不把 Type-I 的“q_K 只进入运行时间”错误搬到 Type-II；
- [ ] 冻结 Type-II challenge-user/public-key creation game，确定 `N_ID` 的准确含义；
- [ ] 逐条列出 Signcrypt/Unsigncrypt/Hash oracle 并证明模拟一致；
- [ ] 从事件概率推出最终常数，而不是使用本文件的结构模板代替证明；
- [ ] 与独立 authenticity theorem 的 SM2/HMAC 项去重。
