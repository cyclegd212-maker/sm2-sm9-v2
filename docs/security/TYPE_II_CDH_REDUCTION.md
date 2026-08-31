# Type-II 恶意 KGC 的 CDH 缩放嵌入与 Oracle 模拟

本文档记录 V2 的 Type-II 机密性证明应如何写，重点避免早期“特殊编程 `H1(ID*)`”可被已知主密钥的恶意 KGC 识别的问题。

## 1. Type-II 能力

Type-II 攻击者获得 SM9 主私钥 `s`，因此能够计算任意身份私钥 `d_ID` 和身份因子 `Z_1`。但是：

- 不允许替换挑战用户的 `X_B`；
- 不知道挑战用户自行选择的 `x_B`；
- 目标是从 `Q_B, U=[rho]Q_B, X_B=[x_B]Q_B` 得到 `Z_2=[rho x_B]Q_B`。

因此 V2 将 Type-II 缺失因子与 G1 上 CDH 对齐。

## 2. 为什么不能强制 `Q_B^*=P`

早期想法若令 `H1(ID_B^*)=1-s`，则 `Q_B^*=(H1(ID_B^*)+s)P=P`。但 Type-II 已知 `s`，所以它看到挑战身份的 `H1` 输出时能够识别该特殊关系，模拟分布不再与真实随机预言机一致。

因此该嵌入必须弃用。

## 3. 缩放 CDH 嵌入

给归约算法 CDH 实例：

`(P, A=[a]P, B=[b]P)`，目标计算 `[ab]P`。

归约算法：

1. 正常选择 SM9 主私钥 `s` 并交给 Type-II 攻击者；
2. 猜测挑战身份 `ID_B^*`；
3. 当第一次回答 `H1(ID_B^*)` 时，诚实均匀采样 `h* in Z_q`；
4. 令 `c=h*+s mod q`。若 `c=0` 则中止，该事件概率为 `1/q`；
5. 设置
   - `Q_B^*=cP`
   - `U^*=cA=c[a]P`
   - `X_B^*=cB=c[b]P`。

因为 `h*` 与真实随机预言机输出同分布，而且 Type-II 已知 `s` 后计算的 `Q_B^*=(h*+s)P` 正好等于 `cP`，因此挑战身份在 `H1` 层没有可识别的特殊编程。

挑战需要的用户因子为：

`Z_2^*=[rho]X_B^*=c[ab]P`。

如果归约算法在某个正确的 KDF 查询中获得 `Z_2^*`，则输出：

`[c^{-1}]Z_2^*=[ab]P`。

## 4. 随机预言机表

投稿版应至少显式维护：

- `L_1`: `H1(ID)` 查询表；
- `L_K`: 会话密钥 KDF 查询表；
- `L_E`: 加密流 SM3-KDF 查询表；
- `L_H`: HMAC/PRF 抽象中需要的查询记录（若直接使用 multi-key PRF 定理，可按相应模型简化）；
- `L_SC`: signcryption oracle 输出记录；
- `L_PK`: 用户公开因子及 Type-II 不可替换状态。

所有随机预言机查询必须在重复输入时返回一致结果。

## 5. 挑战 KDF 与 guess-and-abort

归约算法不知道 `Z_2^*`，因此挑战时不能真实运行：

`KDF(Z_1^*, Z_2^*, ctx^*)`。

标准处理是：

1. 挑战时随机选择 `K_E^*,K_M^*`；
2. 用这些随机密钥生成挑战 ciphertext；
3. 猜测攻击者第 `j^*` 个相关 `H_K` 查询将是第一次包含真实 `(Z_1^*,Z_2^*,ctx^*)` 的查询；
4. 若猜错则归约失败；
5. 若命中，则从该查询提取 `Z_2^*`，立即恢复 `[ab]P` 并终止。

证明必须说明：在正确关键查询发生之前，挑战密钥在真实游戏中从攻击者视角也是随机不可区分的；因此在正确 guess 的条件下，归约在终止前给出的视图与相应 hybrid 一致。

## 6. 挑战身份与关键查询损失

设：

- `N_ID` 为可能成为挑战身份的候选数量上界；
- `q_K` 为相关会话 KDF 查询上界；
- `E_id` 为挑战身份猜测正确；
- `E_c` 为 `c != 0`；
- `E_K` 为关键 KDF 查询索引猜测正确。

则典型成功概率具有：

`Pr[E_id] >= 1/N_ID`,

`Pr[E_c] = 1-1/q`,

`Pr[E_K] >= 1/q_K`。

因此最终 CDH advantage 至少带有 `N_ID * q_K` 量级的归约损失。具体等式必须等完整游戏序列、bad events 和 oracle 新鲜性规则固定后再写，不能提前用一个漂亮公式替代实际概率核算。

## 7. 解签密 Oracle 模拟

针对 Type-II 挑战用户，归约不知道 `x_B^*`，因此不能对任意 ciphertext 直接真实 decapsulate。UnSC 查询分三类处理：

### 7.1 新规范消息 + 新有效 SM2 签名

若查询中的规范 transcript `mu` 从未由 signcryption oracle 签过，却通过 SM2 验签，则触发 `Bad_sig`，将其归入 SM2 EUF-CMA 事件。

### 7.2 已签过 `mu`，但替换为另一个随机化 SM2 签名

普通 SM2 EUF-CMA 不覆盖同消息新签名。若攻击者让新的 `sigma' != sigma` 与 transcript 一起通过会话 HMAC，则触发 `Bad_mac`，归入 multi-key HMAC UFCMA / PRF 事件。

### 7.3 Signcryption oracle 正常生成的记录

对 `L_SC` 中已经生成并记录的 ciphertext/transcript，模拟器直接查表返回对应明文或按游戏规则处理，不需要知道挑战用户 `x_B^*`。

挑战 ciphertext 本身及游戏定义的等价禁止查询必须拒绝。

## 8. HMAC 多密钥损失

每个 token 独立派生 `K_M`。因此证明不能把所有 HMAC 查询压成一个单密钥实例而不给损失。

推荐两种合法写法：

1. 直接定义/引用 multi-key HMAC PRF/UFCMA advantage；或
2. 随机猜测最终发生伪造的 signcryption 会话，支付至多 `q_sc` 量级损失，再嵌入单密钥 HMAC challenger。

整篇论文只能选一种表示方式并保持一致。

## 9. SM9 身份因子假设的边界

Cheng 2018（INSCRYPT，DOI `10.1007/978-3-030-14234-6_1`）公开给出了 SM9 key agreement/encryption 的 ROM 形式安全分析。当前检索已经确认“存在正式安全分析”，但本项目尚未逐页核对该文中哪一个定理、哪一个基础困难假设与 V2 所使用的 `Z_1=g^rho` KEM hybrid 完全同构。

所以在完成该核对之前，论文只能写：

> Type-I confidentiality is conditional on the stated modular SM9 identity-KEM indistinguishability assumption.

不得提前写“已严格归约到 q-BDHI”。若后续逐定理核对成功，再替换为明确的文献定理号、假设名称和归约损失。

## 10. 当前可接受的定理措辞

Type-II 可以表述为：在 ROM 中，若 G1 上 CDH 困难，且 SM2、multi-key HMAC/PRF 及域分离 KDF 满足所声明安全性质，则 V2 在本文 Type-II 模型下满足 IND-CCA，优势界包含挑战身份猜测、`c=0`、关键 KDF 查询猜测及 bad-event 损失。

该表述比“Type-II 直接归约到 CDH”更长，但不会掩盖模拟器实际付出的概率与运行时间成本。
