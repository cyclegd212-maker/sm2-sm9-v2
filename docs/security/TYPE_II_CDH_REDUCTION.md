# Type-II 恶意 KGC：最终 plain-CDH 归约与 Oracle 模拟

本文档给出 V2 在 Type-II 恶意 KGC 模型下的 reviewer-grade IND-CCA 归约。目标是把早期“结构模板”收敛为可直接进入论文的概率系数、Oracle 行为和运行时间说明，同时避免把 Type-I 的 Gap-BCAA/DBIDH 能力错误复制到 Type-II。

## 1. 模型与查询计数

Type-II 攻击者得到 SM9 主秘密 `s`，因而能计算任意身份私钥 `d_ID` 和身份因子 `Z1`；但对挑战接收者：

- 不得替换 `X_B*`；
- 不得获得用户秘密 `x_B*`；
- 挑战发送者的 SM2 私钥不泄漏。

记：

- `N_U`：游戏中被懒惰实例化用户公开因子 `X_ID=[x_ID]Q_ID` 的不同接收身份数。Type-II 无 ReplacePK，因此在当前接口下可取 `N_U <= q_x + q_sc + q_usc + 1`；如果最终游戏另有显式 PublicKey/CreateUser 查询，则把其计数加入该上界。
- `q_K* <= q_K`：满足 `(Z1,ctx)=(Z1*,ctx*)` 的 challenge-candidate session-KDF 查询上限；最终定理可用全局 `q_K` 保守替代。
- `q_sc* <= q_sc`：针对挑战接收状态的 Signcrypt 查询数。
- `q_usc* <= q_usc`：针对挑战接收状态的 Unsigncrypt 查询数。
- `q_E* <= q_E`：与挑战 `ctx*`/消息长度相关的 stream-KDF 查询数。
- `kappa=256`：`K_E,K_M` 与 HMAC tag 的比特长度。

## 2. 随机预言机与状态表

模拟器维护：

- `L_1[ID] = h`：`H1` 表；
- `L_U[ID] = (h,Q,d,x_or_perp,X,state)`：接收用户表；
- `L_K[(Z1,Z2,ctx)] = (K_E,K_M)`：session-KDF 表；
- `L_E[(K_E,ctx,len)] = S`：stream-KDF 表；
- `L_SC[mu] = (X,U,C,sigma,tau,M,K_E,K_M)`：Signcrypt 输出记录；
- `CH = (mu*,X*,U*,C*,sigma*,tau*,K_E*,K_M*)`：挑战记录。

规范编码必须保证 `mu=Enc(SC,ctx,C)` 对 `(ID_A,P_A,ID_B,X,U,C)` 单射。

## 3. 用户公开因子的 lazy embedding

给 CDH 实例 `(P,A=[a]P,B=[b]P)`，目标输出 `[ab]P`。模拟器预选

`i* <- {1,...,N_U}`。

每当一个新的接收身份第一次需要创建用户公开因子时，计数器加一：

- 若不是第 `i*` 个，正常采样 `x` 并置 `X=[x]Q`；
- 若是第 `i*` 个，则诚实采样 `h* <- Z_q`，令 `c=h*+s mod q`。若 `c=0` 中止；否则
  - `Q*=cP`,
  - `X*=cB=[b]Q*`,
  - `x*=perp`（模拟器未知）。

若嵌入身份最终不是挑战身份，归约失败；若嵌入身份在挑战前被 RevealUserSecret，则归约中止。条件在 `i*` 正好命中最终挑战身份时，挑战新鲜性保证后一中止不会发生。

因为 `h*` 仍然均匀，且 Type-II 已知 `s` 后计算出的 `Q*=(h*+s)P` 与真实分布一致，所以没有可检测的 H1 编程。

## 4. 挑战 CDH 缩放嵌入

在挑战身份命中时，令

- `U*=cA=[a]Q*`,
- `d_B*=[s/c]P2`,
- `Z1*=e(U*,d_B*)=e(P,P2)^(as)`。

未知用户因子是

`Z2*=[b]U*=c[ab]P`。

若得到 `Z2*`，输出

`[c^{-1}]Z2*=[ab]P`。

## 5. Signcrypt Oracle

### 非挑战身份

已知 `(d,x)`，真实运行 V2。

### 挑战身份

模拟器对每次 Signcrypt 查询自行采样 `rho`，因此即使未知 `x_B*=b`，也能计算

`U=[rho]Q*`, `Z2=[rho]X*`。

`Z1=g^rho` 也可正常计算。因此 `H_K`、`H_E`、SM2 与 HMAC 全部真实执行，并把完整结果写入 `L_SC`。

### Challenge-U collision

定义 `Coll_U`：某个针对挑战接收状态的 Signcrypt 查询偶然产生 `U=U*`。由于每个 `rho` 在 `Z_q^*` 上均匀，

`Pr[Coll_U] <= q_sc*/(q-1)`。

必须显式剔除该事件：否则现实游戏中该查询与挑战共享同一 KEM 输入/会话密钥，而模拟器在挑战时又独立抽样 `(K_E*,K_M*)`，会造成可利用的 OTP/key-reuse 差异。

## 6. Unsigncrypt Oracle：完整三分支模拟

对挑战身份收到 `CT=(X,U,C,sigma,tau)` 后，先做公开点验证、当前 `X*` 检查、构造 `mu` 并验证 SM2。

### Case A：`mu` 既不在 `L_SC`，也不是 `mu*`

若 SM2 验证失败，返回 `perp`。若验证成功，触发 `Bad_sig`：这是对从未由目标 sender 的 Signcrypt/挑战签名过程签过的新 `mu` 的有效 SM2 签名。修改游戏立即拒绝，游戏差异至多

`Adv_SM2^EUF-CMA(B_sig)`。

SM2 reduction 需模拟至多 `q_sc+1` 次目标 sender 签名（`+1` 为挑战签名）。

### Case B：`mu in L_SC`

模拟器已经保存该记录的 `M,K_M,sigma_0,tau_0`，因此无需 `x_B*`：

- 若 `sigma=sigma_0`，直接用存储 `K_M` 重新验证 HMAC；有效时返回记录明文 `M`；
- 若 `sigma != sigma_0`，仍用存储 `K_M` 真实验证新的 MAC 输入 `Enc(MAC,mu,sigma)`；有效时返回同一记录明文 `M`，否则 `perp`。

因此 **普通 Signcrypt 记录上的替代 SM2 签名不需要作为 confidentiality proof 的 HMAC bad event**。模拟器知道这些记录的会话 MAC key，可以精确回答。

### Case C：`mu=mu*`

- 若 `(sigma,tau)=(sigma*,tau*)`，则是逐字节挑战密文，IND-CCA 规则拒绝；
- 若 `sigma=sigma*` 但 `tau != tau*`，真实 HMAC 确定性意味着拒绝；
- 若 `sigma != sigma*`，先公开验证 SM2。若无效则拒绝；若有效，则攻击者必须为新的 MAC 输入 `(mu*,sigma)` 产生挑战会话 key 下的有效 tag。

为了不暗含 SM2 strong unforgeability，Type-II confidentiality 对**挑战会话 HMAC**采用单目标 PRF hybrid：把 `HMAC_{K_M*}` 替换为随机函数 `F*`。游戏差异至多

`Adv_HMAC^PRF(B_prf)`。

在随机函数游戏里，除已给出的输入 `(mu*,sigma*)` 外，每个新的 `(mu*,sigma)` 的正确 tag 都是独立均匀 `kappa` 比特，因此所有 challenge-mu 替代签名 UnSC 尝试的成功概率至多

`q_usc*/2^kappa`。

这比旧版“对所有 L_SC 会话支付 multi-key HMAC UF-CMA”更紧，也避免与后面的独立 authenticity theorem 重复计项。

## 7. Challenge 与 Ask* 事件

挑战时模拟器独立均匀采样 `(K_E*,K_M*)`，通过自己的 `H_E` 表产生掩码，诚实生成 SM2 challenge signature 和 HMAC/PRF-hybrid tag。

定义

`Ask* := A queries H_K(Z1*, Z2*, ctx*)`。

若 `not Ask*`，且下列事件均未发生：

- `Bad_sig`；
- `Coll_U`；
- challenge-HMAC PRF hybrid 区分；
- challenge alternative-tag random-function guess；
- `Guess_E`：攻击者以某个候选 `K_E` 命中 `(K_E*,ctx*,len*)` 的 `H_E` 查询；

则挑战 `K_E*,K_M*` 对攻击者保持独立随机，`C*` 是一次性随机掩码；因 `C*` 的分布与 `b` 无关，所以由其确定的 `mu*`、SM2 signature 与 random-function tag 的联合分布也与 `b` 无关。因此条件成功概率恰为 `1/2`。

其中

`Pr[Guess_E] <= q_E*/2^kappa`。

令

`delta_II = Adv_SM2^EUF-CMA(B_sig)
          + Adv_HMAC^PRF(B_prf)
          + q_usc*/2^kappa
          + q_E*/2^kappa
          + q_sc*/(q-1)`。

若本文 IND 优势采用半优势

`epsilon_II = |Pr[b'=b]-1/2|`，

则

`Pr[Ask*] >= 2 [epsilon_II-delta_II]_+`。

这里不再把 `Bad_k`、全局 `H_K` 输出碰撞或 multi-key HMAC UF 项机械塞进 Type-II confidentiality：

- SM2 nonce 的随机性已由底层 SM2 EUF-CMA 实例吸收；
- 随机预言机允许自然输出碰撞，不需要模拟器强制唯一，因此无需人为定义全局 `Bad_H`；
- 非挑战 Signcrypt 记录的 `K_M` 已被模拟器保存，可以精确验证；只有 challenge HMAC 需要 PRF/随机函数混合。

## 8. q_K query-index extraction

plain-CDH 模拟器没有 DDH/gap oracle，无法测试任意候选 `Z2`。因此预选

`j* <- {1,...,q_K}`。

只对满足 `(Z1,ctx)=(Z1*,ctx*)` 的 candidate `H_K` 查询计数。前 `j*-1` 个 candidate 返回独立随机输出；第 `j*` 个 candidate `(Z1*,Z2hat,ctx*)` 到来时，立即输出

`[c^{-1}]Z2hat`

并终止。

若 `j*` 正好等于第一次正确 `Ask*` 的 candidate index，则在终止前所有错误候选的 RO 输出与真实分布一致，且输出为 `[ab]P`。正确 query 存在时，猜中概率至少 `1/q_K`。

## 9. 最终 Type-II 定理与系数

设 `B_CDH` 为上述求解器，`B_sig` 为 SM2 EUF-CMA 归约器，`B_prf` 为单目标 HMAC PRF 区分器。则

`Adv_CDH_G1(B_CDH)
 >= (1-1/q) * 2 [epsilon_II-delta_II]_+ / (N_U q_K)`。

等价地，论文最方便采用的上界是

`epsilon_II
 <= delta_II
  + (N_U q_K)/(2(1-1/q)) * Adv_CDH_G1(B_CDH)`。

用全局查询上限写成：

`epsilon_II
 <= Adv_SM2^EUF-CMA(B_sig)
  + Adv_HMAC^PRF(B_prf)
  + q_usc/2^kappa
  + q_E/2^kappa
  + q_sc/(q-1)
  + (N_U q_K)/(2(1-1/q)) Adv_CDH_G1(B_CDH)`。

若改用 normalized advantage `|2Pr[win]-1|`，上述主式中的 `1/2` 系数相应消失。

## 10. 运行时间

CDH solver 本身（不含独立的 SM2/HMAC reduction）满足结构性上界

`t_BCDH <= t_A
 + O(N_U*T_1m
     + q_sc*(2*T_1m + T_Te + T_SM2 + T_H)
     + q_usc*(T_SM2V + T_H + T_lookup)
     + q_K*T_parse
     + q_E*T_H
     + T_1m)`。

最后一个 `T_1m` 是成功提取后乘 `c^{-1}`。与旧稿不同，不应为每个 `H_K` candidate 都计一次 G1 标量乘；candidate 阶段只需解析、比较 `(Z1,ctx)` 与表访问。

`B_sig` 的运行时间约为 `t_A` 加 `q_sc+1` 次签名 oracle 转发与 `q_usc` 次公开验签；`B_prf` 只嵌入 challenge HMAC key，oracle 查询数至多 `1+q_alt`，其中 `q_alt<=q_usc*`。

## 11. 与独立 authenticity theorem 的去重规则

- Type-II confidentiality 只支付 `SM2 EUF-CMA + challenge-key HMAC PRF + random-tag guessing`，这些项服务于 challenge-user UnSC 模拟。
- 全局多会话 “同一 mu 替代 sigma” 认证性质放到 `AUTHENTICITY_THEOREM.md`，使用 multi-key HMAC UF-CMA。
- 不得把 multi-key HMAC UF-CMA 同时再塞入 Type-II confidentiality 的 `delta_II`，否则重复计项。

## 12. Reviewer checklist

- [x] `H1(ID*)` 完全诚实采样；
- [x] `c=h*+s` 且显式支付 `Pr[c=0]=1/q`；
- [x] 用户公钥 embedding 猜测对象收紧为 `N_U` 个 user-key instantiation，而不是所有 H1 查询；
- [x] challenge-state Signcrypt 的 `U=U*` 重随机碰撞单独计为 `q_sc*/(q-1)`；
- [x] 普通 `L_SC` 记录的 alternate signature 可由存储 `K_M` 精确回答，不再误算为 HMAC bad event；
- [x] challenge `mu*` 的 alternate signature 用单目标 HMAC PRF + `q_usc*/2^kappa` 处理；
- [x] `Ask*` 的半优势系数严格为 2；
- [x] plain-CDH 保留 `1/q_K` extraction loss；
- [x] 运行时间中 `q_K` candidate 不再错误地每项计 G1 标量乘；
- [x] 与独立 multi-key authenticity theorem 去重。
