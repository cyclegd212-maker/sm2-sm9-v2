"""Reference implementation of the SM2->enhanced-SM9 V2 construction.

Research code only. The code mirrors the paper equations and is intended for
correctness/benchmark experiments, not production deployment.

Dependency: gongxian-ding/gmssl-python pinned in requirements.txt.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets
from typing import Any, Tuple

from gmssl import sm2, sm9
import gmssl.optimized_curve as ec
import gmssl.optimized_pairing as ate
import gmssl.optimized_field_elements as fq

SM2_N = int(sm2.default_ecc_table["n"], 16)
_FIELD_BYTES = (fq.field_modulus.bit_length() + 7) // 8


def _lp(x: bytes) -> bytes:
    """4-byte length prefix to avoid concatenation ambiguity."""
    return len(x).to_bytes(4, "big") + x


def _sm3(data: bytes) -> bytes:
    return hashlib.new("sm3", data).digest()


def sm3_kdf(z: bytes, out_len: int) -> bytes:
    """Counter-mode KDF using SM3, output length in bytes."""
    if out_len < 0:
        raise ValueError("out_len must be nonnegative")
    out = bytearray()
    counter = 1
    while len(out) < out_len:
        out.extend(_sm3(z + counter.to_bytes(4, "big")))
        counter += 1
    return bytes(out[:out_len])


def _hmac_sm3(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, digestmod="sm3").digest()


def _fq_coeffs(v: Any) -> list[int]:
    if hasattr(v, "coeffs"):
        return [int(c) for c in v.coeffs]
    if hasattr(v, "n"):
        return [int(v.n)]
    return [int(v)]


def encode_field(v: Any) -> bytes:
    coeffs = _fq_coeffs(v)
    return b"".join(c.to_bytes(_FIELD_BYTES, "big") for c in coeffs)


def encode_point(P: Any) -> bytes:
    """Canonical fixed-width encoding of a projective gmssl-python point.

    The reference library represents points as (X,Y,Z). We normalize before
    serialization and encode each base/extension-field coefficient at fixed width.
    """
    if ec.is_inf(P):
        raise ValueError("point at infinity is not allowed")
    x, y = ec.normalize(P)
    return b"\x04" + _lp(encode_field(x)) + _lp(encode_field(y))


def encode_gt(z: Any) -> bytes:
    return _lp(encode_field(z))


def encode_ctx(id_a: bytes, p_a_hex: str, id_b: bytes, x_b_pub: Any, U: Any) -> bytes:
    return (
        b"SM2-SM9-V2/CTX/v1"
        + _lp(id_a)
        + _lp(bytes.fromhex(p_a_hex))
        + _lp(id_b)
        + _lp(encode_point(x_b_pub))
        + _lp(encode_point(U))
    )


def derive_session_keys(z1: Any, z2: Any, ctx: bytes, key_len: int = 32) -> Tuple[bytes, bytes]:
    material = (
        b"SM2-SM9-V2/KEY/v1"
        + _lp(encode_gt(z1))
        + _lp(encode_point(z2))
        + _lp(ctx)
    )
    keymat = sm3_kdf(material, 2 * key_len)
    return keymat[:key_len], keymat[key_len:]


@dataclass(frozen=True)
class SenderKey:
    id_a: bytes
    private_hex: str
    public_hex: str

    @property
    def sm2_obj(self) -> sm2.CryptSM2:
        return sm2.CryptSM2(private_key=self.private_hex, public_key=self.public_hex)


@dataclass(frozen=True)
class ReceiverKey:
    id_b: str
    d_b: Any
    x_b: int
    X_b: Any


@dataclass
class OfflineToken:
    id_b: str
    X_b: Any
    U: Any
    K_E: bytes
    K_M: bytes
    k: int
    x_R: int
    consumed: bool = False


@dataclass(frozen=True)
class Ciphertext:
    X_b: Any
    U: Any
    C: bytes
    sigma_hex: str
    tau: bytes


def setup_sm9() -> tuple[Any, int]:
    return sm9.setup("encrypt")


def sender_keygen(id_a: bytes = b"Alice") -> SenderKey:
    d = secrets.randbelow(SM2_N - 1) + 1
    temp = sm2.CryptSM2(private_key=f"{d:064x}", public_key="")
    p = temp._kg(d, sm2.default_ecc_table["g"])
    return SenderKey(id_a=id_a, private_hex=f"{d:064x}", public_hex=p)


def receiver_keygen(master_public: Any, master_secret: int, id_b: str = "Bob") -> ReceiverKey:
    Q_b = sm9.public_key_extract("encrypt", master_public, id_b)
    d_b = sm9.private_key_extract("encrypt", master_public, master_secret, id_b)
    if d_b is sm9.FAILURE:
        raise RuntimeError("SM9 private-key extraction failed")
    x_b = secrets.randbelow(ec.curve_order - 1) + 1
    X_b = ec.multiply(Q_b, x_b)
    return ReceiverKey(id_b=id_b, d_b=d_b, x_b=x_b, X_b=X_b)


def validate_receiver_key(master_public: Any, receiver: ReceiverKey) -> None:
    Q_b = sm9.public_key_extract("encrypt", master_public, receiver.id_b)
    if not ec.eq(ec.multiply(Q_b, receiver.x_b), receiver.X_b):
        raise ValueError("X_B != [x_B]Q_B")
    if ate.pairing(Q_b, receiver.d_b) != master_public[3]:
        raise ValueError("invalid SM9 identity private key")


def _sm2_precompute(sender: SenderKey) -> tuple[int, int]:
    obj = sender.sm2_obj
    while True:
        k = secrets.randbelow(SM2_N - 1) + 1
        R = obj._kg(k, sm2.default_ecc_table["g"])
        if R:
            return k, int(R[: obj.para_len], 16)


def offline_signcrypt(master_public: Any, sender: SenderKey, receiver_id: str, X_b: Any) -> OfflineToken:
    Q_b = sm9.public_key_extract("encrypt", master_public, receiver_id)
    rho = secrets.randbelow(ec.curve_order - 1) + 1
    U = ec.multiply(Q_b, rho)
    Z1 = master_public[3] ** rho
    Z2 = ec.multiply(X_b, rho)
    ctx = encode_ctx(sender.id_a, sender.public_hex, receiver_id.encode(), X_b, U)
    K_E, K_M = derive_session_keys(Z1, Z2, ctx)
    k, x_R = _sm2_precompute(sender)
    return OfflineToken(receiver_id, X_b, U, K_E, K_M, k, x_R)


def _sm2_message_digest(obj: sm2.CryptSM2, mu: bytes) -> bytes:
    import binascii
    return binascii.a2b_hex(obj._sm3_z(mu).encode("utf-8"))


def sm2_sign_with_precomputation(sender: SenderKey, mu: bytes, k: int, x_R: int) -> str:
    obj = sender.sm2_obj
    e_bytes = _sm2_message_digest(obj, mu)
    e = int(e_bytes.hex(), 16)
    d = int(sender.private_hex, 16)
    r = (e + x_R) % SM2_N
    if r == 0 or (r + k) == SM2_N:
        raise ValueError("SM2 retry condition: discard offline token")
    inv = pow(d + 1, SM2_N - 2, SM2_N)
    s = (inv * (k - r * d)) % SM2_N
    if s == 0:
        raise ValueError("SM2 retry condition: discard offline token")
    return f"{r:064x}{s:064x}"


def online_signcrypt(sender: SenderKey, token: OfflineToken, message: bytes) -> Ciphertext:
    if token.consumed:
        raise ValueError("offline token already consumed")
    # Consume before any online operation. A retry or exception must not make the
    # SM2 nonce/session keys reusable. Cross-process atomicity belongs to storage.
    token.consumed = True
    ctx = encode_ctx(sender.id_a, sender.public_hex, token.id_b.encode(), token.X_b, token.U)
    stream = sm3_kdf(b"SM2-SM9-V2/ENC/v1" + _lp(token.K_E) + _lp(ctx), len(message))
    C = bytes(m ^ s for m, s in zip(message, stream))
    mu = (
        b"SM2-SM9-V2/SC/v1"
        + _lp(sender.id_a)
        + _lp(token.id_b.encode())
        + _lp(encode_point(token.X_b))
        + _lp(encode_point(token.U))
        + _lp(C)
    )
    sigma = sm2_sign_with_precomputation(sender, mu, token.k, token.x_R)
    mac_msg = b"SM2-SM9-V2/MAC/v1" + _lp(mu) + _lp(bytes.fromhex(sigma))
    tau = _hmac_sm3(token.K_M, mac_msg)
    return Ciphertext(token.X_b, token.U, C, sigma, tau)


def unsigncrypt(master_public: Any, sender: SenderKey, receiver: ReceiverKey, ct: Ciphertext) -> bytes:
    if not ec.is_on_curve(ct.X_b, ec.b2) or ec.is_inf(ct.X_b):
        raise ValueError("invalid X_B")
    if not ec.is_on_curve(ct.U, ec.b2) or ec.is_inf(ct.U):
        raise ValueError("invalid U")
    if not ec.eq(ct.X_b, receiver.X_b):
        raise ValueError("ciphertext public factor does not match receiver key")

    mu = (
        b"SM2-SM9-V2/SC/v1"
        + _lp(sender.id_a)
        + _lp(receiver.id_b.encode())
        + _lp(encode_point(ct.X_b))
        + _lp(encode_point(ct.U))
        + _lp(ct.C)
    )
    if not sender.sm2_obj.verify_with_sm3(ct.sigma_hex, mu):
        raise ValueError("invalid SM2 signature")

    Z1 = ate.pairing(ct.U, receiver.d_b)
    Z2 = ec.multiply(ct.U, receiver.x_b)
    ctx = encode_ctx(sender.id_a, sender.public_hex, receiver.id_b.encode(), ct.X_b, ct.U)
    K_E, K_M = derive_session_keys(Z1, Z2, ctx)
    expected = _hmac_sm3(
        K_M,
        b"SM2-SM9-V2/MAC/v1" + _lp(mu) + _lp(bytes.fromhex(ct.sigma_hex)),
    )
    if not hmac.compare_digest(expected, ct.tau):
        raise ValueError("invalid HMAC-SM3 tag")

    stream = sm3_kdf(b"SM2-SM9-V2/ENC/v1" + _lp(K_E) + _lp(ctx), len(ct.C))
    return bytes(c ^ s for c, s in zip(ct.C, stream))
