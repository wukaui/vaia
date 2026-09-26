"""纯 Python 的 PE Authenticode 签名解析与验证 —— **不依赖 Windows**。

## 为什么不用 `powershell.exe Get-AuthenticodeSignature`

旧实现走 Windows 验签，实测下来是个死结（2026-09-26，63 文件 × 恶意样本实测）：

  · 路径在 `AI_AV_NO_WIN_TOUCH_DIRS` 保护目录内 → 按策略跳过 → **53 次调用 53 次 unknown**
  · 路径在保护目录外 → 真的递给 Windows → **Defender 实时防护顺手吃掉样本**
    （实测 21 个恶意样本在扫描窗口内被隔离，时间戳与扫描完全重合）

而且它把"能不能验签"绑死在 Windows 上：Linux 机器 / 独立 Linux 虚拟机里
`powershell.exe` 根本不存在，验签直接不可用。

## 本模块做什么

在 Linux 上原生完成同一件事，分四步：

  1. 定位 PE 安全目录（`IMAGE_DIRECTORY_ENTRY_SECURITY`），取出 `WIN_CERTIFICATE`
  2. 解析其中的 PKCS#7 SignedData，拿到签名者证书与完整证书链
  3. 按 Authenticode 规范算 PE 摘要（**排除**校验和字段、安全目录项、证书表本身），
     与 SignedData 里 `SpcIndirectDataContent` 声明的摘要比对 → 判断文件有没有被改
  4. 用签名者公钥验证 `signedAttrs` 上的签名 → 判断签名本身真不真
  5. 用 `cryptography.x509.verification` 做证书链验证 → 判断签发者可不可信

**不碰 Windows，所以不触发 Defender，也不受保护目录限制。**

## 边界（如实说明）

  · 只处理 **PE 内嵌签名**（embedded）。目录签名（Catalog，Windows 系统文件大量使用）
    存在 `C:\\Windows\\System32\\CatRoot` 里，Linux 侧拿不到 —— 这种情况返回
    `catalog_possible=True`，由调用方按"未知"处理，**不得据此断言"无签名"**。
  · 不查吊销（CRL/OCSP）—— 离线环境做不到，也不该做网络请求。
  · 时间戳签名（RFC3161 副签名）只做存在性识别，不做验证。
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from asn1crypto import cms, core, x509 as asn1_x509

# PKCS#7 里 Authenticode 专用的内容类型 OID
SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4"
# WIN_CERTIFICATE 的证书类型：2 = PKCS#7 SignedData
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 2

# 读取上限：签名表通常在文件尾部，但偏移是 32 位，理论上能指向很大位置
MAX_SIGNATURE_BYTES = 4 * 1024 * 1024
# 证书链里最多取几张（够用即可，防畸形样本塞几千张证书）
MAX_CHAIN_CERTS = 8

# 摘要算法 OID → (名字, hashlib 名)
_DIGEST_ALGOS = {
    "1.3.14.3.2.26": ("sha1", "sha1"),
    "2.16.840.1.101.3.4.2.1": ("sha256", "sha256"),
    "2.16.840.1.101.3.4.2.2": ("sha384", "sha384"),
    "2.16.840.1.101.3.4.2.3": ("sha512", "sha512"),
}


class _SpcAttributeTypeAndOptionalValue(core.Sequence):
    _fields = [
        ("type", core.ObjectIdentifier),
        ("value", core.Any),
    ]


class _DigestInfo(core.Sequence):
    _fields = [
        ("digest_algorithm", asn1_x509.DigestAlgorithm),
        ("digest", core.OctetString),
    ]


class _SpcIndirectDataContent(core.Sequence):
    _fields = [
        ("data", _SpcAttributeTypeAndOptionalValue),
        ("message_digest", _DigestInfo),
    ]


def _security_directory(pe: Any) -> tuple[int, int]:
    """返回 (证书表偏移, 大小)；没有签名目录时返回 (0, 0)。"""
    import pefile  # 延迟导入：本模块只在真要用签名时才被调用

    try:
        entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
    except Exception:
        return 0, 0
    return int(getattr(entry, "VirtualAddress", 0) or 0), int(getattr(entry, "Size", 0) or 0)


def authenticode_digest(raw: bytes, pe: Any, algo: str) -> bytes | None:
    """按 Authenticode 规范算 PE 摘要。

    规范要求跳过三处（跳过而不是清零）：
      1. `CheckSum` 字段（4 字节，位于 OptionalHeader 内）
      2. 安全目录项本身（8 字节，`DataDirectory[SECURITY]`）
      3. 证书表（位于文件尾部，偏移/大小来自安全目录项）

    第 1、2 处的偏移从 pefile 的布局里取 —— 硬编码 PE 头偏移在
    PE32 / PE32+ 上不一样，交给 pefile 更稳。
    """
    try:
        hashlib.new(algo)
    except ValueError:
        return None

    cert_off, cert_size = _security_directory(pe)
    checksum_off = int(pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum"))
    # 安全目录项的**文件偏移**直接从 pefile 的结构体上取（`__file_offset__`）。
    # 别自己算：OptionalHeader 固定部分 PE32 是 96 字节、PE32+ 是 112 字节，
    # 硬编码会在另一种位上错 16 字节，而且错得很安静（摘要算错 → 误判"被篡改"）。
    # 也别写 get_field_absolute_offset("DATA_DIRECTORY") —— pefile 没这个字段名，KeyError。
    try:
        secdir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile_security_index(pe)]
        secdir_off = int(secdir_entry.__file_offset__)
    except Exception:  # noqa: BLE001 - 取不到偏移就没法算摘要，返回 None 让上层记 unknown
        return None

    h = hashlib.new(algo)
    # ① 文件头 → 校验和字段之前
    h.update(raw[:checksum_off])
    # ② 跳过 4 字节校验和，到安全目录项之前
    h.update(raw[checksum_off + 4 : secdir_off])
    # ③ 跳过 8 字节安全目录项，到证书表之前
    h.update(raw[secdir_off + 8 : cert_off])
    # ④ 跳过证书表，哈希其后的内容（通常没有，但规范要求算上）
    tail_start = cert_off + cert_size
    if 0 < tail_start < len(raw):
        h.update(raw[tail_start:])
    return h.digest()   # hashlib 是 .digest()，cryptography 的 Hash 才是 .finalize()


def pefile_security_index(pe: Any) -> int:
    import pefile

    return int(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"])


def _parse_blob(raw: bytes, cert_off: int, cert_size: int) -> tuple[Any | None, str]:
    """从证书表里解出 PKCS#7 ContentInfo。返回 (content_info, 错误说明)。"""
    if cert_off <= 0 or cert_size <= 0:
        return None, ""
    if cert_size > MAX_SIGNATURE_BYTES:
        return None, f"证书表过大（{cert_size} 字节），跳过解析"
    blob = raw[cert_off : cert_off + cert_size]
    if len(blob) < 8:
        return None, "证书表短于 WIN_CERTIFICATE 头"
    length, _revision, cert_type = struct.unpack("<IHH", blob[:8])
    if cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
        return None, f"未知的 WIN_CERTIFICATE 类型 {cert_type}"
    if length < 8 or length > len(blob):
        return None, f"WIN_CERTIFICATE 长度字段异常（{length} vs 实际 {len(blob)}）"
    der = blob[8:length]
    try:
        return cms.ContentInfo.load(der), ""
    except Exception as exc:  # noqa: BLE001 - 畸形签名很常见，不该炸掉扫描
        return None, f"PKCS#7 解析失败: {type(exc).__name__}: {exc}"


def _present(obj: Any) -> bool:
    """判断一个可选 ASN.1 字段是否存在。

    ⚠️ **不能用 `.native`**：Authenticode 的 signedAttrs 里塞了微软自定义属性
    （SPC_* 那一串 OID），asn1crypto 的通用 CMS 模型解不了，`.native` 会抛
    `ValueError: Unknown element - context class, constructed method, tag 0`。
    所以全程走结构化访问（`.dump()` / `len()` / 下标）。
    """
    try:
        return obj is not None and len(obj.dump()) > 0
    except Exception:  # noqa: BLE001
        return False


def _chain_from_signed_data(signed_data: Any) -> list[Any]:
    """取出证书链（顺序按 PKCS#7 里的原始顺序，通常是 [签名者, 中间 CA, ...]）。"""
    out: list[Any] = []
    try:
        certs = signed_data["certificates"]
        for choice in certs:
            if getattr(choice, "name", None) != "certificate":
                continue  # 跳过 CRL 等其它 CertificateChoices
            out.append(choice.chosen)
            if len(out) >= MAX_CHAIN_CERTS:
                break
    except Exception:  # noqa: BLE001 - 畸形证书表不该炸掉扫描
        return out
    return out


def _verify_signed_attrs(signed_data: Any, signer_info: Any, signer_cert: Any) -> tuple[bool | None, str]:
    """用签名者公钥验证 signerInfo 上的签名。返回 (是否通过, 说明)。

    CMS 规定：签名是对 `signedAttrs` 的 DER 编码做的，但签的时候按 **SET OF**（0x31）
    编码，而 SignedData 里存的是 **[0] IMPLICIT**（0xA0）。所以验证前必须把标签改回
    0x31 —— 这是 CMS 验签最经典的一个坑，不改必然验签失败。
    """
    try:
        signed_attrs = signer_info["signed_attrs"]
        if not _present(signed_attrs):
            return None, "signerInfo 没有 signedAttrs（直接签内容，本实现不支持）"
        to_verify = signed_attrs.dump()
        if to_verify[0] == 0xA0:
            to_verify = b"\x31" + to_verify[1:]

        sig_algo = signer_info["signature_algorithm"]["algorithm"].dotted
        signature = signer_info["signature"].native
        # 必须转成 cryptography 的证书：asn1crypto 的 `.public_key` 是 PublicKeyInfo，
        # **没有 `.verify()`**，直接用会 AttributeError（踩过一次）。
        pub = _crypto_public_key(signer_cert)

        # 哈希算法从 **signerInfo.digestAlgorithm** 取，不要从签名算法 OID 推。
        # Authenticode 的签名算法通常是 `1.2.840.113549.1.1.1`（rsaEncryption）——
        # 它**不携带哈希信息**，硬按它查表会一律落到默认值 sha256，
        # 于是 sha1 签名的老文件（如 CMake 的 cpack.exe）验签必然失败。
        digest_oid = signer_info["digest_algorithm"]["algorithm"].dotted
        hash_name = _DIGEST_ALGOS.get(digest_oid, (None, "sha256"))[1]
        from cryptography.hazmat.primitives import hashes

        hash_cls = {"sha1": hashes.SHA1, "sha256": hashes.SHA256,
                    "sha384": hashes.SHA384, "sha512": hashes.SHA512}[hash_name]

        if sig_algo.startswith("1.2.840.113549.1.1"):  # RSA 系列
            from cryptography.hazmat.primitives.asymmetric import padding

            pub.verify(signature, to_verify, padding.PKCS1v15(), hash_cls())
            return True, ""
        if sig_algo.startswith("1.2.840.10045"):  # ECDSA
            from cryptography.hazmat.primitives.asymmetric import ec

            pub.verify(signature, to_verify, ec.ECDSA(hash_cls()))
            return True, ""
        return None, f"不支持的签名算法 {sig_algo}"
    except Exception as exc:  # noqa: BLE001 - 验签失败是正常结果，不是异常
        return False, f"{type(exc).__name__}: {exc}"


def _unwrap_explicit(blob: bytes) -> bytes:
    """剥掉 `[0] EXPLICIT` 包装（0xA0 + 长度），返回内层 DER。

    CMS 的 `EncapsulatedContentInfo.content` 是 `[0] EXPLICIT OCTET STRING`，
    但 asn1crypto 把它当 `Any` 拿（因为内容类型是微软私有的 SpcIndirectDataContent），
    `.dump()` 出来是带包装的，直接 load 会报 "class should have been universal,
    but context was found"。长度按 DER 规则解，别假设只有一字节。
    """
    if len(blob) < 2 or blob[0] != 0xA0:
        return blob
    i = 1
    first = blob[i]
    i += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or i + n > len(blob):
            return blob
        length = int.from_bytes(blob[i : i + n], "big")
        i += n
    else:
        length = first
    return blob[i : i + length]


def _to_crypto_cert(cert: Any):
    """asn1crypto 的 Certificate → cryptography 的 x509.Certificate。"""
    from cryptography import x509 as cx

    return cx.load_der_x509_certificate(cert.dump())


def _crypto_public_key(cert: Any):
    """取公钥对象，兼容 cryptography 的两种 API。

    50.0 起 `Certificate.public_key` 是**方法**（builtin_function_or_method），
    更早的版本是 property。写成 `cert.public_key` 然后直接 `.verify()` 会在新版上报
    `'builtin_function_or_method' object has no attribute 'verify'`（踩过一次）。
    """
    key = _to_crypto_cert(cert).public_key
    return key() if callable(key) else key


def _digest_from_content(signed_data: Any) -> tuple[str | None, bytes | None, str]:
    """从 SpcIndirectDataContent 里取出「签名时算的 PE 摘要」。

    这是判断「文件有没有被改」的基准：签名者签的是这个摘要，
    我们重新算一遍 PE 摘要比对即可。
    """
    try:
        encap = signed_data["encap_content_info"]
        ctype = encap["content_type"].dotted
        if ctype != SPC_INDIRECT_DATA_OID:
            return None, None, f"内容类型不是 SpcIndirectDataContent（{ctype}）"
        content = encap["content"]
        if not _present(content):
            return None, None, "encapContentInfo 为空"
        spc = _SpcIndirectDataContent.load(_unwrap_explicit(content.dump()))
        algo_oid = spc["message_digest"]["digest_algorithm"]["algorithm"].dotted
        algo = _DIGEST_ALGOS.get(algo_oid, (None, None))[1]
        return algo, spc["message_digest"]["digest"].native, ""
    except Exception as exc:  # noqa: BLE001
        return None, None, f"SpcIndirectDataContent 解析失败: {type(exc).__name__}: {exc}"


def _signer_info(signed_data: Any, chain: list[Any]) -> Any | None:
    """找 signerInfo，并让签名者证书排到链首（PKCS#7 不保证顺序）。"""
    try:
        infos = signed_data["signer_infos"]
        if len(infos) == 0:
            return None
        info = infos[0]
    except Exception:  # noqa: BLE001
        return None
    try:
        sid = info["sid"]
        if getattr(sid, "name", None) == "issuer_and_serial_number":
            want_serial = sid.chosen["serial_number"].native
            for i, cert in enumerate(chain):
                if cert.serial_number == want_serial:
                    chain.insert(0, chain.pop(i))
                    break
    except Exception:  # noqa: BLE001 - 排序失败不影响后续（按原顺序试第一张）
        pass
    return info


def _order_chain(certs: list[Any]) -> list[Any]:
    """把证书排成 leaf → … → root。

    PKCS#7 里的证书顺序**没有保证**（实测 QtWebEngineCore.pyd 的第一张就是中间 CA，
    直接当 leaf 去验链会报 "basicConstraints.cA must not be asserted in an EE certificate"）。
    排法：leaf 是"没有被链里任何其它证书当作 issuer"的那张，然后顺着 issuer 往下走。
    """
    by_subject: dict[str, Any] = {}
    for c in certs:
        by_subject.setdefault(c.subject.rfc4514_string(), c)
    issued: set[str] = set()
    for c in certs:
        subj = c.subject.rfc4514_string()
        for other in certs:
            if other is not c and other.issuer.rfc4514_string() == subj:
                issued.add(subj)
                break
    leaves = [c for c in certs if c.subject.rfc4514_string() not in issued]
    ordered: list[Any] = []
    seen: set[str] = set()
    cur = leaves[0] if leaves else certs[0]
    while cur is not None:
        key = cur.subject.rfc4514_string()
        if key in seen:
            break
        seen.add(key)
        ordered.append(cur)
        cur = by_subject.get(cur.issuer.rfc4514_string())
        if cur is not None and cur.subject.rfc4514_string() == key:
            break  # 自签根，到头了
    return ordered or list(certs)


def _is_trusted_root(root: Any) -> bool:
    """根证书是否在本机信任库里（按 subject 精确匹配）。"""
    try:
        want = root.subject.rfc4514_string()
        return any(r.subject.rfc4514_string() == want for r in _system_roots())
    except Exception:  # noqa: BLE001
        return False


def _verify_chain(chain: list[Any]) -> tuple[bool | None, str]:
    """验证证书链：逐环验签 + 有效期 + 根是否受信。

    ⚠️ 不用 `cryptography.x509.verification.PolicyBuilder` —— 它只提供
    `build_client_verifier()` / `build_server_verifier()`，分别强制要求
    clientAuth / serverAuth 扩展密钥用法；而代码签名证书用的是 **codeSigning** EKU，
    拿那两个验证器去验必然报 "required EKU not found"（实测 doclient.dll 就栽在这）。

    三态返回（这个区分很重要，别把"离线查不到"说成"不可信"）：
      True  → 链完整、逐环验签通过、根在本机信任库
      False → 链有问题（断链 / 有效期外 / 签名不符）
      None  → 链本身没问题，但根不在本机信任库，离线环境无法判定可信度
    """
    if not chain:
        return None, "没有证书"
    try:
        certs = [_to_crypto_cert(c) for c in chain]
        ordered = _order_chain(certs)

        for child, parent in zip(ordered, ordered[1:]):
            try:
                child.verify_directly_issued_by(parent)
            except Exception as exc:  # noqa: BLE001
                return False, (
                    f"链断裂：{child.subject.rfc4514_string()[:60]} "
                    f"不是由 {parent.subject.rfc4514_string()[:60]} 签发（{type(exc).__name__}）"
                )

        now = _now()
        for c in ordered:
            try:
                if not (c.not_valid_before_utc <= now <= c.not_valid_after_utc):
                    return False, f"证书不在有效期内：{c.subject.rfc4514_string()[:70]}"
            except AttributeError:  # 老版本 cryptography 没有 *_utc
                pass

        root = ordered[-1]
        if _is_trusted_root(root):
            return True, ""
        return None, (
            f"链完整且逐环验签通过，但根证书（{root.subject.rfc4514_string()[:60]}）"
            "不在本机信任库 —— 离线环境无法判定可信度，按 unknown 处理"
        )
    except Exception as exc:  # noqa: BLE001 - 链验失败是正常结果
        return False, f"{type(exc).__name__}: {str(exc)[:200]}"


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def _system_roots() -> list[Any]:
    """读系统根证书（/etc/ssl/certs 之类）。读不到就返回空表，链验降级为 unknown。"""
    import ssl

    paths = ssl.get_default_verify_paths()
    pem = paths.cafile
    if not pem or not Path(pem).is_file():
        return []
    try:
        from cryptography import x509 as cx

        blob = Path(pem).read_bytes()
        return list(cx.load_pem_x509_certificates(blob))
    except Exception:  # noqa: BLE001
        return []


def analyze(path: Path) -> dict[str, Any]:
    """解析并验证一个 PE 文件的 Authenticode 签名。

    返回结构（字段名与旧 `signature_evidence` 的 `windows_verify` 尽量对齐，
    方便调用方平滑替换）：

        {
          "available": bool,          # 解析流程是否跑通（≠ 签名有效）
          "error": str,               # available=False 时的原因
          "has_signature": bool,      # 有没有内嵌签名表
          "signer": str | None,       # 签名者证书 subject
          "issuer": str | None,       # 签名者证书签发者
          "chain": [ {subject, issuer, not_before, not_after}, ... ],
          "digest_algorithm": str|None,
          "digest_match": bool|None,  # 重算的 PE 摘要 == 签名时声明的摘要
          "signature_valid": bool|None,  # signedAttrs 上的签名验过了
          "chain_valid": bool|None,   # 证书链验到系统根
          "timestamped": bool,        # 有没有 RFC3161 时间戳副签名
          "conclusion": str,          # valid_signed_embedded / not_signed / unknown / tampered / ...
          "note": str,
        }
    """
    try:
        import pefile  # type: ignore
    except ImportError:
        return _unknown("pefile not installed")

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return _unknown("不是 PE 文件")

    try:
        cert_off, cert_size = _security_directory(pe)
        if cert_off <= 0 or cert_size <= 0:
            # 没内嵌签名 ≠ 没签名：Windows 系统文件大量走目录签名（Catalog），
            # 那部分在 C:\Windows\System32\CatRoot 里，Linux 侧拿不到。
            return {
                "available": True,
                "error": "",
                "has_signature": False,
                "signer": None, "signer_cn": None, "issuer": None, "chain": [],
                "digest_algorithm": None, "digest_match": None,
                "signature_valid": None, "chain_valid": None, "timestamped": False,
                "conclusion": "no_embedded_signature",
                "note": SIGNATURE_NOTE,
            }

        try:
            raw = path.read_bytes()
        except OSError as exc:
            return _unknown(f"读取文件失败: {exc}")

        content_info, err = _parse_blob(raw, cert_off, cert_size)
        if content_info is None:
            return _unknown(f"签名表解析失败: {err}", has_signature=True)

        signed_data = content_info["content"]
        chain = _chain_from_signed_data(signed_data)
        signer_info = _signer_info(signed_data, chain)
        if signer_info is None or not chain:
            return _unknown("PKCS#7 里没有签名者证书", has_signature=True)

        algo, declared_digest, derr = _digest_from_content(signed_data)
        digest_match: bool | None = None
        if algo and declared_digest:
            computed = authenticode_digest(raw, pe, algo)
            digest_match = bool(computed is not None and computed == declared_digest)

        sig_ok, _sig_msg = _verify_signed_attrs(signed_data, signer_info, chain[0])
        chain_ok, _chain_msg = _verify_chain(chain)

        timestamped = _present(signer_info["unsigned_attrs"])

        signer_subject = chain[0].subject.human_friendly
        issuer_subject = chain[0].issuer.human_friendly
        # CN 直接从证书的 native 结构里取 —— 别去 parse human_friendly 字符串，
        # 那个格式是 "Common Name: xxx, Organization: ..."，不是 RFC4514 的 "CN=xxx"。
        try:
            signer_cn = chain[0].subject.native.get("common_name")
        except Exception:  # noqa: BLE001
            signer_cn = None

        if digest_match is False:
            conclusion = "tampered"
        elif sig_ok and digest_match:
            conclusion = "valid_signed_embedded"
        elif sig_ok is False:
            conclusion = "signature_invalid"
        else:
            conclusion = "unknown"

        return {
            "available": True,
            "error": "",
            "has_signature": True,
            "signer": signer_subject,
            "signer_cn": signer_cn,
            "issuer": issuer_subject,
            "chain": [
                {
                    "subject": c.subject.human_friendly,
                    "issuer": c.issuer.human_friendly,
                    "not_before": str(c["tbs_certificate"]["validity"]["not_before"].native),
                    "not_after": str(c["tbs_certificate"]["validity"]["not_after"].native),
                }
                for c in chain
            ],
            "digest_algorithm": algo,
            "digest_match": digest_match,
            "signature_valid": sig_ok,
            "chain_valid": chain_ok,
            "timestamped": timestamped,
            "conclusion": conclusion,
            "note": SIGNATURE_NOTE,
        }
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001
            pass


SIGNATURE_NOTE = (
    "本字段只覆盖 **PE 内嵌签名**。没有内嵌签名 ≠ 没有签名 —— "
    "Windows 系统文件大量使用目录签名（Catalog），其签名存放在 "
    r"C:\Windows\System32\CatRoot，本工具在非 Windows 环境下取不到。"
    "conclusion=no_embedded_signature / unknown 时**不得断言文件『无数字签名』**。"
)


def _unknown(reason: str, has_signature: bool = False) -> dict[str, Any]:
    return {
        "available": False,
        "error": reason,
        "has_signature": has_signature,
        "signer": None, "signer_cn": None, "issuer": None, "chain": [],
        "digest_algorithm": None, "digest_match": None,
        "signature_valid": None, "chain_valid": None, "timestamped": False,
        "conclusion": "unknown",
        "note": SIGNATURE_NOTE,
    }
