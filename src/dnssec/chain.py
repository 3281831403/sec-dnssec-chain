"""DNSSEC 委派链校验的唯一实现文件。

本模块提供 8 个公开函数。所有输入都是调用方注入的普通 Python 数据，
实现不得联网、不得做真实 DNS 查询、不得使用随机数。

委派链的约定顺序是叶子在前、信任锚在后，链中每个元素至少包含：

    zone       本层区域名
    dnskey     本层区域的 DNSKEY
    ds         父区域为本层 DNSKEY 发布的 DS，信任锚层为 None
    rrset      本层被签名的记录集
    rrsig      覆盖 rrset 的 RRSIG

RRSIG、DS、DNSKEY 的字段均为小写蛇形命名，时间均为整数秒。
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Any

_DIGESTS = {1: "sha1", 2: "sha256", 4: "sha384"}


def name_labels(name: str) -> list[str]:
    """把 DNS 名称切成标签列表，根名称返回空列表。

    末尾的一个根点必须去掉，不能产生空标签。连续的点、空标签和空名称
    都返回空列表。通配符名称的第一个标签保留为星号，以便调用方识别。
    大小写不改变标签数，本函数不做规范化。
    """
    if not isinstance(name, str) or name == "":
        return []

    # 缺陷 1 修复：切分前先去掉末尾唯一的根点，使 "." 得到空名称而不是
    # ["", ""]，避免根区被多算一层。
    if name.endswith("."):
        name = name[:-1]

    if name == "":
        return []

    labels = name.split(".")
    # 连续点号 / 内部空标签属于非法名称，按契约返回空列表。
    if any(label == "" for label in labels):
        return []

    return labels


def parse_rrset(rrset: dict[str, Any]) -> dict[str, Any]:
    """解析记录集，返回 name、type、ttl、rdata、rrsig、labels 六个键。

    labels 是本记录集名称的标签数，根名称必须为 0。名称末尾的根点不
    构成标签；通配符名称中的星号算一个标签，由 name_labels 单独标记。
    rrsig 缺失时返回 None。输入字段只读，不得修改调用方传入的字典。
    """
    name = rrset["name"]
    return {
        "name": name,
        "type": rrset["type"],
        "ttl": rrset["ttl"],
        "rdata": rrset["rdata"],
        "rrsig": rrset.get("rrsig"),
        "labels": len(name_labels(name)),
    }


def check_labels(rrsig: dict[str, Any], name: str) -> bool:
    """判断 RRSIG 的标签计数是否与实际名称匹配。

    RRSIG.labels 记录签名时的标签数。精确匹配时两者相等；通配符展开后
    实际名称比签名名称多一个标签，因此必须给 RRSIG.labels 加一后再比较，
    并且只有 signer 以星号加点开头时才允许这种展开。通配符名称本身不
    把星号计入 RRSIG.labels。根名称的标签数为 0。
    """
    if not isinstance(rrsig, dict):
        return False

    declared = rrsig.get("labels")
    if not _is_plain_int(declared) or declared < 0:
        return False

    actual = len(name_labels(name))

    # 精确匹配：实际标签数与 RRSIG 声明一致。
    if actual == declared:
        return True

    # 缺陷 2 修复：通配符展开会多出一个标签，必须用 declared + 1 与实际
    # 标签数比较，且仅当 signer 显式以 "*." 开头时才允许这种展开。
    signer = rrsig.get("signer")
    wildcard_signer = isinstance(signer, str) and signer.startswith("*.")
    if wildcard_signer and actual == declared + 1:
        return True

    return False


def _is_plain_int(value: Any) -> bool:
    """时间等字段要求真正的 int；bool 虽是 int 子类，也不接受。"""
    return isinstance(value, int) and not isinstance(value, bool)


def ds_matches(ds: dict[str, Any], dnskey: dict[str, Any]) -> bool:
    """判断 DS 是否匹配 DNSKEY。

    DS 声明了 key_tag、algorithm、digest_type 和十六进制 digest；DNSKEY
    声明了 name、flags、protocol、algorithm、key_tag 和十六进制 public_key。
    摘要材料是规范化后的 owner name、DNSKEY RDATA 的 flags/protocol/algorithm
    三字节前缀和公钥字节。摘要算法必须使用 DS 里声明的 digest_type，
    比较必须覆盖完整摘要，不能使用前缀或子串。任何字段缺失、类型错误、
    十六进制非法或未知算法都返回 False。
    """
    if not isinstance(ds, dict) or not isinstance(dnskey, dict):
        return False

    try:
        # key_tag 与 algorithm 必须先一致；算法迁移 / 错配在此被拦下。
        if ds.get("key_tag") != dnskey.get("key_tag"):
            return False
        if ds.get("algorithm") != dnskey.get("algorithm"):
            return False

        # 缺陷 3 修复：摘要算法按 DS 记录声明的 digest_type 选择，而不是
        # 使用某个当前默认值。
        digest_type = ds["digest_type"]
        algorithm_name = _DIGESTS.get(digest_type)
        if algorithm_name is None:
            return False

        owner_wire = dnskey["name"].lower().rstrip(".").encode("ascii")
        rdata_prefix = struct.pack(
            "!HBB",
            dnskey["flags"],
            dnskey["protocol"],
            dnskey["algorithm"],
        )
        public_key = bytes.fromhex(dnskey["public_key"])
        material = owner_wire + rdata_prefix + public_key

        expected_digest = hashlib.new(algorithm_name, material).digest()
        provided_digest = bytes.fromhex(ds["digest"])
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        UnicodeError,
        struct.error,
    ):
        return False

    # 缺陷 4 修复：完整、定长的摘要比较（常量时间），绝不使用 startswith
    # 之类的前缀比较，短摘要不可能命中。
    return hmac.compare_digest(expected_digest, provided_digest)


def check_validity(rrsig: dict[str, Any], now: int) -> bool:
    """判断 RRSIG 在 now 时刻是否处于有效期内。

    有效期是闭区间：now 等于 inception 或 expiration 都算有效。起点必须
    严格早于终点，inception 等于 expiration 的零长度窗口一律无效。
    时间字段缺失、不是整数或时间顺序颠倒时返回 False。
    """
    if not _is_plain_int(now) or not isinstance(rrsig, dict):
        return False

    inception = rrsig.get("inception")
    expiration = rrsig.get("expiration")
    if not _is_plain_int(inception) or not _is_plain_int(expiration):
        return False

    # 缺陷 6 修复：起点必须严格早于终点，相等的零长度窗口无效；
    # inception > expiration 的颠倒窗口同样在此被拒。
    if inception >= expiration:
        return False

    # 缺陷 5 修复：同时比较起点与终点，未生效（now < inception）拒绝；
    # 两端均为闭区间。
    return inception <= now <= expiration


def verify_chain(
    zone_chain: list[dict[str, Any]],
    trust_anchor: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    """逐层验证委派链，返回 ok、index、reason、chain_length 四个键。

    zone_chain 按叶子到信任锚排列。正确顺序是从下标 0 的叶子开始向锚
    回溯，每层依次校验签名有效期、标签计数和本层 DS 与 DNSKEY 的匹配；
    最后一层必须与 trust_anchor 的 DNSKEY 一致。遇到第一个失败立即返回，
    index 为该层下标，reason 为 validity、labels、ds 或 anchor。全部通过
    时 ok 为 True、index 为 -1；空链返回失败。
    """
    chain_length = len(zone_chain)

    if chain_length == 0:
        return {
            "ok": False,
            "index": -1,
            "reason": "anchor",
            "chain_length": 0,
        }

    # 缺陷 7 修复：严格从下标 0 的叶子开始，逐层向信任锚回溯，任何中间层
    # 都不会被跳过。
    for index, layer in enumerate(zone_chain):
        if not isinstance(layer, dict):
            return _chain_failure(index, "validity", chain_length)

        rrsig = layer.get("rrsig")

        # 每层顺序：有效期 -> 标签计数 -> DS/DNSKEY。
        if not check_validity(rrsig, now):
            return _chain_failure(index, "validity", chain_length)

        rrset = layer.get("rrset")
        if isinstance(rrset, dict) and "name" in rrset:
            signed_name = rrset["name"]
        else:
            signed_name = layer.get("zone", "")
        if not check_labels(rrsig, signed_name):
            return _chain_failure(index, "labels", chain_length)

        ds = layer.get("ds")
        if ds is not None and not ds_matches(ds, layer.get("dnskey")):
            return _chain_failure(index, "ds", chain_length)

        # 缺陷 8 修复：每个失败点都立即返回，因此给出的是从叶子方向遇到的
        # 第一个失败，而不是继续走到锚点后留下的最后一个失败。

    # 回溯到末端后，最后一层 DNSKEY 必须与信任锚完全一致。
    anchor_dnskey = (
        trust_anchor.get("dnskey") if isinstance(trust_anchor, dict) else None
    )
    anchor_layer_dnskey = zone_chain[-1].get("dnskey")
    if anchor_layer_dnskey is None or anchor_layer_dnskey != anchor_dnskey:
        return _chain_failure(chain_length - 1, "anchor", chain_length)

    return {
        "ok": True,
        "index": -1,
        "reason": None,
        "chain_length": chain_length,
    }


def _chain_failure(index: int, reason: str, chain_length: int) -> dict[str, Any]:
    return {
        "ok": False,
        "index": index,
        "reason": reason,
        "chain_length": chain_length,
    }


def _normalize_interval_name(name: Any) -> Any:
    """否定区间比较前做 DNS 名称层面的规范化：小写、去末尾根点。"""
    if not isinstance(name, str):
        return name
    return name.lower().rstrip(".")


def denial_proof(nsec: dict[str, Any], name: str) -> bool:
    """判断 NSEC 是否给出目标名不存在的权威否定证明。

    NSEC 的 owner 是区间起点，next 是区间终点，目标名必须被区间严格包围：
    目标不得等于 owner 或 next。普通区间按 owner 小于 next 处理，跨越
    根的回绕区间按目标大于 owner 或目标小于 next 处理。除了区间覆盖，
    还必须确认该 NSEC 带有 authoritative 为真的标记和可用的 rrsig，
    否则证明无效。
    """
    if not isinstance(nsec, dict):
        return False

    # 缺陷 9 修复：区间本身必须由权威服务器用 RRSIG 签名保护；缺少任一
    # 条件，即使名字落在区间空档内也不能作为否定证明。
    if not nsec.get("authoritative"):
        return False
    rrsig = nsec.get("rrsig")
    if not isinstance(rrsig, dict) or not rrsig:
        return False

    owner = _normalize_interval_name(nsec.get("owner"))
    next_name = _normalize_interval_name(nsec.get("next"))
    target = _normalize_interval_name(name)

    if not all(isinstance(value, str) for value in (owner, next_name, target)):
        return False

    # 严格包围：命中端点（owner 或 next 自身存在 NSEC/RRset）不算空档。
    if target == owner or target == next_name:
        return False

    if owner < next_name:
        # 普通词法区间 (owner, next)。
        return owner < target < next_name

    # 跨根回绕区间：(owner, 根] 与 [根, next) 两段并集。
    return target > owner or target < next_name


def chain_batch(
    queries: list[dict[str, Any]],
    policy: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    """批量验证查询，返回 ok 与 results 两个键。

    queries 中每个元素包含 zone_chain 与 trust_anchor。每个查询必须独立
    调用 verify_chain，不能复用前一个查询的链上下文、缓存或验证状态。
    results 与 queries 等长且顺序一致；只有全部查询通过时 ok 才为 True。
    policy 为调用方策略，本桩不据此改变逐查询验证语义。
    """
    # 缺陷 10 修复：无共享链上下文、无缓存；逐查询独立调用模块全局的
    # verify_chain（运行时解析，monkeypatch chain.verify_chain 可生效），
    # 每次都得到全新的结果字典。
    results = [
        verify_chain(query["zone_chain"], query["trust_anchor"], now)
        for query in queries
    ]

    return {
        "ok": all(bool(result.get("ok")) for result in results),
        "results": results,
    }
