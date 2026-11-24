"""sec-dnssec-chain 的红灯测试。

共 15 个测试：前 10 个一一对应题面的 10 个缺陷，后 5 个是正向与回归断言。
测试只使用构造的 DNS 数据，不联网、不读取随机数、不进行真实 DNS 查询。
tests/test_chain.py 交付后不可修改。
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from dnssec import chain
from dnssec.chain import (
    chain_batch,
    check_labels,
    check_validity,
    denial_proof,
    ds_matches,
    name_labels,
    parse_rrset,
    verify_chain,
)

NOW = 1500


def _key(name, key_tag, public_key):
    return {
        "name": name,
        "key_tag": key_tag,
        "algorithm": 8,
        "flags": 257,
        "protocol": 3,
        "public_key": public_key,
    }


ROOT_KEY = _key(".", 1, "aa11")
EXAMPLE_KEY = _key("example.", 3, "bb22")
WWW_KEY = _key("www.example.", 4, "cc33")


def _ds_for(key, digest_type=2):
    material = (
        key["name"].lower().rstrip(".").encode("ascii")
        + struct.pack(
            "!HBB",
            key["flags"],
            key["protocol"],
            key["algorithm"],
        )
        + bytes.fromhex(key["public_key"])
    )
    algorithm = {1: "sha1", 2: "sha256", 4: "sha384"}[digest_type]
    return {
        "key_tag": key["key_tag"],
        "algorithm": key["algorithm"],
        "digest_type": digest_type,
        "digest": hashlib.new(algorithm, material).hexdigest(),
    }


def _sig(
    labels,
    signer=".",
    inception=1000,
    expiration=2000,
    key_tag=1,
):
    return {
        "key_tag": key_tag,
        "algorithm": 8,
        "labels": labels,
        "inception": inception,
        "expiration": expiration,
        "signer": signer,
        "signature": "deadbeef",
    }


def _layer(
    zone,
    key,
    labels,
    ds=None,
    signer=".",
    inception=1000,
    expiration=2000,
):
    return {
        "zone": zone,
        "dnskey": key,
        "ds": ds,
        "rrset": {
            "name": zone,
            "type": "NS",
            "ttl": 300,
            "rdata": ["ns." + zone if zone != "." else "."],
        },
        "rrsig": _sig(
            labels,
            signer=signer,
            inception=inception,
            expiration=expiration,
            key_tag=key["key_tag"],
        ),
    }


def _two_layer():
    example = _layer("example.", EXAMPLE_KEY, 1, _ds_for(EXAMPLE_KEY))
    root = _layer(".", ROOT_KEY, 0, None)
    return [example, root], {"zone": ".", "dnskey": ROOT_KEY}


def _three_layer():
    leaf = _layer("www.example.", WWW_KEY, 2, _ds_for(WWW_KEY))
    middle = _layer("example.", EXAMPLE_KEY, 1, _ds_for(EXAMPLE_KEY))
    root = _layer(".", ROOT_KEY, 0, None)
    return [leaf, middle, root], {"zone": ".", "dnskey": ROOT_KEY}


def _nsec(owner, next_name):
    return {
        "owner": owner,
        "next": next_name,
        "types": ["A", "RRSIG", "NSEC"],
        "authoritative": True,
        "rrsig": _sig(2, signer="example."),
    }


# 缺陷 1：名称标签切分不去尾点，根区名称多出一层。
def test_root_name_labels_do_not_count_extra_layer():
    assert name_labels(".") == []
    assert name_labels("example.") == ["example"]
    assert name_labels("www.example.") == ["www", "example"]

    parsed = parse_rrset(
        {
            "name": ".",
            "type": "SOA",
            "ttl": 3600,
            "rdata": ["ns."],
            "rrsig": _sig(0),
        }
    )
    assert parsed["name"] == "."
    assert parsed["type"] == "SOA"
    assert parsed["ttl"] == 3600
    assert parsed["labels"] == 0


# 缺陷 2：通配符展开后标签数不加一。
def test_wildcard_expansion_adds_one_label():
    wildcard_sig = _sig(1, signer="*.example.")
    assert check_labels(wildcard_sig, "www.example.") is True
    assert check_labels(wildcard_sig, "*.example.") is True
    assert check_labels(wildcard_sig, "deep.www.example.") is False
    assert check_labels(_sig(2), "www.example.") is True


# 缺陷 3：摘要算法不按 DS 声明计算。
def test_ds_matches_obeys_declared_digest_type():
    for digest_type in (1, 2, 4):
        assert ds_matches(
            _ds_for(EXAMPLE_KEY, digest_type), EXAMPLE_KEY
        ) is True

    wrong_algorithm = _ds_for(EXAMPLE_KEY)
    wrong_algorithm["algorithm"] = 13
    assert ds_matches(wrong_algorithm, EXAMPLE_KEY) is False


# 缺陷 4：摘要比较使用前缀比较。
def test_ds_matches_rejects_truncated_digest():
    truncated = _ds_for(EXAMPLE_KEY)
    truncated["digest"] = truncated["digest"][:16]
    assert ds_matches(truncated, EXAMPLE_KEY) is False


# 缺陷 5：有效期只比较终止时间。
def test_signature_not_yet_valid_is_rejected():
    future = _sig(1, inception=2600, expiration=3000)
    assert check_validity(future, 2500) is False

    active = _sig(1, inception=2000, expiration=3000)
    assert check_validity(active, 2500) is True


# 缺陷 6：有效期允许起始等于终止。
def test_zero_length_validity_window_is_rejected():
    zero = _sig(1, inception=2500, expiration=2500)
    assert check_validity(zero, 2500) is False

    normal = _sig(1, inception=2000, expiration=3000)
    assert check_validity(normal, 3000) is True


# 缺陷 7：链验证从信任锚开始，跳过中间层的 DS 匹配。
def test_chain_checks_every_layer_from_leaf_to_anchor():
    zone_chain, anchor = _three_layer()
    zone_chain[1]["ds"] = _ds_for(ROOT_KEY)
    assert len(zone_chain) == 3

    result = verify_chain(zone_chain, anchor, NOW)
    assert result["chain_length"] == 3
    assert result["ok"] is False
    assert result["index"] == 1
    assert result["reason"] == "ds"


# 缺陷 8：链验证返回最后一个失败点而不是第一个。
def test_chain_returns_first_failure_from_leaf():
    zone_chain, anchor = _three_layer()
    zone_chain[0]["rrsig"] = _sig(2, inception=2600, expiration=3000)
    zone_chain[2]["rrsig"] = _sig(0, inception=2600, expiration=3000)

    result = verify_chain(zone_chain, anchor, NOW)
    assert result["ok"] is False
    assert result["index"] == 0


# 缺陷 9：否定证明不检查 NSEC 是否由权威签名保护。
def test_denial_proof_requires_authoritative_signature():
    unsigned = {
        "owner": "a.example.",
        "next": "m.example.",
        "authoritative": True,
        "rrsig": None,
    }
    assert denial_proof(unsigned, "d.example.") is False

    unsigned_authority = {
        "owner": "a.example.",
        "next": "m.example.",
        "authoritative": False,
        "rrsig": _sig(2, signer="example."),
    }
    assert denial_proof(unsigned_authority, "d.example.") is False


# 缺陷 10：批量验证复用第一个查询的验证状态。
def test_chain_batch_does_not_reuse_first_result(monkeypatch):
    def fake_verify(zone_chain, trust_anchor, now):
        return {
            "ok": zone_chain["valid"],
            "index": -1,
            "reason": None,
            "chain_length": 1,
        }

    monkeypatch.setattr(chain, "verify_chain", fake_verify)
    queries = [
        {"zone_chain": {"valid": True}, "trust_anchor": {}},
        {"zone_chain": {"valid": False}, "trust_anchor": {}},
        {"zone_chain": {"valid": True}, "trust_anchor": {}},
    ]
    result = chain_batch(queries, {"independent": True}, NOW)
    assert [item["ok"] for item in result["results"]] == [True, False, True]
    assert result["ok"] is False


# 正向 1：两层完整链验证通过。
def test_two_layer_chain_verifies():
    zone_chain, anchor = _two_layer()
    assert len(zone_chain) == 2

    result = verify_chain(zone_chain, anchor, NOW)
    assert result["chain_length"] == 2
    assert result["ok"] is True
    assert result["index"] == -1
    assert result["reason"] is None


# 正向 2：中间层摘要不符立即失败并返回该层下标。
def test_middle_ds_mismatch_returns_that_index():
    zone_chain, anchor = _three_layer()
    zone_chain[1]["ds"] = _ds_for(ROOT_KEY)

    result = verify_chain(zone_chain, anchor, NOW)
    assert result["ok"] is False
    assert result["index"] == 1
    assert result["reason"] == "ds"


# 正向 3：有效期端点闭区间，过期立即拒绝。
def test_validity_endpoints_are_inclusive_and_expiry_rejected():
    sig = _sig(1, inception=2000, expiration=3000)
    assert check_validity(sig, 2000) is True
    assert check_validity(sig, 3000) is True
    assert check_validity(sig, 1999) is False
    assert check_validity(sig, 3001) is False


# 正向 4：否定证明覆盖目标名时成立、不覆盖时失败。
def test_denial_proof_interval_coverage():
    nsec = _nsec("a.example.", "m.example.")
    assert denial_proof(nsec, "d.example.") is True
    assert denial_proof(nsec, "z.example.") is False
    assert denial_proof(nsec, "a.example.") is False


# 正向 5：两批独立验证与单独验证结果一致。
def test_two_batches_match_individual_verification():
    valid_chain, valid_anchor = _two_layer()
    invalid_chain, invalid_anchor = _two_layer()
    invalid_chain[0]["rrsig"] = _sig(1, inception=2600, expiration=3000)

    queries = [
        {"zone_chain": valid_chain, "trust_anchor": valid_anchor},
        {"zone_chain": invalid_chain, "trust_anchor": invalid_anchor},
        {"zone_chain": valid_chain, "trust_anchor": valid_anchor},
    ]
    expected = [True, False, True]
    individual = [
        verify_chain(
            query["zone_chain"],
            query["trust_anchor"],
            NOW,
        )["ok"]
        for query in queries
    ]

    batch_one = chain_batch(queries, {"independent": True}, NOW)
    batch_two = chain_batch(queries, {"independent": True}, NOW)

    assert individual == expected
    assert [item["ok"] for item in batch_one["results"]] == expected
    assert [item["ok"] for item in batch_two["results"]] == expected
    assert batch_one["results"] == batch_two["results"]
    assert [item["ok"] for item in batch_one["results"]] == individual