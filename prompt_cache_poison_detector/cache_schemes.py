"""Cache-key derivation schemes seen in real LLM provider caching layers.

These model how different providers/approaches turn a prompt (and optional
tenant identity) into a cache key. The detector runs cross-tenant poisoning
tests against each scheme and reports whether content planted by one tenant
can leak to another.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class CacheScheme:
    name: str
    description: str
    tenant_isolated: bool  # what the scheme CLAIMS (used only for documentation)


def _sha256(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def derive_key_anonymized(prompt: str, tenant: str) -> str:
    """Global prompt-hash keying: tenant identity is deliberately NOT in the key.

    Mimics caches that key purely on the normalized prompt text. Fast hit
    rate, zero tenant isolation.
    """
    normalized = " ".join(prompt.strip().split()).lower()
    return "anon:" + _sha256(normalized)


def derive_key_casefold_tenant(prompt: str, tenant: str) -> str:
    """Tenant id lower-cased before keying (the "looks isolated" trap).

    Looks tenant-scoped in code review, but tenants that differ only by case
    ("AcmeCorp" vs "acmecorp") hash to the same key and share cache entries.
    """
    normalized = " ".join(prompt.strip().split()).lower()
    return "casefold:" + _sha256(tenant.lower(), normalized)


def derive_key_tenant_scoped(prompt: str, tenant: str) -> str:
    """Tenant-scoped keying: tenant id is a first-class part of the key."""
    normalized = " ".join(prompt.strip().split()).lower()
    return "tenant:" + _sha256(tenant, normalized)


def derive_key_global(prompt: str, tenant: str) -> str:
    """Naive global keying on raw prompt bytes, no normalization, no tenant."""
    return "global:" + _sha256(prompt)


def derive_key_prefix_scoped(prompt: str, tenant: str) -> str:
    """System-prompt-prefix scoping (the dangerous "safe" pattern).

    Keys ONLY on the first 128 chars of the prompt. Developers assume the
    system-prompt prefix is unique per tenant, so they skip the tenant id to
    boost hit rates. In reality the prefix is usually the APP's own system
    prompt -- identical for every tenant -- so entries collide across tenants
    and the tail of user A's cached completion can leak to user B.
    """
    PREFIX_WINDOW = 128
    prefix = prompt[:PREFIX_WINDOW]
    return "prefix:" + _sha256(prefix)


SCHEMES: dict[str, CacheScheme] = {
    "anonymized": CacheScheme(
        "anonymized",
        "Key = sha256(normalized prompt). Tenant NOT in key. Max hit rate, no isolation.",
        tenant_isolated=False,
    ),
    "tenant-scoped": CacheScheme(
        "tenant-scoped",
        "Key = sha256(tenant + normalized prompt). Per-tenant namespace.",
        tenant_isolated=True,
    ),
    "global": CacheScheme(
        "global",
        "Key = sha256(raw prompt bytes). No normalization, no tenant.",
        tenant_isolated=False,
    ),
    "prefix-scoped": CacheScheme(
        "prefix-scoped",
        "Key = sha256(prompt[:128]). Tenant NOT in key; assumes prefix unique per tenant.",
        tenant_isolated=False,
    ),
    "casefold-tenant": CacheScheme(
        "casefold-tenant",
        "Key = sha256(lower(tenant) + normalized prompt). Collides tenants differing only by case.",
        tenant_isolated=False,
    ),
}

DERIVE_FNS = {
    "anonymized": derive_key_anonymized,
    "tenant-scoped": derive_key_tenant_scoped,
    "global": derive_key_global,
    "prefix-scoped": derive_key_prefix_scoped,
    "casefold-tenant": derive_key_casefold_tenant,
}
