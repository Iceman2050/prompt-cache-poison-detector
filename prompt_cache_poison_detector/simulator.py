"""In-memory multi-tenant prompt-cache simulator.

A faithful-enough model of a real LLM prompt-caching layer: key derivation
per scheme, TTL expiry, byte-size accounting, hit/miss counters, and an
optional "warming" phase. The detector uses it to run cross-tenant poisoning
tests without touching any real provider.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .cache_schemes import DERIVE_FNS, SCHEMES


@dataclass
class Tenant:
    tenant_id: str
    label: str = ""


@dataclass
class CacheEntry:
    key: str
    tenant: str
    prompt: str
    completion: str
    created_at: float = field(default_factory=time.monotonic)
    hits: int = 0


class TenantCacheSimulator:
    """One shared cache instance, N tenants, one key-derivation scheme."""

    def __init__(self, scheme: str, ttl_seconds: float = 3600.0) -> None:
        if scheme not in SCHEMES:
            raise ValueError(f"unknown scheme {scheme!r}; pick from {sorted(SCHEMES)}")
        self.scheme = scheme
        self.ttl = ttl_seconds
        self._derive = DERIVE_FNS[scheme]
        self._store: dict[str, CacheEntry] = {}
        self.lookups = 0
        self.hits = 0

    def _purge_expired(self) -> None:
        now = time.monotonic()
        expired = [k for k, e in self._store.items() if now - e.created_at > self.ttl]
        for k in expired:
            del self._store[k]

    def store(self, tenant: Tenant, prompt: str, completion: str) -> str:
        """Store a completion under the scheme's derived key. Returns the key."""
        self._purge_expired()
        key = self._derive(prompt, tenant.tenant_id)
        self._store[key] = CacheEntry(key=key, tenant=tenant.tenant_id,
                                      prompt=prompt, completion=completion)
        return key

    def lookup(self, tenant: Tenant, prompt: str) -> CacheEntry | None:
        """Look up a prompt as `tenant`. Returns the entry on key collision."""
        self._purge_expired()
        self.lookups += 1
        key = self._derive(prompt, tenant.tenant_id)
        entry = self._store.get(key)
        if entry is not None:
            self.hits += 1
            entry.hits += 1
        return entry

    def bytes_used(self) -> int:
        return sum(len(e.prompt.encode()) + len(e.completion.encode())
                   for e in self._store.values())

    def stats(self) -> dict:
        return {
            "scheme": self.scheme,
            "entries": len(self._store),
            "lookups": self.lookups,
            "hits": self.hits,
            "bytes": self.bytes_used(),
        }


SIMULATED_SCHEMES = sorted(SCHEMES)
