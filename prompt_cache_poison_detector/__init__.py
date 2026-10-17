"""prompt-cache-poison-detector: detect cache-isolation failures in multi-tenant LLM prompt caches."""

from .cache_schemes import (
    CacheScheme,
    derive_key_anonymized,
    derive_key_tenant_scoped,
    derive_key_global,
    derive_key_prefix_scoped,
)
from .simulator import TenantCacheSimulator, Tenant, SIMULATED_SCHEMES
from .detector import run_detection, DetectionResult, Finding

__all__ = [
    "CacheScheme",
    "derive_key_anonymized",
    "derive_key_tenant_scoped",
    "derive_key_global",
    "derive_key_prefix_scoped",
    "TenantCacheSimulator",
    "Tenant",
    "SIMULATED_SCHEMES",
    "run_detection",
    "DetectionResult",
    "Finding",
]

__version__ = "1.0.0"
