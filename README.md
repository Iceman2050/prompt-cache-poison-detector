# prompt-cache-poison-detector

**Your LLM app caches prompts to save money. What if user A's cached answer is served to user B?**

Prompt caching is a standard cost optimization — but in multi-tenant apps, one wrong cache-key design turns it into a cross-tenant data leak. This tool simulates the cache-key derivation schemes real providers and homegrown layers use, runs attacker-vs-victim poisoning tests against each one, and tells you in 30 seconds whether your scheme is **ISOLATED**, **SUSPECT**, or **CONFIRMED** leaking — with evidence.

## Quickstart

```bash
# zero dependencies, Python 3.9+
git clone https://github.com/Iceman2050/prompt-cache-poison-detector
cd prompt-cache-poison-detector
python -m prompt_cache_poison_detector          # test all schemes
python -m prompt_cache_poison_detector --scheme tenant-scoped   # test one
python -m prompt_cache_poison_detector --list-schemes           # describe schemes
python -m unittest discover -s tests            # run the test suite
```

## Example output

Machine-verified against a fresh run of `python -m prompt_cache_poison_detector` (exit code 2 = findings present; canary tokens are random per run):

```
prompt-cache-poison-detector report
========================================
[CONFIRMED] anonymized
           victim tenant 'tenant-victim' received attacker's cached completion containing canary CANARY-e5400e1d4d2a (planted by 'tenant-attacker'). Keys match: attacker_key == victim_key.
[SUSPECT  ] casefold-tenant
           partial isolation failure: tenants 'AcmeCorp' and 'acmecorp' derived the same cache key, so victim received attacker content containing canary CANARY-92a9cf7505e9. Tenants distinguished only by case share cache entries.
[CONFIRMED] global
           victim tenant 'tenant-victim' received attacker's cached completion containing canary CANARY-719dab6ab39f (planted by 'tenant-attacker'). Keys match: attacker_key == victim_key.
[CONFIRMED] prefix-scoped
           victim tenant 'tenant-victim' received attacker's cached completion containing canary CANARY-afd1deb2ed4f (planted by 'tenant-attacker'). Keys match: attacker_key == victim_key.
[ISOLATED ] tenant-scoped
           no cross-tenant leak: victim lookups (identical prompt, shared-prefix probe, and case-variant-tenant probe) never returned attacker content.
========================================
schemes tested: 5 | ISOLATED=1 SUSPECT=1 CONFIRMED=3
```

## How it works

1. **Cache-key derivation** (`cache_schemes.py`) — five schemes modeled on real designs: `anonymized` (key on prompt only), `global` (key on raw prompt bytes), `prefix-scoped` (key on the first 128 chars — the "shared system prompt" trap), `casefold-tenant` (tenant lower-cased before keying), and `tenant-scoped` (tenant is a first-class key part).
2. **In-memory tenant simulator** (`simulator.py`) — shared cache, N tenants, TTL expiry, hit/miss stats. No network, no API keys, deterministic.
3. **Poisoning tests** (`detector.py`) — attacker plants a completion containing a random canary; victim looks up the identical prompt, a shared-prefix variant, and a case-variant tenant id. Canary exfiltration across tenants = isolation failure.

## Ethical use

This is a defensive testing tool. Use it only on **your own applications** or targets you have explicit permission to test. Do not use it to probe third-party services.

## What it does NOT do

- It does **not** connect to any real LLM provider or inspect a real cache — all tests run against the in-memory simulator.
- It does **not** prove your production cache is safe — it proves *classes of key-derivation designs* leak or hold. Your implementation may differ in normalization, TTL, or key handling.
- It does **not** cover side-channel leaks (timing, hit/miss oracles) — only direct cross-tenant content exfiltration.
- It is **not** legal advice or a compliance certification for SOC 2 / HIPAA / GDPR tenant isolation.

## Built by Ingenious AI
- DisclosureGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DisclosureGuard.
- ModelMinder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ModelMinder.
- TermsWatch — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20TermsWatch.
- Vibe-Code Audit — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.
- Rogue-Agent Defense — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.
- BreachHunter — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20BreachHunter.
- ChatBreaker — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ChatBreaker.
- Agent Flight Recorder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.
- Agent Auth Gateway — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.
- DomainGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DomainGuard.
- ContentCraft AI — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ContentCraft%20AI.
Built — try it free: invite code

## License

MIT — see [LICENSE](LICENSE).
