# DPAPI-NG offline recovery: real security boundary

This note describes what `dpapi-ng` actually checks on the `KeyCache` path and
what it stops checking once the domain controller is removed. It is written for
a backend that preloads a domain root key for offline restore.

## Short version

- `target security descriptor` (`target_sd`) is **key-derivation input**. It
  selects a different L1/L2 seed and therefore a different KEK. It is not an
  access-control check.
- Online `GetKey` is the only place in this library where the domain decides
  whether the current caller may obtain private seed material. When the caller
  is not entitled to the private seed, the DC returns a **public-key envelope**
  (`flags` bit 1). On a decrypt path `get_kek` rejects that with _Current user
  is not authorized..._; on a protect path the public key is the normal input
  for producing a blob the authorized user can later open.
- With a preloaded root key in `KeyCache`, the same KDF runs locally, no
  `GetKey`, no authentication and no domain policy evaluation happens. The SID
  in the blob still **binds the ciphertext to a descriptor**; it no longer
  **authorises the operator**.
- Those are two separate properties:
  1. **KDF binding**: which descriptor the key material is tied to.
  2. **Caller authorization**: whether this principal may decrypt now.
  Offline recovery preserves (1) and must re-supply (2) itself.

## Path trace

| Step | Online path | Offline `KeyCache` path |
|-|-|-|
| 1. Blob parsed | `DPAPINGBlob.unpack`; descriptor parsed from PKCS#7 `OtherKeyAttribute` | same |
| 2. SD computed | `SIDDescriptor.get_target_sd()` builds bytes with owner/group `S-1-5-18`, DACL `target SID mask 3`, `S-1-1-0 mask 2` | same pure function |
| 3. Key lookup | cache miss -> `_sync_get_key`/`_async_get_key` over MS-GKDI RPC | `KeyCache._get_key`, keyed by `(root_key_id, target_sd, l0)` |
| 4. Authorization | DC evaluates the authenticated caller against the request. A caller not entitled to the private seed gets a public-key envelope instead | **not evaluated**; cache has no caller identity |
| 5. Seed derivation | `compute_l1_key(target_sd, root_key_id, l0, root_key, hash)` then `compute_l2_key` | same code, locally |
| 6. KEK | `kdf(hash, l2_key, "KDS service\0", key_info, 32)` | same |
| 7. Audit | DC-side authentication/RPC logs | caller must emit its own audit event |

Relevant implementation points:

- `src/dpapi_ng/_blob.py:188` `SIDDescriptor.get_target_sd`
- `src/dpapi_ng/_gkdi.py:653` `compute_l1_key` mixes `target_sd` into the L1 KDF context
- `src/dpapi_ng/_gkdi.py:496` `GroupKeyEnvelope.get_kek` rejects a public-key envelope
- `src/dpapi_ng/_gkdi.py:455` `GroupKeyEnvelope.is_public_key` exposes the in-library authorization signal
- `src/dpapi_ng/_client.py:504` `KeyCache._get_key` derives locally without caller identity
- `src/dpapi_ng/_client.py:576` / `:770` `ncrypt_unprotect_secret` / async: cache hit skips `_sync_get_key`
- `src/dpapi_ng/_client.py:672` / `:865` encrypt side does the same for the target SID

Because the descriptor bytes are a pure function of the SID string, the cache
key is also a pure function of `(root key id, descriptor, L0)`. Nothing about
`username`, Kerberos ticket, group membership or tenant is part of that key.

## What the SID does and does not establish

The blob's SID selects the KDF context. An attacker who swaps the descriptor in
the PKCS#7 envelope gets different seed material and unwrap fails; the test
suite asserts this with `InvalidUnwrap`. That is **integrity binding**, not
identity.

A process that possesses the root key can derive the key for *any* SID and
decrypt any blob protected to it. Conversely, an authorised user without the
root key cannot decrypt offline merely because the blob names their SID. So:

- "ciphertext is bound to SID X" is true offline;
- "the caller is a member of SID X" is **not checked** offline;
- "the caller is currently allowed to restore this tenant's data" is **not
  checked** offline either.

Do not read a successful offline decrypt as proof of entitlement. It only
proves the process had root-key material and the blob was intact.

## Authorization semantics of online `GetKey`

The RPC call carries `target_sd` (`GetKey.pack`) and the authenticated
principal is established by the RPC security context (Kerberos/NTLM/Negotiate).
The DC decides whether to return the private L1/L2 seed or only the public
key. `GroupKeyEnvelope.is_public_key` (flags bit 1) is the reliable in-library
signal. With a public envelope:

- on decrypt, `get_kek` raises `ValueError("Current user is not authorized
  ...")`;
- `ncrypt_*` does not cache the public envelope (`if not rk.is_public_key`);
- on decrypt, the operation fails before key material is produced. On protect,
  the public key is legitimate input: the result is a blob the authorised
  recipient can open, not a decision that the current caller may read it.

Integration tests in `tests/integration/templates/test_integration.py` model
authorised vs unauthorised users purely through this online path.

## Multi-tenant cache scope

`KeyCache` is process-local and has no tenant tag. `_get_key` first consults
`_seed_keys[root_key_id][target_sd][l0]`. Consequences:

- Sharing one cache across tenants lets a tenant-B request reuse a seed that
  was derived for the same descriptor/root key during a tenant-A operation,
  bypassing a fresh online authorization check.
- Sharing one cache across callers with different entitlements is the same
  problem even inside a single tenant.
- The cache key includes the descriptor, so different SIDs do not collide; but
  "different SID" is not "different tenant". A group SID protection descriptor
  is intentionally shared, and a tenant may legitimately ask for several SIDs.
- Tenant isolation must therefore be applied by the backend, e.g. one
  `KeyCache` per `(tenant, root_key_id)` and fixed protection-descriptor
  policy, not by relying on the SID.

Recommended backend constraints:

1. One cache instance per tenant boundary; never a global cache.
2. Pin the allowed root key ids per tenant and reject blobs whose
   `root_key_identifier` is outside that set before touching the cache.
3. Compare the blob's descriptor against a per-tenant allowlist; do not accept
   arbitrary SIDs from untrusted blobs.
4. Never use a caller-supplied `cache` object across request boundaries.

## Root-key rotation

`load_key` is keyed by `root_key_id`, and the id is not a version. If the same
id is reloaded with different `RootKeyData` or parameters, any `_seed_keys`
already derived from the old definition would still satisfy `_get_key` because
it is checked before `_root_keys`. This implementation now tracks a fingerprint
of the loaded definition and drops derived seeds for that id when it changes.

Operational rules that still apply:

- Treat rotation as a new `root_key_id` whenever the domain allows it; do not
  reuse ids in your inventory.
- Rebuild the cache after any key material or KDF/secret parameter change, and
  restart workers rather than hot-swapping.
- Record `root_key_id`, descriptor hash, `l0/l1/l2`, and cache-source in the
  restore audit record.
- When retiring a key, remove both the root key and any exported seed
  material; a cached seed is as sensitive as the blob it opens.
- Do not mix caches across root-key generations in one tenant.

## Backend integration constraints

Minimum enforceable contract for an offline restore service:

1. **Explicit offline mode**: call `ncrypt_unprotect_secret(..., cache=cache,
   cache_only=True)`. Without `cache_only`, a cache miss falls back to DNS
   lookup and online `GetKey`; in an air-gapped service that is an
   availability and audit surprise, and in a connected one it silently
   re-enables domain authorization.
2. **Own authorization**: authenticate the operator in your own service,
   resolve the tenant/secret ownership, check the restore entitlement, and
   deny before calling the library. The library cannot do this offline.
3. **Own audit**: emit one append-only event per restore with operator id,
   tenant, secret/blob id, descriptor value + hash, root key id, L0/L1/L2,
   cache hit/miss, `cache_only`, success/failure, and request id. Do not rely
   on DC logs; there are none offline.
4. **Descriptor policy**: allowlist descriptor type (this library supports
   `SID` only) and, per tenant, allowed SID values. Reject unsupported
   descriptor OIDs early.
5. **Key custody**: root keys in an HSM/KMS or sealed store, never in the same
   process image as request handlers; decrypt caches in memory only, zero them
   after use, and keep cache lifetime shorter than the rotation window.
6. **Tenant cache partition**: one `KeyCache` per tenant (and per root-key
   generation), with a bounded size and a documented eviction policy. A cache
   hit must be treated as "key material already present", not as "caller is
   authorized".
7. **Fail closed**: `cache_only=True` plus a typed error when the key is
   absent. Do not retry over the network from the offline worker.
8. **Rotation drill**: test that reloading a root key id with new material
   invalidates old seeds and that a stale cache cannot decrypt new blobs.
9. **Negative tests**: descriptor substitution must fail; a blob for another
   tenant's descriptor must fail your policy check even if the key derives.
10. **No identity claim**: the audit record should say "decrypted with
    preloaded root key", never "domain-validated caller". If you need
    domain-attested authorization, require an online `GetKey` for that
    operation and do not serve it from cache.

## Offline experiment (synthetic root key)

`examples/offline_descriptor_lab.py` is a self-contained experiment; it uses a
fixed synthetic root key and never contacts a domain. Run:

```bash
.venv/bin/python examples/offline_descriptor_lab.py
```

It demonstrates:

- two SIDs -> two different target SD byte strings (SHA-256 shown);
- two different L1/L2 seeds and KEKs;
- the same SID is deterministic;
- changing L1, L2 or `key_info` changes the KEK;
- a blob protected to SID A fails to unwrap after its descriptor is swapped
  to SID B;
- a cache hit succeeds even when bogus credentials are supplied, because no
  authentication occurs.

The experiment uses a **synthetic** root key. It proves KDF separation and
descriptor binding. It does **not** prove that the requesting operator is
authorized: that requires an online `GetKey` decision by a DC and is out of
scope for an air-gapped lab.
