# Structural fuzzing for GKDI structs

This directory holds a deterministic, bounded fuzz harness for
`dpapi_ng._gkdi.GroupKeyEnvelope` and `dpapi_ng._blob.KeyIdentifier`. It is
focused on the relationship between the length prefixes, UTF-16 names, and
synthetic binary regions in those structures, not on calling decrypt paths.

## Layout

| File | Purpose |
|-|-|
| `layout.py` | Independent, hand-written layout inspector. It reads only bytes and never calls `unpack`. |
| `corpus.py` | Deterministic case generator. A fixed seed and a hard byte cap make every run reproducible. |
| `oracle.py` | Outcome taxonomy, field-level interpretation comparison, and a bounded reproducer shrinker. |
| `findings.json` | 13 baseline witnesses with minimized bytes, checkpoints, offsets, and the actual baseline interpretation. |
| `test_structural_fuzz.py` | The pytest suite. |

## Corpus

Every seed is produced by local, synthetic `pack()` calls. Names use RFC 2606
`.invalid` suffixes; no real domain, forest, host, or key material is used.
`DEFAULT_SEED = 20261113`; change it with `cases_for(struct, seed=...)`.
`DEFAULT_CASES = 220` per struct and `MAX_CASE_BYTES = 4096`, so the suite
stays fast and reproducible.

Cases fall into seven categories:

| Category | What changes |
|-|-|
| `normal` | Unmodified legal `pack()` output, including byte round-trip |
| `length_prefix` | One uint32 header field at a time: zero, one, ±2, past-end, `0xFFFFFFFF` |
| `boundary` | Compensated length pairs that move a boundary while keeping the total fixed; swaps names |
| `terminator` | Missing final NUL, embedded NUL, lone surrogate, shifted boundary |
| `flags` | Public/private bit toggles, all bits, and a public flag with a mismatched `l2_key` |
| `truncation` | The final 1, 2, 3, 7, or 8 bytes removed |
| `trailing` | Four bytes appended after the last field |

## Oracle

`oracle.run_case` reports one of:

- `ok`: accepted, layout-valid, every parsed field agrees with the independent slice, and `pack()` is byte-identical.
- `ambiguous_acceptance`: accepted for the single documented case where an embedded NUL inside a framed string is intentionally tolerated.
- `success` classes are never treated as proof from round-trip alone: byte equality is checked *in addition to* the independent field comparison.
- `rejected_malformed` / `rejected_codec`: the layout is invalid and parsing raised; messages must name the field and input offset.
- `silent_acceptance`: the layout is invalid but parsing succeeded (the failure this harness exists to catch).
- `interpretation_mismatch`, `false_rejection`, `parser_crash`: additional contract violations.

The shrinker only removes a byte range when the fault signature
`(accepted, exception class, layout deviation, field, differing field names)`
stays identical, and reports a checkpoint inside the minimized buffer.

## Findings

Before the parser hardening, the corpus produced 315 silent acceptances out of
440 samples, e.g.:

- `GroupKeyEnvelope` with `l2_key_len = 0xFFFFFFFF` returning an empty `l2_key`
- truncated `l2_key` silently parsed as an empty/short binary region
- `domain_name_len` shrunk by 2 returning an empty domain and a shifted forest name
- trailing bytes after the last field ignored entirely
- an oversize `kdf_parameters_len` consuming the neighbouring algorithm name

`findings.json` keeps one minimal witness per class; each records the bytes,
original and minimized size, the inspector's deviation, its field, the
checkpoint offset, and what the baseline parser actually returned.

After hardening, all 440 samples in the default corpus classify as `ok` (56
legal samples) or `rejected_malformed` (384), and the 13 recorded witnesses all
raise `ValueError` with the field and offset.

## Limits

- This is not a general-purpose libFuzzer run; it is a structured, reproducible
  regression corpus. Extend `corpus.py` rather than turning it into random
  byte flips.
- `unpack_response` framing (length/referent fields around the envelope) is out
  of scope; the harness targets the two structs themselves.
- An embedded NUL is accepted by design when it is framed by an explicit
  declared length; the strict checks only reject it for UTF-16 string fields.
