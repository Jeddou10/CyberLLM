# `agents/attack/ethics_guard.py` — scope/ethics gate for the attack pipeline

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

The offensive-side analogue of `SecurityGuard` (step [5/5], before any script is
emitted). It decides whether the attack plan is **in scope** and whether generated
scripts are **non-destructive**, mapping to P1's properties: requester authorized
(source auth), scenario in scope (task alignment), action serves the scenario
(action alignment), target in agreed scope (data isolation). If a check fails, the
script is **redacted** in the output and an `EthicsVerdict(allowed=False)` is
returned.

## 2. Imports
`re`, `dataclass`; `AttackScript` from the generator.

## 3. Walkthrough

### `_DESTRUCTIVE_PATTERNS` / `_DESTRUCTIVE_RE` — lines 33–41
A regex of clearly destructive shell signatures (`rm -rf`, `shutdown -h`,
`mkfs.`, the classic fork bomb, `dd if=/dev/zero of=/dev/…`, `chmod -R 777 /`).
Used to redact any generated script that contains one.

### `EthicsVerdict` — lines 44–50
`allowed` + the three sub-checks (`scope_ok`, `target_ok`, `non_destructive`) +
reason.

### `__init__` — lines 53–65
Stores allowed scenarios, authorized targets (config **plus** any CLI
`--authorize-target`), and the `allow_all_in_dev` flag.

### `check_plan(scenario, target_asset)` — lines 67–98
- **scope_ok (70–78):** the scenario is allowed if `allow_all_in_dev`, or it's in the allowed set, or one of the allowed scenarios is a substring of it.
- **target_ok (82–90):** the target asset is authorized if `allow_all_in_dev`, or matches an authorized target (with `*` wildcard support).
- Returns `allowed = scope_ok and target_ok` with `non_destructive=True` (script-level destructiveness is handled separately by `filter_scripts`).

### `filter_scripts(scripts)` — lines 100–121
Scan each generated script's body against `_DESTRUCTIVE_RE`; a match is **redacted**
(replaced with a stub noting what was removed) and its title recorded. Returns
`(safe_scripts, redacted_titles)`.

## 4. Edge cases, gotchas & design decisions
- **Two-layer safety.** Plan-level scope/target authorization *and* script-level
  destructive-pattern redaction — a plan can be in scope yet still have a
  dangerous script redacted.
- **Authorization can come from the CLI.** `--authorize-target` lets an operator
  explicitly widen scope for a specific engagement without editing config.
- **`allow_all_in_dev` is a deliberate escape hatch** for lab use; in production
  it would be off so scope/target checks bite.
- **Redaction, not deletion.** A blocked script is replaced with a stub describing
  what was removed, preserving the audit trail of what the plan *would* have done.
- **Mirror of P1.** The docstring maps each check to a contextual-security
  property, making the offensive guard auditable the same way the defense guard is.
