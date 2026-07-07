# `skills/__init__.py` — the skills package surface

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

Package initializer for `skills/`. It re-exports the four skill-list constants so
callers can import them from the package root. Its docstring frames skills as
"declarative capabilities the agents can pick from" (P5 response tiers + P2 attack
scenarios).

## 2. Imports / re-exports — lines 4–10
`SOFT_RESPONSE_SKILLS`, `MODERATE_RESPONSE_SKILLS`, `HARD_RESPONSE_SKILLS`,
`DEFENSE_SKILLS`, `ATTACK_SKILLS` — all from `.skills`.

## 3. Walkthrough
No logic — pure re-export so `from skills import DEFENSE_SKILLS` works. (Note it
re-exports the *lists*; the `Skill` dataclass and `find_skill` are imported from
`skills.skills` directly when needed.)

## 4. Edge cases, gotchas & design decisions
- **Lists, not the helper.** The package surfaces the curated skill *lists*; the
  `find_skill` lookup and the `Skill` type stay in the submodule, keeping the
  package root focused on "what skills exist."
