# `agents/action_engine/playbooks.py` — the remediation playbook catalogue + plan builder

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

This file is the **remediation knowledge base**. The key idea: a response should
match the *kind* of finding, not merely its severity tier. A SQL-injection wants
a code patch + credential rotation; a CAN-injection wants safe-mode + ECU
isolation + driver notification; a topology violation wants a block + architect
notification. Hard-coding "soft→rate_limit, hard→isolate" is fine for a demo but
**isn't auditable** — so instead each finding maps to a typed **playbook**: an
ordered sequence of MCP-tool `StepTemplate`s with pre/post conditions and
rollback.

`build_plan(decision, ctx)` is the public function `generator.py` calls; it turns
a `Decision` into a concrete, ordered, de-duplicated `ActionPlan`.

---

## 2. Imports — lines 28–45

| line | import | why |
|------|--------|-----|
| 30 | `json` | Hashing params for dedup. |
| 31 | `re` | Match rule-ids to playbook patterns; pull IPs/files/secrets from evidence. |
| 32 | `dataclass, field` | `StepTemplate`, `Playbook`. |
| 33 | `datetime` | Plan timestamp. |
| 34 | `Any, Callable` | Type the `params_fn` closures. |
| 35 | `uuid4` | Plan id. |
| 37–45 | types | The step/plan shapes + `kind_priority`/`severity_rank`. |

---

## 3. Walkthrough

### `StepTemplate` — lines 52–85
A **template** for a step (a step that hasn't yet been bound to a finding). It
carries the same metadata as `ActionStep` plus a `params_fn(finding,
decision_ctx) -> params` closure and an optional `rollback_template`.
`instantiate(finding, decision_ctx, rule_id)` (67–85) materializes it into a real
`ActionStep`: it calls `params_fn` to compute concrete params (e.g. the suspect
IP from the evidence), formats the description, and recursively instantiates the
rollback. **Why a template:** the same response shape applies to many findings;
the closure fills the specifics at build time.

### `Playbook` — lines 88–93
`rule_id_pattern` (an exact id or a regex), a `title`, a `blast_radius`, and the
ordered `StepTemplate`s.

### `params_fn` helper closures — lines 100–130
Small extractors used inside templates:
- `_suspect_ip` (100–108) — pull an IPv4 from the finding's evidence/explanation, else from a ctx hint, else `0.0.0.0`.
- `_affected_file` (111–117) — parse the `<filename>:` prefix the static analyzer puts on code evidence, else the ctx default.
- `_vehicle_id` / `_ecu_id` (120–130) — vehicle/ECU identifiers (the ECU one sniffs the evidence for `BodyCtrl`/`GatewayECU`).

### The catalogue (`PLAYBOOKS` + `_book`) — lines 137–479
`PLAYBOOKS` is a module list; `_book(...)` (140–143) constructs a `Playbook` and
appends it. The file then registers specific playbooks. A representative sample:

| rule pattern | title | shape (kinds → tools) |
|---|---|---|
| `LOG-AUTH-03` | Brute-force on privileged account | CONTAIN `firewall.rate_limit` → OBSERVE `observe.log_tail` → CONTAIN `firewall.block_ipv4` → NOTIFY `notify.create_incident` |
| `LOG-CAN-02` | CAN injection from non-gateway ECU | safe-mode + ECU isolation + driver notify (node blast radius) |
| `CODE-003` (and similar) | Hard-coded secret | rotate the secret + propose a patch that reads it from env |
| `TOP-006` | World-readable secrets store | CONTAIN incident → ERADICATE `secrets.rotate` (destructive, authorized) |
| `TOP-00[12578]` | Architectural / topology violation | NOTIFY architecture-review ticket |

Each step declares its `side_effect` and `requires_authorization`, so the
executor/registry gate it correctly (e.g. `firewall.rate_limit` is WRITE +
authorization; `network.isolate_node`/`secrets.rotate` are DESTRUCTIVE).

### Patch-synthesis helpers — lines 609–650
`_PATCH_HINTS` (609–621) maps `CODE-*` ids to concrete remediation text (e.g.
CODE-001 shell-injection → use `subprocess.run(shlex.split(x))`; CODE-012 →
parameterized SQL). `_patch_for_code_finding` (624–633) and
`_patch_for_hardcoded_secret` (636–644) wrap those into a unified-diff-style
proposal; `_secret_token_excerpt` (647–650) pulls the literal secret out of the
evidence so it can be referenced (and later scrubbed in the audit).

### Generic family fallbacks — lines 483–548
When no specific playbook matches, the builder falls back to a **family-generic**
playbook by rule-id prefix: `_GENERIC_CODE` (propose patch + incident),
`_GENERIC_LOG` (incident), `_GENERIC_TOP` (architecture ticket). This guarantees
*every* actionable finding gets at least a sensible default response.

### Tier-generic fallbacks — lines 551–602
`_TIER_PLAYBOOKS` maps the decision's tier to a last-resort response when no
finding-specific or family steps fired: `soft` → rate-limit, `moderate` →
block-IP, `hard` → isolate-node (destructive). This is the bridge to P5's tiered
model when the findings themselves don't dictate specifics.

### `_lookup_playbook(rule_id)` — lines 657–667
The three-level lookup the docstring promised: exact/regex match in `PLAYBOOKS`
first (658–660), then the family-generic by prefix (`CODE-`/`LOG-`/`TOP-`), else
`None`.

### Dedup helpers — lines 670–684
`_dedupe_steps` (670–679) removes equivalent steps across findings, keyed on
`(tool, sorted params)`. `_hashable_params` (682–684) JSON-encodes non-string
values so the key is hashable/stable.

### `build_plan(decision, ctx)` — lines 687–752  (the core)
1. 696–698 — **sort findings by severity, critical first** (so the most serious drive the plan).
2. 701–719 — for each finding **at least `medium`** (informational hits don't drive automated response, 705–706), look up its playbook, apply it **once per (title, rule_id)** (710–715), and instantiate each step whose `severity_min` the finding meets.
3. 724–731 — **tier fallback:** if no specific steps fired but there's at least one actionable finding, instantiate the tier-generic playbook. The "only if actionable" guard (729) prevents responding to pure noise.
4. 735–736 — **order by `StepKind`** (contain→observe→eradicate→recover→notify→audit) and dedup.
5. 738–741 — compute the plan's `blast_radius` as the **max** radius across the chosen playbooks (`_radius_rank`).
6. 743–752 — assemble the immutable `ActionPlan` (uuid, decision summary, blast radius, asset categories, ordered steps).

### `_RADIUS_RANK` / `_radius_rank` — lines 755–759
Order blast radii `local < service < node < network < fleet` so the plan's
overall radius is the worst of its steps.

---

## 4. Edge cases, gotchas & design decisions

- **Findings, not just tiers, drive the response.** The whole point of the catalogue is auditable, kind-specific remediation. The tier-generic playbooks are a *fallback*, not the primary path.
- **The `medium` action threshold prevents noise-chasing.** Low/informational findings never trigger automated steps; they're still reported, just not acted on.
- **Specific → family → tier fallback chain** guarantees coverage: every actionable finding produces *something*, even an unknown rule-id (family generic) or a findingless tier (tier generic).
- **Ordering is enforced twice.** `build_plan` sorts by `StepKind`, and `generator.py` re-sorts after LLM additions — so containment always precedes eradication.
- **Dedup is param-aware.** Two findings that would rate-limit the *same* IP collapse to one step; two different IPs stay separate.
- **Destructive steps are flagged at the template.** `side_effect`/`requires_authorization` are declared here, so the registry's dry-run + authorization gate applies automatically — the playbook author doesn't have to wire safety per call.
