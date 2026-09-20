# gpu-security — Claude Code Skills

Four purpose-built skills that turn the binding principles in `CLAUDE.md` into guardrails Claude
Code applies automatically while coding. Each maps to one non-negotiable — this is a guardrail
set, deliberately small, not a marketplace.

| Skill | Enforces | Phase it matters |
|---|---|---|
| `metadata-only-guard` | P3 — zero payload access (safety-critical) | **Phase 0** |
| `ray-guard-scanner` | §3 L1 / §14 Phase 0 build conventions | **Phase 0** |
| `rego-verification-sentinel` | §8 — finding + verification conditions | Phase 1 |
| `postgres-tenant-isolation` | §9 — tenant_id + RLS on every table | Phase 1 |

## To start Phase 0 you only need the first two.
`metadata-only-guard` + `ray-guard-scanner` are enough to build the scanner correctly and safely.
The other two are created now (cheap, and they encode conventions you won't want to relitigate)
but only become active when you build the Phase-1 control plane.

## Install (Claude Code)
These are project-level skills. Keep them in the repo:
```
<repo-root>/.claude/skills/<skill-name>/SKILL.md
```
Claude Code reads them automatically; a skill activates when your request matches its
`description`. That's the whole install — no package manager.

- Project-level (recommended, shown above): commit them so the whole team + any agent gets them.
- Global alternative: copy a skill folder to `~/.claude/skills/` to use it across projects.

## The one official skill to also install
Your Phase-0 report is a PDF, so install Anthropic's document skill for rendering:
```
/plugin marketplace add anthropics/skills
/plugin install document-skills@anthropic-agent-skills
```
That gives you the `pdf` skill (and docx/pptx/xlsx, which you can ignore). Verify current steps at
docs.claude.com/en/docs/claude-code (Skills section) — the feature evolves.

## What NOT to add yet
No Postgres/GitHub MCP, no frontend-design skill, no community skill mega-repos. Those belong to
Phase 1+. Importing them now is setup that feels productive without moving you toward the only
Phase-0 goal: a scanner good enough to earn three buyer-led assessments.
