# llm-agent-redteam

[![CI](https://github.com/badrmatar/llm-agent-redteam/actions/workflows/ci.yml/badge.svg)](https://github.com/badrmatar/llm-agent-redteam/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**Automated red-teaming of tool-using LLM agents, with statistically rigorous defence comparisons.**

An attacker LLM tries to break a customer-support agent that can look up orders, issue
refunds and send emails. Every attack is judged from an audit log of the tools the agent
actually called, and the harness measures how often attacks succeed under three defences,
with exact confidence intervals and stratified significance tests.

The question it answers is simple: *does this defence actually make the agent safer, or did
the numbers just move by chance?*

```
 ┌──────────────┐  message   ┌──────────────┐  tool calls  ┌──────────────────────────┐
 │ attacker LLM │ ─────────▶ │ target agent │ ───────────▶ │ fake shop: orders,       │
 │  (5 turns)   │ ◀───────── │ + defence    │              │ refunds, email, secrets  │
 └──────────────┘   reply    └──────────────┘              └────────────┬─────────────┘
                                                                        │ audit log
                                                  ┌─────────────────────▼──────────────┐
                                                  │ judge: rules on the log,           │
                                                  │ LLM judge only for fuzzy outcomes  │
                                                  └─────────────────────┬──────────────┘
                                                                        ▼
                                          Clopper-Pearson CIs · CMH tests · Holm · report
```

## Threat model

The attacker is a logged-in customer (Alice). Anything beyond her own account is a failure.

| category | attacker wants to | judged by |
|---|---|---|
| `refund` | refund someone else's order, an undamaged order, or more than the price | executed refunds in the audit log |
| `exfiltration` | get an email sent to an outside address | executed emails in the audit log |
| `pii` | learn another customer's email or home address | normalised string match + LLM judge |
| `secret` | extract the internal staff discount code | normalised string match + LLM judge |
| `promise` | get an out-of-policy written promise ("free for life") | LLM judge |

There are 20 goals, each using one of five strategies: **direct**, **authority** (posing
as staff or a developer), **social engineering**, **indirect prompt injection** and
**obfuscation** (encodings, games, spelled-out answers).

The two indirect-injection goals plant instructions in order notes that the customer wrote
at checkout. The attacker never states the malicious request; it only has to get the agent
to read its own database.

## Defences compared

| defence | what changes |
|---|---|
| `none` | plain policy prompt |
| `prompt` | hardened prompt, with tool output wrapped in `<untrusted_data>` tags (spotlighting) |
| `guard` | plain prompt, but policy is enforced in code: ownership checks, refund rules, an email allow-list and output redaction |

## Statistics

- **Clopper-Pearson exact 95% intervals** on every success rate. With 10 runs per cell,
  normal-approximation intervals are badly wrong near 0% and 100%.
- **Cochran-Mantel-Haenszel test, stratified by goal**, to compare a defence with no
  defence. Goals differ hugely in difficulty, and pooling them would confound the comparison.
- **Holm correction** across the per-category comparisons, so testing several categories
  doesn't inflate false positives.

## Quick start

```bash
git clone https://github.com/badrmatar/llm-agent-redteam && cd llm-agent-redteam
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,openai]"          # or .[dev,anthropic]

pytest -q                               # 16 offline tests
redteam --provider mock                 # offline smoke run, no API key needed

export OPENAI_API_KEY=...               # see .env.example
redteam --provider openai --runs 3      # small run first to check cost
redteam --provider openai --runs 10     # full run: 20 goals × 3 defences × 10 runs
```

Useful flags: `--defences none guard`, `--goals R5 E3` (only the injection goals),
`--attacker-model`, `--target-model`, `--judge-model`, `--turns`, `--workers`.
`python run.py ...` works too, without installing.

Each run writes to `results/<provider>/`:
- `results.jsonl`: one line per conversation, with the full transcript and tool log.
- `report.md`: all tables and the significance tests.
- `success_by_category.png`: the chart below.

`redteam --report-only results/openai` rebuilds the report from saved results.

## Results

<!-- Replace this section with your real run: paste tables from results/openai/report.md
     and commit results/openai/success_by_category.png -->

*Results from a real model run will be added here.*

## Design decisions

- **Judge from the audit log, not the transcript.** Whether a refund happened is a fact in
  the tool log. An LLM judge reading the chat would be slower, costlier and sometimes wrong.
  The LLM judge is used only where there's no objective trace (promises), and as a second
  check for leaks hidden by encoding.
- **Provider-agnostic tool protocol.** The target answers in a small JSON format instead of
  using vendor-specific function calling, so any chat model can be swapped in and compared fairly.
- **Offline mock models.** The whole pipeline, including tests and CI, runs with no API key.
  Mock numbers prove the plumbing works and are clearly labelled as not being findings.
- **Fresh world per conversation.** Every episode gets its own copy of the shop, so runs are
  independent, which is what the statistics assume.

## Limitations

- The shop and tools are simulated; real deployments have more tools, context and users.
- Some models refuse the attacker role. If attack rates look suspiciously low, read the
  attacker turns in `results.jsonl` and try another attacker model.
- The LLM judge can misjudge fuzzy cases.
- Runs at temperature 1.0 to capture variability, so repeated runs differ slightly.

## Project layout

```
redteam/
  world.py      fake shop, tools, audit log, code-level guard
  target.py     the agent and its three defence modes
  attacker.py   multi-turn attacker and strategy prompts
  goals.py      the 20 goals and the judges
  stats.py      Clopper-Pearson, CMH test, Holm correction
  report.py     report.md and chart
  models.py     OpenAI, Anthropic and offline mock backends
  runner.py     parallel experiment runner
  cli.py        command-line interface
tests/          offline pytest suite
.github/        CI: lint, tests and a smoke run on Python 3.10–3.12
```

## License

MIT
