# Prior art

Reversible substitution of secrets and PII before sending text to an
LLM is **not new**. Open-source tools that do something in this
territory shipped well before Invisibool started. This document
surveys the most relevant ones, explains where Invisibool sits next
to them, and is careful not to claim ground that another tool
already occupies.

The comparators below were verified by web search at the time this
document was written. Each row lists the source we relied on so a
reader can re-check it independently rather than trust this page.

## What already ships in the open

### Protect AI's **LLM Guard**

A self-hosted Python library that provides 36 scanners for
validating and sanitising prompts and responses to LLMs. The
relevant scanner pair for this comparison is `Anonymize` (input) +
`Deanonymize` (output):

- `Anonymize` detects PII entities and replaces them with tokens.
  The default token shape is a bracketed placeholder such as
  `[REDACTED_PERSON_1]`; an optional `use_faker=True` parameter
  substitutes entities with "fabricated data" instead — realistic-
  looking fakes generated per entity type. The library's vault
  stores `(placeholder_or_fake, original_value)` tuples in process
  memory.
- `Deanonymize` restores the original values in the LLM response by
  looking each tuple up in the same vault.

**This means reversible vault-based substitution, with the optional
realistic-fake shape, is already shipped in LLM Guard.** Invisibool
does not claim either of those properties as novel.

> Sources: project README and docs at
> [github.com/protectai/llm-guard](https://github.com/protectai/llm-guard),
> [the Anonymize scanner page](https://protectai.github.io/llm-guard/input_scanners/anonymize/),
> and the source of
> [`anonymize.py`](https://github.com/protectai/llm-guard/blob/main/llm_guard/input_scanners/anonymize.py).

### Microsoft **Presidio**

An open-source framework for detecting and de-identifying PII
across text, images, and structured data. Detection uses regex +
NER + custom rules in multiple languages. De-identification ships
a documented set of "operators":

| Operator | What it does | Reversible? |
|---|---|---|
| `Replace` | Replace PII with a configurable value (default: `<ENTITY_TYPE>`) | No |
| `Redact` | Remove PII entirely | No |
| `Mask` | Overwrite with a chosen character | No |
| `Hash` | SHA-256 / SHA-512 / MD5 with optional salt | No |
| `Encrypt` | AES-encrypt the PII text | Yes, only with `Decrypt` + key |
| `Custom` | Apply a user-supplied lambda | No |
| `Surrogate_AHDS` | Realistic medical surrogates via Azure Health Data Services | No |
| `Keep` | Pass through unchanged | (preserves original) |

Presidio's `Encrypt` + `Decrypt` pair gives reversibility — but the
ciphertext output is **not format-preserving** (it's an AES blob,
not a same-length-same-alphabet fake). Presidio does not ship a
LLM-Guard-style vault that maps a realistic fake back to its
original.

> Sources: [github.com/microsoft/presidio](https://github.com/microsoft/presidio)
> and the
> [Anonymizer operators reference](https://microsoft.github.io/presidio/anonymizer/).

### Egress-gateway proxies that redact before sending

A separate class of tool sits between a user's CLI/agent and the
upstream LLM API and redacts secrets/PII on the way out. They are
**redaction-first, not reversible-substitution-first**: the user
gets a redacted prompt sent upstream and a normal response back,
with no restoration step.

The canonical example is **AI Security Gateway**
(`aisecuritygateway`) — self-hosted, OpenAI-SDK-compatible proxy
that redacts ~28 PII types and detects secrets / API keys before
forwarding to any of the supported upstream providers (OpenAI,
Anthropic, Groq, Together, Gemini, Mistral, etc.). No vault, no
round-trip; the redaction is the whole product.

> Source: [github.com/aisecuritygateway/aisecuritygateway](https://github.com/aisecuritygateway/aisecuritygateway).

Similar redaction-only gateways include **AegisGate** (open-source
LLM-API security gateway with prompt-injection detection, PII
redaction, dangerous-response sanitisation, and audit logging —
[github.com/ax128/AegisGate](https://github.com/ax128/AegisGate))
and WangYihang's **`llm-redactor`** (a transparent egress gateway
that detects 100+ secret types via Gitleaks-compatible rules,
intercepts SSE streams, logs detections to a local file —
[github.com/WangYihang/llm-redactor](https://github.com/WangYihang/llm-redactor)).
All three sit in the same proxy class; pick whichever upstream-
provider story and policy surface fits your stack.

**Naming-collision note for readers citing both this section and
the humility paper below:** WangYihang's `llm-redactor` (an
open-source proxy tool) and the arXiv paper
*"LLM-Redactor: An Empirical Evaluation of Eight Techniques for
Privacy-Preserving LLM Requests"* (Agyemang et al., 2026) share
the name but are **unrelated projects** — one is software, the
other is a benchmark study. Each is cited at its own URL above
and below.

## The humility note

A peer-reviewed empirical evaluation of eight techniques for
privacy-preserving LLM requests was published on arXiv in April
2026: *"LLM-Redactor: An Empirical Evaluation of Eight Techniques
for Privacy-Preserving LLM Requests"* (Justice Owusu Agyemang et
al., 13 April 2026, arXiv:2604.12064). The paper evaluates local
inference, redaction + restoration, semantic rephrasing, Trusted
Execution Environments, split inference, homomorphic encryption,
multi-party computation, and differential privacy across a
1,300-sample labelled leak benchmark.

The headline finding:

> "the combination A+B+C (route locally when possible, redact and
> rephrase the rest) achieves 0.6% combined leak on PII and 31.3%
> on proprietary code"

The paper's `achieves N% leak` phrasing makes N a **leak rate, not
a success rate**: a higher number is a worse outcome. So that 31.3%
is the **best** combination the authors evaluated — even the optimal
mix of local routing + redaction + rephrasing still leaves roughly
a third of proprietary code exposed in the LLM request. None of
the eight techniques the paper studied solves the proprietary-code
case satisfactorily, and combining them does not close the gap.
Privacy-preserving LLM input is not a solved problem; this tool is
a contribution to it, not a closure of it.

> Source: [arxiv.org/abs/2604.12064](https://arxiv.org/abs/2604.12064)
> (paper PDF: [arxiv.org/html/2604.12064v1](https://arxiv.org/html/2604.12064v1)).

## Where Invisibool sits

Reading the comparators above:

- **Reversible vault + realistic-fake substitution** is already
  the LLM Guard model. Invisibool's `Engine::scrub_with_session` /
  `Engine::restore_with_session` round-trip is the same shape from
  the user's point of view.
- **Redaction-only** is the egress-gateway model
  (WangYihang/llm-redactor, AI Security Gateway, AegisGate).
  Invisibool's fail-closed branches reduce to that behaviour when a
  fake cannot be produced, but the default path emits a
  format-preserving fake instead.

Invisibool's mechanism choices that differ from the above:

1. **Format-preserving encryption (FF1) for the fake.** LLM Guard
   produces fakes either as bracketed placeholders or as Faker-
   generated realistic values; in either case the (placeholder,
   original) pair is the only thing that can reverse the
   substitution, so reversal requires the vault. Invisibool's
   FF1-eligible registered values are reversible **statelessly** —
   any process loading the same vault keys can decrypt the fake
   back to the original via FF1 trial-decrypt. Presidio's
   `Encrypt` is also reversible-via-key, but its output is not
   format-preserving (it's an AES blob, not a same-length-same-
   alphabet fake).
2. **MAC-tagged self-authenticating fakes for the formatless
   case.** When a Formatless value is long enough, Invisibool
   emits a fake whose tail is a truncated keyed MAC of its body.
   The idempotence layer recognises any such fake on re-scrub
   **without consulting a vault**. We have not found, in the
   survey above, another open-source tool in this territory using
   this construction; the closest analogue is "look the fake up
   in the vault" (LLM Guard), which works only inside one process.
3. **Personal exact-match vault as a first-class input.** The
   exact matcher fires on user-registered values byte-for-byte
   before any pattern detection runs. The comparators above either
   use pattern/NER detection only (Presidio, the egress gateways)
   or expect a developer to wire the library's PII detectors;
   Invisibool's vault path puts the user's specific secrets first.
   The exact-match-precedence rule in idempotence makes registered
   values immune to the MAC-false-positive class of mistakes
   (`docs/THREAT_MODEL.md` row 6).
4. **Fail-closed redaction as a documented contract.** When the
   engine cannot produce a valid fake, the value is removed and
   replaced with a sentinel — the engine never passes a real
   value through with a "couldn't scrub this, watch out" notice.
   The leak harness exercises every fail-closed branch on every
   PR. We have not found a comparator that exposes this as a
   documented property with a CI-enforced check.
5. **Local-only by design.** The engine has zero network
   dependencies, the binary holds no provider keys, and there is
   no telemetry. LLM Guard runs locally as a library too; the
   gateway proxies run on the user's infrastructure but expose
   provider-compatible APIs. Invisibool is the simplest deployment
   shape — a CLI binary the user runs themselves, no proxy
   surface, no API to expose.

These are **mechanism** differences, not property differences.
LLM Guard's user-visible round-trip and Invisibool's round-trip
solve the same user problem: "stop my prompt's secrets from
leaving the machine, then bring them back when the LLM replies."
The choices above are why we built a separate tool rather than
contributing to an existing one — not because we think they make
Invisibool categorically better.

## What is explicitly NOT yet claimed

The following are written in the project plan as Invisibool's
intended differentiators but **do not ship at M0b**. They are
listed here so a reader does not infer them from this document:

- **Tool-call restoration safety.** A policy for restoring fakes
  inside structured tool-call arguments without corrupting them
  is planned for a later milestone. Not shipped at M0b.
- **Streaming chunk-boundary restoration.** A rolling-buffer
  restore that hands the user output as it streams from the LLM,
  without holding back whole chunks, is planned. Not shipped at
  M0b.
- **Assisted discovery.** Helping the user find values that
  *should* be registered (a personal-secrets discovery pass over
  their dotfiles, env files, browser autofill, etc.) is planned
  for a later milestone. Not shipped at M0b.

When any of those land, this document should be updated to claim
only what has actually been built — and to re-survey the
comparators above to confirm none of them has shipped the same
thing in the meantime.

## How this document is maintained

Every claim about an external tool above is anchored to a URL the
reader can re-check. The URLs were live at the time of writing.
Two things will degrade over time and need re-verification on the
release schedule:

1. **Comparator capability claims.** Each tool above is under
   active development. A capability we said it "does not ship"
   today may have landed by the time you read this. If a
   comparator now ships the same thing Invisibool ships, this
   document should be updated to say so plainly.
2. **The arXiv 2604.12064 citation.** The 31.3% number cited
   above is from a specific paper at a specific date. Later
   work in the same area (better techniques, larger benchmarks,
   contradictory findings) should be cited alongside or in place
   of it as it appears.

If you re-survey this space and find a claim above is wrong,
that is a bug in this file. Open an issue or send a PR. The goal
is honest positioning, not a defensive page.
