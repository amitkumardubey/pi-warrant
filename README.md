# pi-warrant

A permission gate for [pi](https://github.com/badlogic/pi-mono) that lets [Jev](https://openrouter.ai/typesafe/jev-1.13) clear the routine tool calls, keeps risky commands on a static rule, and sends the genuinely ambiguous ones to you.

*A warrant is the instrument that authorizes an action — granted by a judge, revocable, required before something proceeds. That is what this is.*

pi runs tool calls without asking. This extension adds the gate pi lacks — then stops it from becoming prompt fatigue by having a decision model clear the calls a careful reviewer would wave through.

```text
every check >= 0.90   ->   allow    the tool just runs
any  check <= 0.10   ->   block    the model gets a reason and can adapt
anything in between   ->   ask      you are prompted
```

One file. No dependencies beyond pi itself.

---

## Why

Every coding agent that asks before acting produces the same problem. You turn prompting on to get a check between the model and `git push --force`, and then you approve `bun test`, `git status`, and `cat package.json` dozens of times a session. Turn prompting off and the check disappears entirely.

This keeps the check and removes the busywork. The key idea, from the OpenRouter cookbook [Auto-Approve Coding Agent Permission Prompts with Jev](https://openrouter.ai/docs/cookbook/coding-agents/auto-approve-permission-prompts-with-jev): **anything short of a confident yes leaves the request exactly as the agent had it.** A wrong or missing answer costs one extra prompt instead of an unwanted command.

## Install

```bash
mkdir -p ~/.pi/agent/extensions
curl -o ~/.pi/agent/extensions/warrant.ts \
  https://raw.githubusercontent.com/amitkumardubey/pi-warrant/main/warrant.ts
```

Then set a key for a decision model — pi already ships Jev, so no extra provider setup:

```bash
export TYPESAFE_API_KEY=...      # -> typesafe/jev-latest
# or
export OPENROUTER_API_KEY=...    # -> openrouter/typesafe/jev-1.13
```

Restart pi, or `/reload`. Without a key every call asks you, which is the old behaviour.

## How a call is decided

Every tool call — shell, file tools, custom tools, and MCP — goes through these stages in order:

| Stage | What it is | Outcome |
|---|---|---|
| **Deny** | Static, in code. Fork bombs, `dd` to a block device, `mkfs`, `shutdown`, firewall flushes. | **block** — no model, no prompt, no override |
| **Always-ask** | Static, in code. `sudo`, recursive deletes, force pushes, publish/deploy, credential paths, shell indirection, unreadable text, paths escaping the project. | **ask** — never judged by a model |
| **Session grant** | A call you already allowed for this session | **allow** — no second prompt |
| **Jev** | Three narrow yes/no questions against the call and your current task | **allow / block / ask** by threshold |
| **No UI** | An unresolved call in a headless run | **block** |

If Jev is unavailable, times out, errors, or answers with something out of range, the call is **asked**, never approved.

## The three questions

Each is a complete proposition, true or false of the state on its own. None of them is "should this be approved" — that is what the thresholds decide, and splitting it up is what gives every block a readable reason.

- **`reversible`** — does the call stay inside the project and can it be undone with git?
- **`no_secrets`** — does it avoid reading, printing, or transmitting credentials?
- **`serves_task`** — is it a reasonable next step toward what you actually asked for?

The relevance question is skipped when there is no user task to compare against.

## Why it is safe by construction

- **The static list is the security boundary, not the threshold.** Jev only sees the text of a call; it cannot tell that a `cat` reads a secret or that a remote is production unless the text says so. Anything irreversible or credential-touching is caught in code before Jev is consulted.
- **Failures never approve.** Every error path asks or blocks. A timeout is one extra prompt, not an unwanted command.
- **No UI means no.** In headless runs an unresolved call is denied, matching Claude Code's behaviour.
- **Secrets are redacted before they leave the machine.** Named secret assignments, `Bearer`/`Basic` headers, `sk-`/`ghp_`/`AKIA`/`xox` tokens, JWTs, and private key blocks are masked on the way out. File contents of large writes are omitted entirely rather than sent. Redaction can only *lower* a score, which sends the call to you — the safe direction.
- **It is a decision layer, not a sandbox.** It decides whether a call may proceed; it does not constrain what a permitted call can reach. Pair it with a container or VM when that matters.

## Configuration

Everything is optional. Defaults are safe; create `~/.pi/agent/extensions/warrant.json` to override.

```jsonc
{
  "enabled": true,

  // Gate everything by default. Leave noisy tools to pi's native behaviour here.
  "exclude": [],

  // Thresholds. Set "blockAt": 0 so Jev only ever clears routine calls and never refuses one.
  "approveAt": 0.9,
  "blockAt": 0.1,

  // Jev budget per call. A timeout asks you.
  "timeoutMs": 8000,

  // Pin a specific classifier as "provider/model-id".
  "model": null,

  // Extra static rules (regex sources).
  "deny": [],    // -> always block
  "risky": [],   // -> always ask

  "log": true,
  "sessionGrants": true
}
```

### Tuning thresholds

`approveAt` / `blockAt` are not probabilities of safety — they are the bar you set for delegation. Two sensible shapes:

- **Conservative (default):** `0.9 / 0.1`. Three-way. You see only genuinely ambiguous calls.
- **Prompt-only:** `0.9 / 0`. Jev never refuses anything; it only clears calls it is confident about, and everything else comes to you. Useful when you want auto-approval without ever being blocked by a model's opinion.

If you would rather have the simpler binary rule some agents use — above 50% approve, below deny — set `"approveAt": 0.5, "blockAt": 0.5`. It is cheaper in prompts and much more willing to run borderline calls on a coin flip. The default is deliberately not that.

## Commands

```text
/warrant status              # what is gated, thresholds, which classifier
/warrant test <command>      # dry-run a shell command through the pipeline
/warrant test write <path>   # dry-run a path tool
/warrant log 20              # recent decisions
/warrant on | off
/warrant thresholds 0.9 0
/warrant reload
```

`test` runs the real pipeline and prints the outcome, stage, reason, per-question probabilities, and cost. Nothing is executed.

```text
/warrant test bun test src/date.test.ts   ->  ALLOW
/warrant test git push --force            ->  ASK   (static risk pattern)
/warrant test rm -rf /                    ->  ASK   (static risk pattern)
```

## Audit trail

Every decision appends one JSONL line to `~/.pi/agent/extensions/warrant.log` with the tool, target, outcome, stage, reason, per-question probabilities, model, and cost.

```json
{"ts":"...","tool":"bash","target":"bun test src/date.test.ts","outcome":"allow","stage":"jev",
 "reason":"every check clear","checks":{"reversible":0.93,"no_secrets":0.95,"serves_task":0.95},
 "model":"typesafe/jev-latest","cost":0.00002}
```

One Decision request per call that reaches the model — nothing is spent on calls your static rules already resolve. In the cookbook's runs a request cost about $0.00002 and returned in under 600 ms.

## Cost and latency

Roughly 20 ms of local work per call, plus one classifier round-trip (under 600 ms typical) for calls that reach Jev. It runs before the tool, so it adds to wall-clock time. Set `timeoutMs` lower if that matters more than accuracy.

## Limitations

- **Model judgment is advisory.** Thresholds encode your risk appetite, not a proof of safety.
- **Redaction is pattern-based.** A secret in an unrecognized format could reach the classifier endpoint. If that is unacceptable for your workload, keep secrets out of tool arguments or set `exclude` for the relevant tools.
- **MCP arguments are judged as opaque JSON.** Jev sees the redacted arguments and tool name; it does not know what the remote server will do with them.
- **Session grants are per exact call.** A slightly different command asks again.

## Prior art

- [Claude Code permission modes](https://code.claude.com/docs/en/permission-modes) — classifier-backed auto mode, and the `ask`/`deny` layering this mirrors.
- [OpenRouter: Gate Agent Tool Calls with Jev](https://openrouter.ai/docs/cookbook/building-agents/gate-tool-calls-with-jev) — the three-way approve/block/review pattern.
- [OpenRouter: Auto-Approve Permission Prompts with Jev](https://openrouter.ai/docs/cookbook/coding-agents/auto-approve-permission-prompts-with-jev) — the static-list-first design.
- [`@gotgenes/pi-permission-system`](https://www.npmjs.com/package/@gotgenes/pi-permission-system) — a full policy-enforcement extension for pi with an authorizer-chain seam, if you want deterministic policy plus a deny-first judge rather than a general auto-approver.

## License

MIT
