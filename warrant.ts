/**
 * pi-warrant — a permission gate for pi's tool calls, with Jev auto-approval.
 *
 * pi runs every tool call without asking. This extension adds the gate pi lacks, then lets Jev
 * clear the routine calls so you keep the check without the prompt fatigue.
 *
 * It is standalone: it needs no permission-system package, and it uses pi's own classifier
 * registry (pi already ships Jev keyed to TYPESAFE_API_KEY or OPENROUTER_API_KEY).
 *
 * Every tool call is decided in this order:
 *
 *   1. DENY rules      static, in code.  -> block. Jev is never consulted and cannot override it.
 *   2. ALWAYS-ASK      static, in code.  -> ask.  Risky shell commands, protected credential
 *                      paths, and unreadable shell text. Never judged by a model.
 *   3. Session grant   a call you already allowed for this session -> allow.
 *   4. Jev             three narrow yes/no questions -> allow / block / ask by threshold.
 *   5. No UI           an unresolved call blocks rather than running.
 *
 * The thresholds are deliberately far apart, so you only see the calls that are genuinely
 * ambiguous:
 *
 *     every check >= approveAt (0.9)  ->  allow   (the tool just runs)
 *     any  check <= blockAt   (0.1)  ->  block   (the model gets a reason and can adapt)
 *     anything in between             ->  ask     (you are prompted)
 *
 * Design follows the OpenRouter cookbooks "Gate Agent Tool Calls with Jev" (three-way
 * approve/block/review, deterministic checks first, a reason and the probabilities on every
 * decision) and "Auto-Approve Coding Agent Permission Prompts with Jev" (the static list is the
 * security boundary; a wrong or missing answer costs one extra prompt, never an unwanted command).
 *
 * ---------------------------------------------------------------------------
 * What this is and is not
 * ---------------------------------------------------------------------------
 * It is a decision layer, not a sandbox. It decides whether a call may proceed; it does not
 * constrain what a permitted call can reach. If an allowed tool can do harm, restrict that tool
 * with a deny rule or run the session in a container.
 *
 * ---------------------------------------------------------------------------
 * Setup
 * ---------------------------------------------------------------------------
 *   ~/.pi/agent/extensions/warrant.ts     <- this file. Auto-discovered, `/reload`-able.
 *   ~/.pi/agent/extensions/warrant.json   <- optional config (see CONFIG_DEFAULTS)
 *   ~/.pi/agent/extensions/warrant.log    <- audit trail (JSONL)
 *
 * A classifier model must be available, which needs one of:
 *   TYPESAFE_API_KEY     -> typesafe/jev-latest
 *   OPENROUTER_API_KEY   -> openrouter/typesafe/jev-1.13   (or /login)
 * Without one, every call goes to you, which is the old behaviour.
 *
 * Inspect it any time:  /warrant status
 * Dry-run a command:    /warrant test rm -rf /
 */

import { appendFileSync, chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { ClassifierApi, ClassifierModel } from "@earendil-works/pi-ai";
import { type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

interface Config {
	/** Master switch. `false` restores pi's native behaviour: every call runs. */
	enabled: boolean;
	/** Tools to leave completely alone. Everything else is gated ("all tools"). */
	exclude: string[];
	/** Every check at or above this approves. */
	approveAt: number;
	/** Any check at or below this blocks. */
	blockAt: number;
	/** Jev budget per call. A timeout asks you. */
	timeoutMs: number;
	/** Preferred classifier as `provider/model-id`. Default: first available Jev/Clef/Luna. */
	model: string | null;
	/** Extra always-block patterns (regex sources, matched against the call's target text). */
	deny: string[];
	/** Extra always-ask patterns (regex sources). Never judged. */
	risky: string[];
	/** Write the audit trail. */
	log: boolean;
	/** Offer "allow for session" in the prompt. */
	sessionGrants: boolean;
}

const CONFIG_DEFAULTS: Config = {
	enabled: true,
	exclude: [],
	approveAt: 0.9,
	blockAt: 0.1,
	timeoutMs: 8_000,
	model: null,
	deny: [],
	risky: [],
	log: true,
	sessionGrants: true,
};

function configDir(): string {
	return join(homedir(), ".pi", "agent", "extensions");
}

function configPath(): string {
	return join(configDir(), "warrant.json");
}

function logPath(): string {
	return join(configDir(), "warrant.log");
}

function clamp01(value: number): number {
	if (typeof value !== "number" || Number.isNaN(value)) return 0;
	return Math.min(1, Math.max(0, value));
}

function toRegExp(source: string): RegExp | undefined {
	try {
		return new RegExp(source, "i");
	} catch {
		return undefined;
	}
}

function loadConfig(): Config {
	let config: Config = { ...CONFIG_DEFAULTS };
	try {
		const parsed: unknown = JSON.parse(readFileSync(configPath(), "utf8"));
		if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
			config = { ...config, ...(parsed as Partial<Config>) };
		}
	} catch {
		/* no config file, or unreadable: the defaults are the safe choice */
	}
	// A mistyped value falls back to the default, never to 0: 0 would widen the gate.
	config.approveAt =
		typeof config.approveAt === "number" && Number.isFinite(config.approveAt)
			? clamp01(config.approveAt)
			: CONFIG_DEFAULTS.approveAt;
	config.blockAt =
		typeof config.blockAt === "number" && Number.isFinite(config.blockAt)
			? clamp01(config.blockAt)
			: CONFIG_DEFAULTS.blockAt;
	if (config.blockAt > config.approveAt) config.blockAt = config.approveAt;
	if (typeof config.enabled !== "boolean") config.enabled = CONFIG_DEFAULTS.enabled;
	if (typeof config.sessionGrants !== "boolean") config.sessionGrants = CONFIG_DEFAULTS.sessionGrants;
	if (typeof config.log !== "boolean") config.log = CONFIG_DEFAULTS.log;
	if (typeof config.model !== "string" && config.model !== null) config.model = CONFIG_DEFAULTS.model;
	// JSON `1e999` parses to Infinity, which AbortSignal.timeout rejects; fall back instead.
	config.timeoutMs =
		typeof config.timeoutMs === "number" && Number.isFinite(config.timeoutMs)
			? Math.max(250, Math.trunc(config.timeoutMs))
			: CONFIG_DEFAULTS.timeoutMs;
	if (!Array.isArray(config.exclude)) config.exclude = [];
	if (!Array.isArray(config.deny)) config.deny = [];
	if (!Array.isArray(config.risky)) config.risky = [];
	return config;
}

function saveConfig(config: Config): string | undefined {
	try {
		const path = configPath();
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
		return undefined;
	} catch (error) {
		return (error as Error).message;
	}
}

// ---------------------------------------------------------------------------
// Static lists. Keep these in code, not in config: a mistyped config value must not be able to
// silently widen the gate. This list, not the threshold, is the security boundary — Jev only sees
// the text of a call and cannot tell that a `cat` reads a secret.
// ---------------------------------------------------------------------------

/** Always blocked. No prompt, no model, no override. */
const DENY: RegExp[] = [
	/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/, // fork bomb
	/\bdd\b[^\n]*\bof=\/dev\//,
	/\bmkfs(\.[a-z0-9]+)?\b/,
	/\b(shutdown|reboot|halt|poweroff)\b/,
	/\bcrontab\s+-r\b/,
	/\bkill\s+-9\s+-?1\b/,
	/\b(iptables|nft)\b[^\n]*(--flush|\s-F\b)/,
];

/**
 * Always a prompt, never Jev. Recursive deletes, force pushes, privilege escalation,
 * publish/deploy, and anything that hands a quoted string to another shell — the one way to hide
 * all of the above from a text check.
 */
const RISKY: RegExp[] = [
	/^(\S*['"\\=$]|[-0-9])/,
	/^(sudo|doas|su)\b/,
	/^(bash|sh|zsh|fish|eval|xargs)\b/,
	/^(node|bun|python3?)\s+(-\S+\s+)*(-c|-e|-p|--eval)\b/,
	/^rm\s+(-\S*[rRf]\S*\s+)+/,
	/^git\b.*\b(push|reset\s+--hard|clean\s+-\S*[fd]|branch\s+-D)\b/,
	/^(npm|pnpm|yarn|bun)\s+publish\b/,
	/^(wrangler|vercel|fly|flyctl)\s+deploy\b|^terraform\s+(apply|destroy)\b|^kubectl\s+(delete|apply)\b/,
	/\.env\b|\.ssh\b|\.aws\b|\.npmrc\b|\.netrc\b|credentials/i,
];

/** Paths that are never auto-approved, whatever the tool or command looks like. Always asked. */
const PROTECTED_PATHS: RegExp[] = [
	/(^|[\\/])\.env(\.|$)/i,
	/(^|[\\/])\.ssh([\\/]|$)/i,
	/(^|[\\/])\.aws([\\/]|$)/i,
	/(^|[\\/])\.npmrc$/i,
	/(^|[\\/])\.netrc$/i,
	/(^|[\\/])id_(rsa|ed25519|ecdsa|dsa)(\.|$)/i,
	/(^|[\\/])\.git[\\/]config$/i,
	/(^|[\\/])\.gnupg([\\/]|$)/i,
	/(^|[\\/])\.kube[\\/]config$/i,
];

/** Sentinel for "cannot be read safely". `/$^/` never matches. */
const UNPARSEABLE = /$^/;

/**
 * Refuse anything the text check cannot read: command substitution, process substitution,
 * backticks, line continuations. Splitting below ignores quotes, so a separator inside a quoted
 * argument can only add a prompt, never hide a command.
 */
function unreadable(text: string): boolean {
	return /\$\(|[<>]\(|`|\\\r?\n/.test(text);
}

/** Strip wrappers, assignments, path prefixes, and shell keywords until the program name is bare. */
function normalizeCommand(part: string): string {
	let current = part;
	while (true) {
		const next = current
			.trim()
			.replace(/^(if|then|elif|else|fi|while|until|do|done|for|in|case|esac|!)\s+/, "")
			.replace(/^(command|builtin|exec|env|nohup|time|timeout|nice|watch|npx|bunx|pnpx)\s+/, "")
			.replace(/^[A-Za-z_][A-Za-z0-9_]*=[^\s'"\\$]*\s+/, "")
			.replace(/^\\/, "")
			.replace(/^[^\s'"\\$]*\//, "");
		if (next === current) return current;
		current = next;
	}
}

/**
 * Split a shell command into its command units.
 *
 * Redirections are shielded first: in `2>&1` or `2>/dev/null` the `&` and digits belong to the
 * redirection, not a new command. Splitting there would leave a bare `1` that matches the
 * leading-digit guard in RISKY and flag every redirecting command as suspicious.
 */
function eachPart(text: string): string[] {
	const shielded = text.replace(/\d?>>?&?\d*/g, (whole) => whole.replace(/&/g, "\u0000"));
	return shielded.split(/\s*(?:&&|\|\||;|\||&|\n|[(){}])\s*/).map(normalizeCommand);
}

function firstMatch(patterns: readonly RegExp[], text: string): RegExp | undefined {
	return patterns.find((pattern) => pattern.test(text));
}

/** Match the risk list against every parsed part, so a compound command cannot hide one. */
function matchRisk(text: string, extra: readonly RegExp[]): RegExp | undefined {
	if (unreadable(text)) return UNPARSEABLE;
	const all = [...RISKY, ...extra];
	return firstMatch(all, text) ?? eachPart(text).map((part) => firstMatch(all, part)).find(Boolean) ?? undefined;
}

// ---------------------------------------------------------------------------
// Redaction. Jev is a third-party endpoint: send the shape of a call, not the secrets in it.
// Anything masked only reduces the evidence, which can lower a score and send the call to you —
// the safe direction.
// ---------------------------------------------------------------------------

const REDACTIONS: [RegExp, string][] = [
	// Private key blocks first: they must not be half-consumed by a later rule.
	[/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[private key redacted]"],
	// Authorization headers, so the scheme word is not mistaken for a value below.
	[/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 [redacted]"],
	// KEY=value and KEY: value assignments with secret-looking names. The lookahead keeps a bare
	// scheme word (`Authorization: Bearer`) from being read as the secret itself.
	[
		/\b([A-Za-z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AUTH)[A-Za-z0-9_.-]*)(\s*[=:]\s*)(["']?)(?!Bearer\b|Basic\b)([^\s"',;]{4,})\3/gi,
		"$1$2$3[redacted]$3",
	],
	// Vendor key and token shapes.
	[/\b(sk|pk|rk)-[A-Za-z0-9_-]{16,}\b/g, "$1-[redacted]"],
	[/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "gh[redacted]"],
	[/\bAKIA[0-9A-Z]{16}\b/g, "AKIA[redacted]"],
	[/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "xox[redacted]"],
	[/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "[jwt redacted]"],
];

const REDACTED_FIELDS = new Set(["content", "newText", "oldText", "text", "body", "arguments"]);

/** A JSON value, so a redacted payload has a name instead of `unknown`. */
type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

function redactText(text: string): string {
	let out = text;
	for (const [pattern, replacement] of REDACTIONS) out = out.replace(pattern, replacement);
	return out;
}

/**
 * Deep-copy a tool input, masking secrets and dropping bulky free text. Accepts `unknown` because
 * it sits at the boundary where pi hands us untrusted tool arguments; everything nested below is
 * treated as JSON.
 */
function redactValue(value: unknown, depth = 0): JsonValue {
	if (depth > 6) return "[deep]";
	if (typeof value === "string") return redactText(value);
	if (typeof value === "number" || typeof value === "boolean") return value;
	if (value === null || value === undefined) return null;
	if (Array.isArray(value)) return value.slice(0, 50).map((item) => redactValue(item, depth + 1));
	if (typeof value === "object") {
		const out: Record<string, JsonValue> = {};
		for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
			out[key] = REDACTED_FIELDS.has(key)
				? `[${typeof item === "string" ? item.length : 0} chars omitted]`
				: redactValue(item, depth + 1);
		}
		return out;
	}
	// Functions and symbols have no JSON form.
	return String(value);
}

// ---------------------------------------------------------------------------
// Describing a call
// ---------------------------------------------------------------------------

/** Tools that execute shell text, and the input field that carries it. */
const SHELL_TOOLS = new Set(["bash", "powershell", "exec_command", "shell", "run_command"]);
/** Tools whose target is a filesystem path. */
const PATH_TOOLS = new Set(["read", "write", "edit", "grep", "find", "ls", "ffgrep", "fffind"]);

interface CallShape {
	toolName: string;
	/** The text the static lists are matched against. */
	target: string;
	/** Paths the call names, for the containment check. */
	paths: string[];
	/** Whether the target should be parsed as shell text. */
	shell: boolean;
	/** What Jev is shown. Redacted. */
	state: Record<string, unknown>;
}

function stringField(input: Record<string, unknown>, keys: readonly string[]): string | undefined {
	for (const key of keys) {
		const value = input[key];
		if (typeof value === "string" && value.trim()) return value;
	}
	return undefined;
}

/** Best-effort absolute paths named in a shell command, for the containment check. */
function extractPaths(text: string): string[] {
	const found: string[] = [];
	for (const token of text.split(/\s+/)) {
		const cleaned = token.replace(/^['"`<]+|['"`>,;:]+$/g, "");
		if (!cleaned || cleaned.startsWith("-")) continue;
		if (cleaned.startsWith("~") || isAbsolute(cleaned) || cleaned.startsWith("../") || cleaned === "..") {
			found.push(cleaned);
		}
	}
	return found;
}

function describeCall(toolName: string, input: unknown): CallShape {
	const record = (typeof input === "object" && input !== null ? input : {}) as Record<string, unknown>;

	if (SHELL_TOOLS.has(toolName)) {
		const command = stringField(record, ["command", "cmd", "script"]) ?? "";
		return {
			toolName,
			target: command,
			paths: extractPaths(command),
			shell: true,
			state: { shell: redactValue(command) },
		};
	}

	const path = stringField(record, ["path", "file", "target", "file_path"]);
	if (PATH_TOOLS.has(toolName) || path) {
		const detail: Record<string, unknown> = {};
		for (const key of ["offset", "limit", "pattern", "glob", "oldText", "newText", "content"]) {
			const value = record[key];
			if (value === undefined) continue;
			// Write bodies are omitted outright: `redactValue` applies REDACTED_FIELDS only to
			// object keys, so a bare string would otherwise reach Jev verbatim.
			detail[key] =
				key === "oldText" || key === "newText" || key === "content"
					? `[${typeof value === "string" ? value.length : 0} chars omitted]`
					: redactValue(value);
		}
		return {
			toolName,
			target: path ? `${toolName} ${path}` : `${toolName} ${JSON.stringify(redactValue(record)).slice(0, 1_000)}`,
			paths: path ? [path] : [],
			shell: false,
			state: { tool: toolName, path: path ? redactValue(path) : null, ...detail },
		};
	}

	// Any other tool, including MCP and custom tools: judge the name and the redacted arguments.
	const args = redactValue(record);
	return {
		toolName,
		target: `${toolName} ${JSON.stringify(args).slice(0, 1_500)}`,
		paths: extractPathFields(record),
		shell: false,
		state: { tool: toolName, arguments: args },
	};
}

/** Paths carried under a non-standard key, so an exotic tool still gets the containment check. */
function extractPathFields(input: Record<string, unknown>): string[] {
	const out: string[] = [];
	for (const [key, value] of Object.entries(input)) {
		if (typeof value !== "string") continue;
		if (!/(path|file|dir|target|dest|output)/i.test(key)) continue;
		if (value.startsWith("~") || isAbsolute(value) || value.startsWith("..")) out.push(value);
	}
	return out;
}

/** Deterministic: a call that reaches outside the project is asked about, never auto-approved. */
function containmentProblem(call: CallShape, project: string): string | null {
	for (const raw of call.paths) {
		const expanded = raw.startsWith("~") ? join(homedir(), raw.slice(1)) : resolve(project, raw);
		const rel = relative(resolve(project), expanded);
		if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
			return `${raw} resolves outside the project (${expanded})`;
		}
	}
	return null;
}

function protectedPathProblem(call: CallShape): string | null {
	const haystack = `${call.target}\n${call.paths.join("\n")}`;
	const hit = matchesPath(PROTECTED_PATHS, haystack);
	return hit ? `touches a protected path (/${hit.source}/)` : null;
}

function matchesPath(patterns: readonly RegExp[], text: string): RegExp | undefined {
	return patterns.find((pattern) => pattern.test(text));
}

// ---------------------------------------------------------------------------
// The questions. Each is a complete proposition, true or false of the state on its own. Never ask
// "should this be approved" — that is what the thresholds decide, and splitting it into named
// checks is what gives you a readable reason for every block and a usable audit record.
// ---------------------------------------------------------------------------

const QUESTIONS = {
	reversible: {
		type: "bool",
		instructions:
			"Running `call` only reads or changes state inside `project`, and can be undone with `git` " +
			"or by rerunning it. It does not delete files outside `project`, change system settings, " +
			"publish or deploy, or send data to an external service.",
		criteria: {
			true: "Reversible and contained in the project",
			false: "Not reversible, or reaches outside the project",
		},
	},
	no_secrets: {
		type: "bool",
		instructions:
			"Running `call` does not read, print, copy, or transmit credentials, tokens, private keys, " +
			"or other secrets. Redacted values in `call` were masked before you saw them, so a masked " +
			"value is not by itself evidence of a secret.",
		criteria: { true: "Touches no secrets", false: "Touches secrets" },
	},
	serves_task: {
		type: "bool",
		instructions: "Running `call` is a reasonable next step toward `task`.",
		criteria: { true: "Serves the task", false: "Does not serve the task" },
	},
} as const;

type QuestionName = keyof typeof QUESTIONS;

// ---------------------------------------------------------------------------
// Jev, through pi's own classifier registry
// ---------------------------------------------------------------------------

type ClassifierHandle = ClassifierModel<ClassifierApi>;

/** Preference order: the configured model, then Jev, then any other decision model. */
function pickClassifier(
	available: readonly ClassifierHandle[],
	preferred: string | null,
): ClassifierHandle | undefined {
	if (preferred) {
		const [provider, ...rest] = preferred.split("/");
		const exact = available.find((m) => m.provider === provider && m.id === rest.join("/"));
		if (exact) return exact;
	}
	const byName = (re: RegExp) => available.find((m) => re.test(`${m.provider}/${m.id}`));
	return (
		byName(/^openrouter\/typesafe\/jev-/) ??
		byName(/^(typesafe|opencode|vercel-ai-gateway|cloudflare-workers-ai)\/.*jev/) ??
		byName(/^openai\/gpt-6-luna$/) ??
		byName(/clef/) ??
		available[0]
	);
}

function withTimeout(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
	const timer = AbortSignal.timeout(timeoutMs);
	if (!signal) return timer;
	return typeof AbortSignal.any === "function" ? AbortSignal.any([signal, timer]) : timer;
}

interface Scores {
	checks: Record<string, number>;
	model: string;
	cost?: number;
}

/**
 * Ask Jev. Resolves `undefined` on anything other than a clean answer: no model, network failure,
 * timeout, error response, missing answer, or a score outside 0..1. The caller turns `undefined`
 * into a prompt, never into an approval.
 */
async function askJev(
	ctx: ExtensionContext,
	state: Record<string, unknown>,
	asked: readonly QuestionName[],
	config: Config,
): Promise<Scores | undefined> {
	let available: readonly ClassifierHandle[] = [];
	try {
		available = await ctx.modelRegistry.getAvailableOfType("classifier");
	} catch {
		return undefined;
	}
	const model = pickClassifier(available, config.model);
	if (!model) return undefined;

	const questions = Object.fromEntries(asked.map((key) => [key, QUESTIONS[key]]));
	const result = await ctx.modelRegistry
		.classify(model, { state: state as never, questions: questions as never }, {
			signal: withTimeout(ctx.signal, config.timeoutMs),
		})
		.catch(() => undefined);
	if (!result || result.stopReason !== "stop") return undefined;

	const checks: Record<string, number> = {};
	for (const key of asked) {
		const answer = result.answers[key];
		if (!answer || answer.type !== "bool") return undefined;
		const p = (answer as { probability?: unknown }).probability;
		if (typeof p !== "number" || p < 0 || p > 1) return undefined;
		// Every question is phrased so that a high probability is a reason to approve.
		checks[key] = p;
	}
	return { checks, model: `${result.provider}/${result.model}`, cost: result.usage?.cost?.total };
}

// ---------------------------------------------------------------------------
// The task: the last thing the user asked for, which the relevance question reads
// ---------------------------------------------------------------------------

function lastUserText(ctx: ExtensionContext, limit = 2_000): string | undefined {
	try {
		const entries = ctx.sessionManager.buildContextEntries();
		for (let i = entries.length - 1; i >= 0; i--) {
			const entry = entries[i] as { type?: string; message?: { role?: string; content?: unknown } };
			if (entry.type !== "message" || entry.message?.role !== "user") continue;
			const content = entry.message.content;
			const text =
				typeof content === "string"
					? content
					: Array.isArray(content)
						? content
								.map((block) => (block as { type?: string; text?: string }).text ?? "")
								.filter(Boolean)
								.join("\n")
						: "";
			if (text.trim()) return redactText(text.trim().slice(0, limit));
		}
	} catch {
		/* no session state: the relevance question is simply not asked */
	}
	return undefined;
}

function askedQuestions(task: string | undefined): readonly QuestionName[] {
	return task ? ["reversible", "no_secrets", "serves_task"] : ["reversible", "no_secrets"];
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

type Stage = "disabled" | "excluded" | "deny" | "static" | "granted" | "jev" | "unavailable";

interface Decision {
	outcome: "allow" | "block" | "ask";
	reason: string;
	stage: Stage;
	checks: Record<string, number> | null;
	model?: string;
	cost?: number;
}

/** Session-scoped grants, keyed by tool and target, cleared on session start and shutdown. */
const grants = new Set<string>();

function grantKey(call: CallShape): string {
	return `${call.toolName}\u0000${call.target}`;
}

/**
 * Everything this extension decides, before it touches the UI. Also powers
 * `/warrant test`, which is why it takes no session state it cannot build itself.
 */
async function decide(ctx: ExtensionContext, call: CallShape, config: Config): Promise<Decision> {
	if (!config.enabled) {
		return { outcome: "allow", reason: "gate disabled", stage: "disabled", checks: null };
	}
	if (config.exclude.includes(call.toolName)) {
		return { outcome: "allow", reason: "tool excluded", stage: "excluded", checks: null };
	}

	const denyExtra = config.deny.map(toRegExp).filter(Boolean) as RegExp[];
	const deny = firstMatch([...DENY, ...denyExtra], call.target);
	if (deny) {
		return {
			outcome: "block",
			reason: `blocked by deny rule /${deny.source}/ — do not attempt this; choose another approach`,
			stage: "deny",
			checks: null,
		};
	}

	const riskyExtra = config.risky.map(toRegExp).filter(Boolean) as RegExp[];
	if (call.shell) {
		const risky = matchRisk(call.target, riskyExtra);
		if (risky) {
			return {
				outcome: "ask",
				reason:
					risky === UNPARSEABLE
						? "this command cannot be read by a text check"
						: `matches static risk pattern /${risky.source}/`,
				stage: "static",
				checks: null,
			};
		}
	} else {
		const risky = firstMatch(riskyExtra, call.target);
		if (risky) {
			return {
				outcome: "ask",
				reason: `matches static risk pattern /${risky.source}/`,
				stage: "static",
				checks: null,
			};
		}
	}

	const protectedPath = protectedPathProblem(call);
	if (protectedPath) {
		return { outcome: "ask", reason: protectedPath, stage: "static", checks: null };
	}

	const escaped = containmentProblem(call, ctx.cwd ?? process.cwd());
	if (escaped) {
		return { outcome: "ask", reason: escaped, stage: "static", checks: null };
	}

	if (config.sessionGrants && grants.has(grantKey(call))) {
		return { outcome: "allow", reason: "covered by a session grant", stage: "granted", checks: null };
	}

	const task = lastUserText(ctx);
	const state: Record<string, unknown> = {
		call: call.state,
		project: ctx.cwd ?? process.cwd(),
	};
	if (task) {
		state.task = task;
		state.asked = askedQuestions(task);
	}
	const scores = await askJev(ctx, state, askedQuestions(task), config);
	if (!scores) {
		return {
			outcome: "ask",
			reason: "Jev is unavailable, timed out, or answered unrecognisably",
			stage: "unavailable",
			checks: null,
		};
	}

	const values = Object.values(scores.checks);
	const base = { stage: "jev" as const, checks: scores.checks, model: scores.model, cost: scores.cost };
	if (values.every((p) => p >= config.approveAt)) {
		return { ...base, outcome: "allow", reason: "every check clear" };
	}
	const failed = Object.entries(scores.checks)
		.filter(([, p]) => p <= config.blockAt)
		.map(([name, p]) => `${name}=${p.toFixed(2)}`);
	if (failed.length > 0) {
		return {
			...base,
			outcome: "block",
			reason: `failed ${failed.join(", ")} — reconsider whether this call is needed`,
		};
	}
	return { ...base, outcome: "ask", reason: "no check is clearly true or clearly false" };
}

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

function appendLog(entry: Record<string, unknown>, config: Config): void {
	if (!config.log) return;
	try {
		const path = logPath();
		mkdirSync(dirname(path), { recursive: true });
		// Every string is untrusted: the target and the reason both embed command or path text,
		// and a path can carry a secret (`cat /tmp/AUTH=...`) that the target rule would miss.
		const safe: Record<string, unknown> = {};
		for (const [key, value] of Object.entries(entry)) {
			safe[key] = typeof value === "string" ? redactText(value) : value;
		}
		appendFileSync(path, `${JSON.stringify({ ts: new Date().toISOString(), ...safe })}\n`, {
			encoding: "utf8",
			mode: 0o600,
		});
		// `mode` applies only when the file is created; tighten one that already exists.
		chmodSync(path, 0o600);
	} catch {
		/* logging must never break a tool call */
	}
}

function readLog(count: number): string[] {
	try {
		const lines = readFileSync(logPath(), "utf8").trim().split("\n").filter(Boolean);
		return lines.slice(-count).map((line) => {
			try {
				const entry = JSON.parse(line) as Record<string, unknown>;
				const checks = entry.checks
					? ` ${Object.entries(entry.checks as Record<string, number>)
							.map(([k, v]) => `${k}=${Number(v).toFixed(2)}`)
							.join(" ")}`
					: "";
				const target = String(entry.target ?? "").slice(0, 60);
				return `${entry.ts} ${String(entry.outcome).toUpperCase().padEnd(5)} (${entry.stage}) ${entry.tool} ${target} — ${entry.reason}${checks}`;
			} catch {
				return line;
			}
		});
	} catch {
		return [];
	}
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

export default function warrant(pi: ExtensionAPI): void {
	let config = loadConfig();
	let warnedNoModel = false;

	pi.on("session_start", () => {
		config = loadConfig();
		grants.clear();
		warnedNoModel = false;
	});

	pi.on("session_shutdown", () => {
		grants.clear();
	});

	pi.on("tool_call", async (event, ctx): Promise<{ block: boolean; reason?: string } | undefined> => {
		const current = config;
		if (!current.enabled || current.exclude.includes(event.toolName)) return undefined;

		const call = describeCall(event.toolName, event.input);
		if (!call.target.trim()) return undefined;

		ctx.ui.setStatus("warrant", "checking…");
		let decision: Decision;
		try {
			decision = await decide(ctx, call, current);
		} finally {
			ctx.ui.setStatus("warrant", undefined);
		}

		if (decision.outcome === "ask" && ctx.hasUI) {
			const preview = call.target.slice(0, 1_500);
			const scores = decision.checks
				? `\n\n${Object.entries(decision.checks)
						.map(([name, p]) => `  ${name}: ${p.toFixed(2)}`)
						.join("\n")}`
				: "";
			const options = current.sessionGrants ? ["Allow once", "Allow for session", "Block"] : ["Allow once", "Block"];
			const choice = await ctx.ui.select(
				`${event.toolName} wants to run:\n\n  ${preview}\n\n${decision.reason}${scores}`,
				options,
			);
			if (choice === "Allow for session") {
				grants.add(grantKey(call));
				decision = { ...decision, outcome: "allow", reason: "allowed for this session by you" };
			} else if (choice === "Allow once") {
				decision = { ...decision, outcome: "allow", reason: "allowed once by you" };
			} else {
				decision = {
					...decision,
					outcome: "block",
					reason: choice === undefined ? "you dismissed the prompt" : "blocked by you",
				};
			}
		} else if (decision.outcome === "ask") {
			// No UI to ask: denying is the only safe reading of "needs a human".
			decision = { ...decision, outcome: "block", reason: `needs your review (${decision.reason}) and no UI is available` };
		}

		appendLog(
			{
				tool: call.toolName,
				target: redactText(call.target).slice(0, 500),
				outcome: decision.outcome,
				stage: decision.stage,
				reason: decision.reason,
				checks: decision.checks,
				model: decision.model,
				cost: decision.cost,
			},
			current,
		);

		if (decision.stage === "unavailable" && !warnedNoModel) {
			warnedNoModel = true;
			ctx.ui.notify(
				"warrant: no classifier model available — set TYPESAFE_API_KEY or OPENROUTER_API_KEY. " +
					"Until then every call asks you.",
				"warning",
			);
		}

		if (decision.outcome === "allow") return undefined;
		return { block: true, reason: `warrant: ${decision.reason}` };
	});

	pi.registerCommand("warrant", {
		description: "Jev permission gate: status, on/off, thresholds, test <tool> <input>, log",
		getArgumentCompletions: (prefix: string) => {
			const first = prefix.trim().split(/\s+/)[0] ?? "";
			const words = ["status", "on", "off", "thresholds", "test", "log", "reload"];
			const items = words.filter((w) => w.startsWith(first)).map((w) => ({ value: w, label: w }));
			return items.length > 0 ? items : null;
		},
		handler: async (args, ctx) => {
			const [verb, ...rest] = args.trim().split(/\s+/);
			const arg = rest.join(" ").trim();

			switch (verb) {
				case undefined:
				case "":
				case "status": {
					const model = await describeModel(ctx, config);
					ctx.ui.notify(
						[
							`enabled: ${config.enabled}`,
							`gated tools: ${config.exclude.length === 0 ? "all" : `all except ${config.exclude.join(", ")}`}`,
							`thresholds: allow >= ${config.approveAt}, block <= ${config.blockAt}, else ask`,
							`timeout: ${config.timeoutMs}ms`,
							`classifier: ${model}`,
							`session grants: ${config.sessionGrants ? `${grants.size} active` : "off"}`,
							`log: ${config.log ? logPath() : "off"}`,
						].join("\n"),
						"info",
					);
					return;
				}
				case "on":
				case "off": {
					config = { ...config, enabled: verb === "on" };
					const error = saveConfig(config);
					ctx.ui.notify(
						error
							? `warrant ${verb === "on" ? "enabled" : "disabled"} (could not save: ${error})`
							: `warrant ${verb === "on" ? "enabled" : "disabled"} — saved to ${configPath()}`,
						error ? "warning" : "info",
					);
					return;
				}
				case "thresholds": {
					// `Number("")` is 0, so an empty arg must be rejected before it reaches the clamp.
					const tokens = arg.split(/\s+/).filter(Boolean);
					if (tokens.length === 0 || tokens.some((token) => !Number.isFinite(Number(token)))) {
						ctx.ui.notify("usage: /warrant thresholds <approveAt> [blockAt]", "warning");
						return;
					}
					const approveAt = Number(tokens[0]);
					config = { ...config, approveAt: clamp01(approveAt) };
					if (tokens.length > 1) config.blockAt = clamp01(Number(tokens[1]));
					if (config.blockAt > config.approveAt) config.blockAt = config.approveAt;
					const error = saveConfig(config);
					ctx.ui.notify(
						`thresholds: allow >= ${config.approveAt}, block <= ${config.blockAt}` + (error ? ` (could not save: ${error})` : ""),
						error ? "warning" : "info",
					);
					return;
				}
				case "reload": {
					config = loadConfig();
					warnedNoModel = false;
					ctx.ui.notify("warrant config reloaded", "info");
					return;
				}
				case "log": {
					const lines = readLog(Number(arg) || 20);
					ctx.ui.notify(lines.length > 0 ? lines.join("\n") : "log is empty", "info");
					return;
				}
				case "test": {
					if (!arg) {
						ctx.ui.notify("usage: /warrant test <command>   (shortcut for: test bash <command>)", "warning");
						return;
					}
					// `test bash <cmd>` picks an explicit tool; anything else is treated as a command.
					const explicit = rest[0] === "bash" || rest[0] === "write" || rest[0] === "edit";
					const toolName = explicit ? rest[0] : "bash";
					const body = explicit ? rest.slice(1).join(" ") : arg;
					if (!body) {
						ctx.ui.notify("usage: /warrant test <command>", "warning");
						return;
					}
					const input =
						toolName === "bash" ? { command: body } : toolName === "write" ? { path: body, content: "" } : { path: body };
					const call = describeCall(toolName, input);
					ctx.ui.setStatus("warrant", "checking…");
					let decision: Decision;
					try {
						decision = await decide(ctx, call, config);
					} finally {
						ctx.ui.setStatus("warrant", undefined);
					}
					const checks = decision.checks
						? `\nchecks: ${Object.entries(decision.checks)
								.map(([name, p]) => `${name}=${p.toFixed(2)}`)
								.join(" ")}`
						: "";
					const cost = decision.cost === undefined ? "" : `\ncost: $${decision.cost}`;
					ctx.ui.notify(
						`${decision.outcome.toUpperCase()}  (${decision.stage})\n${decision.reason}${checks}${cost}\n\nNothing was executed.`,
						decision.outcome === "block" ? "error" : decision.outcome === "ask" ? "warning" : "info",
					);
					return;
				}
				default:
					ctx.ui.notify(
						"usage: /warrant [status|on|off|thresholds <a> [b]|test <command>|log [n]|reload]",
						"warning",
					);
			}
		},
	});
}

async function describeModel(ctx: ExtensionContext, config: Config): Promise<string> {
	try {
		const available = await ctx.modelRegistry.getAvailableOfType("classifier");
		const model = pickClassifier(available, config.model);
		if (!model) return "none available — set TYPESAFE_API_KEY or OPENROUTER_API_KEY (every call will ask)";
		return `${model.provider}/${model.id} (of ${available.length} available)`;
	} catch (error) {
		return `unavailable: ${(error as Error).message}`;
	}
}