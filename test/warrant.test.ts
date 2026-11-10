/**
 * Smoke test for pi-warrant. Stubs pi's extension surface and exercises every decision stage,
 * including non-shell tools, the no-UI path, session grants, redaction, and the `/warrant` command.
 *
 * `HOME` is redirected to a scratch directory: the extension resolves `~/.pi` through
 * `os.homedir()`, so without this the suite would write config and audit records to the real home.
 */
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import * as actualOs from "node:os";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

// Bun caches `os.homedir()` after its first call, so changing HOME at runtime would not move the
// extension's config/log directory. Mock that one function to read HOME each time, then load the
// extension so its `node:os` import sees the mock.
const require = createRequire(import.meta.url);
const { mock } = require("bun:test") as {
	mock: { module: (specifier: string, factory: () => Record<string, unknown>) => void };
};
mock.module("node:os", () => ({
	...actualOs,
	homedir: () => process.env.HOME ?? actualOs.homedir(),
}));
const ext = (await import("../warrant.ts")).default;

const realHome = process.env.HOME;
const suiteHome = mkdtempSync(join(tmpdir(), "warrant-test-"));
process.env.HOME = suiteHome;

const handlers: Record<string, ((e: unknown, c: unknown) => unknown)[]> = {};
const commands: string[] = [];
const commandSpecs = new Map<string, { handler: (args: string, ctx: unknown) => Promise<unknown> }>();
const pi = {
	on: (event: string, handler: (e: unknown, c: unknown) => unknown) => {
		(handlers[event] ??= []).push(handler);
	},
	events: { on: () => {} },
	registerCommand: (name: string, spec?: unknown) => {
		commands.push(name);
		if (spec && typeof spec === "object" && "handler" in spec) {
			commandSpecs.set(name, spec as { handler: (args: string, ctx: unknown) => Promise<unknown> });
		}
	},
};

let classifierAvailable = false;
let answers: Record<string, number> = {};

function makeCtx(opts: { hasUI: boolean; choice?: string; cwd?: string }) {
	return {
		cwd: opts.cwd ?? "/home/amit/projects/demo",
		signal: undefined,
		hasUI: opts.hasUI,
		ui: {
			setStatus: () => {},
			notify: () => {},
			select: async (_t: string, options: string[]) =>
				opts.choice !== undefined && options.includes(opts.choice) ? opts.choice : undefined,
		},
		sessionManager: {
			buildContextEntries: () => [
				{ type: "message", message: { role: "user", content: "fix the failing date parsing test" } },
			],
		},
		modelRegistry: {
			async getAvailableOfType() {
				return classifierAvailable ? [{ provider: "typesafe", id: "jev-latest", type: "classifier" }] : [];
			},
			async classify() {
				return {
					stopReason: "stop",
					provider: "typesafe",
					model: "jev-latest",
					answers: Object.fromEntries(
						Object.entries(answers).map(([k, v]) => [k, { type: "bool", probability: v }]),
					),
					usage: { cost: { total: 0.00002 } },
				};
			},
		},
	};
}

ext(pi as never);
const onToolCall = handlers["tool_call"][0];
const warrantCommand = commandSpecs.get("warrant");
if (!warrantCommand) throw new Error("warrant command was not registered");
const warrantHandler = warrantCommand.handler;

async function run(
	name: string,
	toolName: string,
	input: unknown,
	expected: "allow" | "block",
	opts: { hasUI?: boolean; choice?: string; setup?: () => void } = {},
) {
	opts.setup?.();
	const result = (await onToolCall(
		{ toolName, input },
		makeCtx({ hasUI: opts.hasUI ?? true, choice: opts.choice }),
	)) as { block: boolean; reason?: string } | undefined;
	const actual = result?.block ? "block" : "allow";
	const ok = actual === expected;
	console.log(`${ok ? "PASS" : "FAIL"}  ${name.padEnd(30)} ${actual.padEnd(5)} ${result?.reason ?? ""}`);
	return ok;
}

function newSession() {
	for (const h of handlers["session_start"] ?? []) h({}, {});
}

let all = true;
newSession();
console.log(`command registered: /${commands.join(", /")}\n`);

all = (await run("deny: fork bomb", "bash", { command: ":(){ :|:& };:" }, "block")) && all;
all = (await run("deny: dd to device", "bash", { command: "dd if=/dev/zero of=/dev/sda" }, "block")) && all;

classifierAvailable = true;
answers = { reversible: 0.99, no_secrets: 0.99, serves_task: 0.99 };
all = (await run("static: force push", "bash", { command: "git push --force" }, "block", { choice: "Block" })) && all;
all = (await run("static: sudo", "bash", { command: "sudo rm x" }, "block", { choice: "Block" })) && all;
all = (await run("static: rm -rf", "bash", { command: "rm -rf src" }, "block", { choice: "Block" })) && all;
all = (await run("static: shell indirection", "bash", { command: "eval $(cat x)" }, "block", { choice: "Block" })) && all;
all = (await run("static: hidden in chain", "bash", { command: "ls && git push" }, "block", { choice: "Block" })) && all;
all = (await run("static: path prefix evade", "bash", { command: "/usr/bin/rm -rf /" }, "block", { choice: "Block" })) && all;

// Regression: a redirect like `2>&1` must not be split at the `&`, which used to leave a bare `1`
// that matched the leading-digit guard and flagged every redirecting command as risky.
all = (await run("redirect: 2>&1 is not risky", "bash", { command: "ls -la 2>&1" }, "allow", {
	setup: () => { answers = { reversible: 0.95, no_secrets: 0.95, serves_task: 0.95 }; },
})) && all;
all = (await run("redirect: 2>/dev/null ok", "bash", { command: "npm test 2>/dev/null" }, "allow", {
	setup: () => { answers = { reversible: 0.95, no_secrets: 0.95, serves_task: 0.95 }; },
})) && all;

all = (await run("protected: read .env", "read", { path: "/home/amit/projects/demo/.env" }, "block", { choice: "Block" })) && all;
all = (await run("protected: write key", "write", { path: "/home/amit/.ssh/id_rsa", content: "x" }, "block", { choice: "Block" })) && all;
all = (await run("protected: bash cat aws", "bash", { command: "cat ~/.aws/credentials" }, "block", { choice: "Block" })) && all;

all = (await run("escaped: write outside", "write", { path: "../../etc/passwd", content: "x" }, "block", { choice: "Block" })) && all;
all = (await run("escaped: read absolute", "read", { path: "/etc/hosts" }, "block", { choice: "Block" })) && all;
all = (await run("inside: read in project", "read", { path: "/home/amit/projects/demo/src/a.ts" }, "allow", { choice: "Allow once" })) && all;

all = (await run("jev: all clear", "bash", { command: "bun test src/date.test.ts" }, "allow", {
	setup: () => { answers = { reversible: 0.93, no_secrets: 0.95, serves_task: 0.95 }; },
})) && all;
all = (await run("jev: all clear, edit tool", "edit", { path: "/home/amit/projects/demo/src/a.ts", oldText: "a", newText: "b" }, "allow", {
	setup: () => { answers = { reversible: 0.95, no_secrets: 0.95, serves_task: 0.95 }; },
})) && all;
all = (await run("jev: all clear, custom tool", "my_deploy", { target: "staging" }, "allow", {
	setup: () => { answers = { reversible: 0.95, no_secrets: 0.95, serves_task: 0.95 }; },
})) && all;
all = (await run("jev: touches secrets", "bash", { command: "grep -r TOKEN ." }, "block", {
	setup: () => { answers = { reversible: 0.95, no_secrets: 0.08, serves_task: 0.95 }; },
})) && all;
all = (await run("jev: clearly off task", "bash", { command: "bun add left-pad" }, "block", {
	setup: () => { answers = { reversible: 0.95, no_secrets: 0.95, serves_task: 0.05 }; },
})) && all;
all = (await run("jev: ambiguous -> ask", "bash", { command: "curl https://api.example.com" }, "block", {
	choice: "Block",
	setup: () => { answers = { reversible: 0.5, no_secrets: 0.95, serves_task: 0.6 }; },
})) && all;

all = (await run("prompt: allow once", "bash", { command: "npm run lint" }, "allow", {
	choice: "Allow once",
	setup: () => { answers = { reversible: 0.5, no_secrets: 0.95, serves_task: 0.6 }; },
})) && all;
all = (await run("prompt: allow for session", "bash", { command: "npm run lint" }, "allow", {
	choice: "Allow for session",
	setup: () => { answers = { reversible: 0.5, no_secrets: 0.95, serves_task: 0.6 }; },
})) && all;
all = (await run("grant: reuse", "bash", { command: "npm run lint" }, "allow", {
	setup: () => { answers = { reversible: 0.0, no_secrets: 0.0, serves_task: 0.0 }; },
})) && all;
all = (await run("prompt: dismissed", "bash", { command: "npm run build" }, "block", {
	setup: () => { answers = { reversible: 0.5, no_secrets: 0.95, serves_task: 0.6 }; },
})) && all;

all = (await run("no UI: needs review", "bash", { command: "npm run build" }, "block", {
	hasUI: false,
	setup: () => { answers = { reversible: 0.5, no_secrets: 0.95, serves_task: 0.6 }; },
})) && all;

all = (await run("no classifier + UI", "bash", { command: "bun test" }, "block", {
	choice: "Block",
	setup: () => { classifierAvailable = false; },
})) && all;

// Redaction: a secret in the command must not reach the classifier.
let seen: unknown;
classifierAvailable = true;
const ctxR: any = makeCtx({ hasUI: true, choice: "Block" });
ctxR.modelRegistry.classify = async (_m: unknown, context: { state: unknown }) => {
	seen = context.state;
	return {
		stopReason: "stop", provider: "typesafe", model: "jev-latest",
		answers: {
			reversible: { type: "bool", probability: 0.5 },
			no_secrets: { type: "bool", probability: 0.95 },
			serves_task: { type: "bool", probability: 0.6 },
		},
		usage: { cost: { total: 0.00002 } },
	};
};
await onToolCall(
	{ toolName: "bash", input: { command: "curl -H 'Authorization: Bearer sk-abcdef1234567890abcdef' https://x" } },
	ctxR,
);
const serialized = JSON.stringify(seen);
const leaked = /sk-abcdef/.test(serialized);
console.log(`${leaked ? "FAIL" : "PASS"}  redaction: secret withheld from Jev`);
console.log(`      ${serialized.slice(0, 150)}`);
all = !leaked && all;

// ---------------------------------------------------------------------------
// `/warrant` command: threshold parsing, config coercion, redaction, audit log
// ---------------------------------------------------------------------------

function check(name: string, ok: boolean, detail = ""): boolean {
	console.log(`${ok ? "PASS" : "FAIL"}  ${name.padEnd(30)} ${detail.slice(0, 200)}`);
	return ok;
}

function notifyCtx(hasUI = true) {
	const messages: { text: string; level: string }[] = [];
	const ctx: any = makeCtx({ hasUI });
	ctx.ui.notify = (text: string, level?: string) => {
		messages.push({ text, level: level ?? "" });
	};
	return { ctx, messages };
}

async function runCommand(args: string): Promise<string[]> {
	const { ctx, messages } = notifyCtx();
	await warrantHandler(args, ctx);
	return messages.map((message) => message.text);
}

/** Run `fn` with `HOME` pointed at a fresh scratch directory, then restore and remove it. */
async function withHome<T>(fn: (home: string) => Promise<T>): Promise<T> {
	const home = mkdtempSync(join(tmpdir(), "warrant-test-"));
	const previous = process.env.HOME;
	process.env.HOME = home;
	try {
		return await fn(home);
	} finally {
		process.env.HOME = previous;
		rmSync(home, { recursive: true, force: true });
	}
}

function configFile(home: string): string {
	return join(home, ".pi", "agent", "extensions", "warrant.json");
}

function writeConfig(home: string, config: unknown): string {
	const path = configFile(home);
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
	return path;
}

function readConfig(home: string): Record<string, unknown> {
	return JSON.parse(readFileSync(configFile(home), "utf8")) as Record<string, unknown>;
}

function logFile(home: string): string {
	return join(home, ".pi", "agent", "extensions", "warrant.log");
}

function usage(messages: string[]): boolean {
	return messages.some((text) => text.includes("usage: /warrant thresholds"));
}

// Threshold parsing: an empty or garbage argument must show usage and change nothing.
await withHome(async (home) => {
	const path = writeConfig(home, { approveAt: 0.7, blockAt: 0.2 });
	await runCommand("reload");
	const before = readFileSync(path, "utf8");

	const noArgs = await runCommand("thresholds");
	const garbage = await runCommand("thresholds abc");
	const mixed = await runCommand("thresholds 0.9 abc");

	all = check("thresholds: no args -> usage", usage(noArgs), noArgs.join(" | ")) && all;
	all = check("thresholds: garbage -> usage", usage(garbage), garbage.join(" | ")) && all;
	all = check("thresholds: mixed -> usage", usage(mixed), mixed.join(" | ")) && all;
	all = check("thresholds: bad args change nothing", readFileSync(path, "utf8") === before) && all;

	const status = (await runCommand("status")).join("\n");
	all = check("thresholds: config survives bad args", status.includes("allow >= 0.7, block <= 0.2"), status) && all;
});

// A valid pair still saves.
await withHome(async (home) => {
	await runCommand("thresholds 0.8 0.3");
	const saved = readConfig(home);
	all =
		check("thresholds: valid pair saves", saved.approveAt === 0.8 && saved.blockAt === 0.3, JSON.stringify(saved)) &&
		all;
});

// Config coercion: a mistyped threshold or flag falls back to the default, never to 0.
classifierAvailable = true;
await withHome(async (home) => {
	writeConfig(home, { approveAt: "0.95", blockAt: "0.05", enabled: 0, sessionGrants: 0, log: 0, model: 42 });
	await runCommand("reload");
	const status = (await runCommand("status")).join("\n");
	all = check("config: string threshold -> default", status.includes("thresholds: allow >= 0.9, block <= 0.1"), status) && all;
	all = check("config: non-boolean enabled -> default", status.includes("enabled: true"), status) && all;
	all = check("config: non-boolean sessionGrants -> default", !status.includes("session grants: off"), status) && all;
	all = check("config: non-boolean log -> default", status.includes(`log: ${logFile(home)}`), status) && all;
	all = check("config: non-string model -> default", status.includes("classifier: typesafe/jev-latest"), status) && all;
});

// A non-finite timeoutMs (JSON `1e999` parses to Infinity) must fall back, not reach
// AbortSignal.timeout, which throws on Infinity.
await withHome(async (home) => {
	const path = configFile(home);
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, '{"timeoutMs": 1e999}\n', "utf8");
	await runCommand("reload");
	const status = (await runCommand("status")).join("\n");
	all = check("config: non-finite timeoutMs -> default", status.includes("timeout: 8000ms"), status) && all;
});

// Valid numbers still load.
await withHome(async (home) => {
	writeConfig(home, { approveAt: 0.8, blockAt: 0.2 });
	await runCommand("reload");
	const status = (await runCommand("status")).join("\n");
	all = check("config: valid numbers load", status.includes("allow >= 0.8, block <= 0.2"), status) && all;
});

// Path-tool redaction: write bodies must be omitted from the state sent to Jev.
async function captureState(toolName: string, input: unknown): Promise<string> {
	let seen: unknown;
	const ctx: any = makeCtx({ hasUI: true, choice: "Allow once" });
	ctx.modelRegistry.classify = async (_m: unknown, context: { state: unknown }) => {
		seen = context.state;
		return {
			stopReason: "stop",
			provider: "typesafe",
			model: "jev-latest",
			answers: {
				reversible: { type: "bool", probability: 0.95 },
				no_secrets: { type: "bool", probability: 0.95 },
				serves_task: { type: "bool", probability: 0.95 },
			},
			usage: { cost: { total: 0 } },
		};
	};
	await onToolCall({ toolName, input }, ctx);
	return JSON.stringify(seen);
}

const writeState = await captureState("write", {
	path: "/home/amit/projects/demo/src/a.ts",
	content: "TOP_SECRET_WRITE_BODY_9f3a",
});
const editState = await captureState("edit", {
	path: "/home/amit/projects/demo/src/a.ts",
	oldText: "TOP_SECRET_OLD_TEXT_7c2b",
	newText: "TOP_SECRET_NEW_TEXT_5d1e",
});
const pathLeak = /TOP_SECRET_(WRITE_BODY|OLD_TEXT|NEW_TEXT)/.test(`${writeState}${editState}`);
all = check("redaction: write body withheld from Jev", !pathLeak, `${writeState} ${editState}`) && all;
all =
	check(
		"redaction: write body reported as omitted",
		writeState.includes("chars omitted") && editState.includes("chars omitted"),
	) && all;

// Audit log: redact the target and keep the file owner-only.
await withHome(async (home) => {
	writeConfig(home, { log: true });
	await runCommand("reload");
	// Pre-create the log world-readable to exercise the chmod on an existing file.
	mkdirSync(dirname(logFile(home)), { recursive: true });
	writeFileSync(logFile(home), "", "utf8");
	chmodSync(logFile(home), 0o644);
	classifierAvailable = true;
	answers = { reversible: 0.95, no_secrets: 0.95, serves_task: 0.95 };
	const token = "supersecrettoken12345";
	await onToolCall(
		{ toolName: "bash", input: { command: `curl -H 'Authorization: Bearer ${token}' https://example.com/x` } },
		makeCtx({ hasUI: true, choice: "Allow once" }),
	);
	const log = readFileSync(logFile(home), "utf8");
	const mode = statSync(logFile(home)).mode & 0o777;
	all = check("log: token withheld", !log.includes(token), log.trim()) && all;
	all = check("log: target redacted", log.includes("[redacted]"), log.trim()) && all;
	all = check("log: mode 0600", mode === 0o600, mode.toString(8)) && all;
});

// A secret carried in a path reaches the log through the containment reason, not only the target.
await withHome(async (home) => {
	writeConfig(home, { log: true });
	await runCommand("reload");
	const token = "SUPERSECRETVALUE12345";
	await onToolCall(
		{ toolName: "bash", input: { command: `cat /tmp/notes/AUTH=${token}` } },
		makeCtx({ hasUI: false }),
	);
	const log = readFileSync(logFile(home), "utf8");
	all = check("log: token in path withheld", !log.includes(token), log.trim()) && all;
});

process.env.HOME = realHome;
rmSync(suiteHome, { recursive: true, force: true });

console.log(`\n${all ? "ALL PASS" : "SOME FAILED"}`);
process.exit(all ? 0 : 1);
