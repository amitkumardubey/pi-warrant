/**
 * Smoke test for pi-warrant. Stubs pi's extension surface and exercises every decision stage,
 * including non-shell tools, the no-UI path, session grants, and redaction.
 */
import ext from "../warrant.ts";

const handlers: Record<string, ((e: unknown, c: unknown) => unknown)[]> = {};
const commands: string[] = [];
const pi = {
	on: (event: string, handler: (e: unknown, c: unknown) => unknown) => {
		(handlers[event] ??= []).push(handler);
	},
	events: { on: () => {} },
	registerCommand: (name: string) => commands.push(name),
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

console.log(`\n${all ? "ALL PASS" : "SOME FAILED"}`);
process.exit(all ? 0 : 1);