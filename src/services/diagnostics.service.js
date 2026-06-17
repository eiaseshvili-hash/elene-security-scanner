import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const COMMAND_TIMEOUT_MS = 10000;

function isValidTarget(value) {
  const input = String(value || "").trim();

  if (!input) return false;
  if (input.length > 253) return false;

  // domain / ipv4 / simple ipv6-safe chars
  return /^[a-zA-Z0-9.:_-]+$/.test(input);
}

function cleanTarget(value) {
  return String(value || "").trim().toLowerCase();
}

async function runCommand(command, args) {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: COMMAND_TIMEOUT_MS,
      maxBuffer: 1024 * 1024
    });

    return {
      ok: true,
      command,
      args,
      output: (stdout || stderr || "").trim()
    };
  } catch (error) {
    return {
      ok: false,
      command,
      args,
      output: (error.stdout || error.stderr || error.message || "Command failed").trim()
    };
  }
}

async function runTraceroute(target) {
  const tracerouteResult = await runCommand("traceroute", ["-m", "8", "-q", "1", "-w", "1", target]);

  if (tracerouteResult.ok || !/ENOENT|not found/i.test(tracerouteResult.output)) {
    return tracerouteResult;
  }

  return runCommand("tracepath", ["-m", "8", target]);
}

export async function getDiagnosticsReport(input) {
  const target = cleanTarget(input);

  if (!isValidTarget(target)) {
    throw new Error("Invalid domain or IP address");
  }

  const startedAt = new Date();

  const [pingResult, tracerouteResult] = await Promise.all([
    runCommand("ping", ["-c", "5", target]),
    runTraceroute(target)
  ]);

  return {
    checked: true,
    target,
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    ping: {
      ok: pingResult.ok,
      output: pingResult.output
    },
    traceroute: {
      ok: tracerouteResult.ok,
      output: tracerouteResult.output
    }
  };
}