#!/usr/bin/env node
import { existsSync, readFileSync } from "fs";
import { join, dirname, resolve } from "path";
import { parse } from "yaml";
import { fileURLToPath } from "url";

// -------------------------------------
// Config
// -------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DEFAULT_LIST_FILE = "malicious_list.txt";
const defaultListPath = join(__dirname, DEFAULT_LIST_FILE);
const SUPPORTED_LOCKFILE = "pnpm-lock.yaml";

// -------------------------------------
// CLI flags
// -------------------------------------
function getFlagValue(prefix) {
    const arg = process.argv.find(a => a.startsWith(prefix));
    return arg ? arg.split("=")[1].trim() : null;
}

const FLAGS = {
    json: process.argv.includes("--json"),
    silent: process.argv.includes("--silent"),
    failOnSafe: process.argv.includes("--fail-on-safe"),
    includeDev: process.argv.includes("--include-dev"),
    strict: process.argv.includes("--strict"),
    maliciousFile: getFlagValue("--malicious=") // NEW
};

function humanOutputEnabled() {
    return !FLAGS.silent && !FLAGS.json;
}

function log(...args) {
    if (humanOutputEnabled()) console.log(...args);
}

// -------------------------------------
// Helpers
// -------------------------------------
function getLockfileName() {
    const arg = process.argv.find(a => a.startsWith("--lockfile="));
    return arg ? arg.split("=")[1].trim() : null;
}

// Normalize package names so:
// @scope/name == scope/name
function normalizeName(n) {
    return n.replace(/^@/, "");
}

// Extract package@version from PNPM top-level keys
function extractNameAndVersion(key) {
    const lastAt = key.lastIndexOf("@");
    if (lastAt <= 0) return null;

    const name = key.slice(0, lastAt);
    const version = key.slice(lastAt + 1);

    if (!/^\d+\.\d+\.\d+/.test(version)) return null;

    return { name, version };
}

// -------------------------------------
// MAIN
// -------------------------------------
async function checkLockfile() {
    const lockfileName = getLockfileName();
    if (!lockfileName) {
        console.error("❌ Error: Use --lockfile=<filename>");
        console.error(`Example: npx check-my-node-project --lockfile=${SUPPORTED_LOCKFILE}`);
        process.exit(1);
    }

    if (lockfileName !== SUPPORTED_LOCKFILE) {
        console.error(`❌ Only '${SUPPORTED_LOCKFILE}' is supported right now.`);
        process.exit(1);
    }

    const lockfilePath = resolve(process.cwd(), lockfileName);

    if (!existsSync(lockfilePath)) {
        console.error(`❌ Lockfile '${lockfileName}' not found.`);
        process.exit(1);
    }

    // ---------------------------
    // Malicious list file selection
    // ---------------------------
    const maliciousPath = FLAGS.maliciousFile
        ? resolve(process.cwd(), FLAGS.maliciousFile)
        : defaultListPath;

    if (!existsSync(maliciousPath)) {
        console.error(`❌ Malicious list file not found: ${maliciousPath}`);
        process.exit(1);
    }

    // Load malicious list
    const targets = readFileSync(maliciousPath, "utf8")
        .split("\n")
        .map(l => l.trim())
        .filter(Boolean)
        .map(line => {
            const m = line.match(/^(@?[\w\-/]+)\s+\((v?[\d\.]+)\)$/);
            if (!m) return null;
            return {
                name: normalizeName(m[1]),
                version: m[2].replace(/^v/, "")
            };
        })
        .filter(Boolean);

    log(`🔍 Scanning '${lockfileName}' with ${targets.length} malicious package entries...`);
    log(`📄 Using malicious list: ${maliciousPath}\n`);

    // Read lockfile once (for both YAML and regex scanning)
    let lockfileRaw;
    try {
        lockfileRaw = readFileSync(lockfilePath, "utf8");
    } catch (err) {
        console.error("❌ Error reading lockfile.");
        process.exit(1);
    }

    let lockfile;
    try {
        lockfile = parse(lockfileRaw);
    } catch (err) {
        console.error("❌ Error parsing lockfile YAML.");
        process.exit(1);
    }

    const packages = lockfile.packages || {};
    const results = [];

    // -------------------------------------
    // Scan top-level installed packages
    // -------------------------------------
    for (const pkgPath in packages) {
        const info = extractNameAndVersion(pkgPath);
        if (!info) continue;

        const name = normalizeName(info.name);
        const version = info.version;
        const pkgInfo = packages[pkgPath] || {};
        const env = pkgInfo.dev === true ? "dev" : "prod";

        const target = targets.find(t => t.name === name);
        if (!target) continue;

        const status = version === target.version ? "danger" : "safe";
        const severity =
            status === "danger"
                ? (env === "dev" ? "medium" : "high")
                : "info";

        results.push({
            name,
            version,
            status,
            nested: false,
            env,
            safeVersion: status === "safe" ? target.version : undefined,
            severity
        });
    }

    // -------------------------------------
    // Scan nested PNPM inline deps: (pkg@1.2.3)
    // -------------------------------------
    const nestedRegex = /\((@?[\w\-/]+)@(\d+\.\d+\.\d+)\)/g;

    let match;
    while ((match = nestedRegex.exec(lockfileRaw)) !== null) {
        const name = normalizeName(match[1]);
        const version = match[2];

        const target = targets.find(t => t.name === name);
        if (!target) continue;

        const exists = results.some(r => r.name === name && r.version === version);
        if (exists) continue;

        const env = "unknown";
        const status = version === target.version ? "danger" : "safe";
        const severity = status === "danger" ? "high" : "info";

        results.push({
            name,
            version,
            status,
            nested: true,
            env,
            safeVersion: status === "safe" ? target.version : undefined,
            severity
        });
    }

    const anyMatch = results.length > 0;

    // Counters
    let dangerProd = 0;
    let dangerDev = 0;
    let safeProd = 0;
    let safeDev = 0;

    for (const r of results) {
        const isDev = r.env === "dev";
        if (r.status === "danger") {
            if (isDev) dangerDev++;
            else dangerProd++;
        } else {
            if (isDev) safeDev++;
            else safeProd++;
        }
    }

    // Decide exit code
    let exitCode = 0;

    if (FLAGS.failOnSafe && anyMatch) {
        exitCode = 1;
    } else if (FLAGS.strict && (dangerProd > 0 || dangerDev > 0)) {
        exitCode = 1;
    } else {
        if (FLAGS.includeDev) {
            if (dangerProd > 0) exitCode = 1;
        } else {
            if (dangerProd > 0 || dangerDev > 0) exitCode = 1;
        }
    }

    // JSON mode output
    if (FLAGS.json) {
        const jsonOut = {
            lockfile: lockfileName,
            maliciousEntries: targets.length,
            maliciousList: maliciousPath,
            matches: results,
            summary: {
                totalMatches: results.length,
                dangerProd,
                dangerDev,
                safeProd,
                safeDev
            },
            flags: FLAGS,
            exitCode
        };
        console.log(JSON.stringify(jsonOut, null, 2));
        process.exit(exitCode);
    }

    // No matches
    if (!anyMatch) {
        log("✅ None of the malicious packages are installed.\n");
        process.exit(0);
    }

    // -------------------------------------
    // Human-readable output
    // -------------------------------------
    log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    log("📦 Scan results:");
    log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    for (const r of results) {
        const nestedTag = r.nested ? " (nested)" : "";
        const envTag =
            r.env === "dev"
                ? " [dev]"
                : r.env === "prod"
                    ? " [prod]"
                    : " [env?]";

        if (r.status === "danger") {
            log(`\x1b[31m❌ ${r.name}@${r.version}${nestedTag}${envTag} — Malicious version INSTALLED!\x1b[0m`);
        } else {
            log(`\x1b[32m✔ ${r.name}@${r.version}${nestedTag}${envTag} — Safe (malicious version is ${r.safeVersion})\x1b[0m`);
        }
    }

    log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    log("📊 Summary:");
    log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    log(`\x1b[31mProd/unknown dangerous: ${dangerProd}\x1b[0m`);
    log(`\x1b[33mDev dangerous: ${dangerDev}\x1b[0m`);
    log(`\x1b[32mProd/unknown safe: ${safeProd}\x1b[0m`);
    log(`\x1b[32mDev safe: ${safeDev}\x1b[0m`);

    log("\nFlags:", FLAGS);
    log(`Malicious list used: ${maliciousPath}`);

    if (exitCode !== 0) log(`\n❌ One or more conditions triggered a failure (exit code ${exitCode}).\n`);
    else log("\n✅ No dangerous versions installed under the chosen rules.\n");

    process.exit(exitCode);
}

checkLockfile();
