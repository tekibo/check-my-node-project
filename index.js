#!/usr/bin/env node
import { existsSync, readFileSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { parse } from 'yaml';
import { fileURLToPath } from 'url';

// Configuration for tool's internal files
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const LIST_FILE = 'malicious_list.txt';
const listPath = join(__dirname, LIST_FILE);

const SUPPORTED_LOCKFILE = 'pnpm-lock.yaml';

/**
 * Get lockfile name from CLI args.
 */
function getLockfileName() {
    const lockfileArg = process.argv.find(arg => arg.startsWith('--lockfile='));
    if (lockfileArg) {
        return lockfileArg.split('=')[1].trim();
    }
    return null;
}

/**
 * Proper PNPM-safe name + version extractor.
 */
function extractNameAndVersion(packagePath) {
    // PNPM paths vary:
    // /foo@1.2.3
    // /@scope/foo@1.2.3
    // /foo/1.2.3
    // /registry.npmjs.org/foo/1.2.3
    // foo@1.2.3

    const match = packagePath.match(/^\/?(.*?)(?:\/|@)(\d+\.\d+\.\d+)/);
    if (!match) return null;

    const raw = match[1];      // everything before the version segment
    const version = match[2];  // extracted version

    const segments = raw.split('/');

    let name;
    if (segments.length >= 2 && segments[0].startsWith('@')) {
        // Scoped package
        name = `${segments[0]}/${segments[1]}`;
    } else {
        // Non-scoped: take last segment as name
        name = segments[segments.length - 1];
    }

    return { name, version };
}

async function checkLockfile() {
    const lockfileName = getLockfileName();
    if (!lockfileName) {
        console.error('❌ Error: Please specify the lockfile using --lockfile=<filename>.');
        console.error(`Example: npx check-my-node-project --lockfile=${SUPPORTED_LOCKFILE}`);
        process.exit(1);
    }

    if (lockfileName !== SUPPORTED_LOCKFILE) {
        console.error(`❌ Error: Only '${SUPPORTED_LOCKFILE}' is supported right now.`);
        console.error(`Use: npx check-my-node-project --lockfile=${SUPPORTED_LOCKFILE}`);
        process.exit(1);
    }

    const lockfilePath = resolve(process.cwd(), lockfileName);

    if (!existsSync(lockfilePath)) {
        console.error(`❌ Error: Lockfile '${lockfileName}' not found in current directory.`);
        process.exit(1);
    }
    if (!existsSync(listPath)) {
        console.error(`❌ Error: Internal '${LIST_FILE}' missing. Reinstall the tool.`);
        process.exit(1);
    }

    // Read malicious list
    const listContent = readFileSync(listPath, 'utf8');
    const targets = listContent
        .split('\n')
        .map(l => l.trim())
        .filter(l => l)
        .map(line => {
            const m = line.match(/^(@?[\w\-\/]+)\s+\((v?[\d\.]+)\)$/);
            if (!m) return null;
            return {
                name: m[1],
                version: m[2].replace(/^v/, '')
            };
        })
        .filter(Boolean);

    console.log(`🔍 Scanning '${lockfileName}' with ${targets.length} packages...\n`);

    // Parse lockfile
    let lockfile;
    try {
        lockfile = parse(readFileSync(lockfilePath, 'utf8'));
    } catch (e) {
        console.error(`❌ Error parsing YAML in ${lockfileName}.`);
        process.exit(1);
    }

    const packages = lockfile.packages || {};
    let foundCount = 0;
    const foundPackages = [];

    // Scan
    for (const pkgPath in packages) {
        const info = extractNameAndVersion(pkgPath);
        if (!info) continue;

        const { name, version } = info;

        for (const target of targets) {
            if (name === target.name && version === target.version) {
                const id = `${name}@${version}`;
                if (!foundPackages.includes(id)) {
                    foundPackages.push(id);
                    foundCount++;
                }
            }
        }
    }

    // Results
    if (foundCount > 0) {
        console.log('⚠️  POTENTIAL COMPROMISED PACKAGES FOUND ⚠️');
        console.log('---------------------------------------------');
        foundPackages.forEach(pkg => console.log(`ALARM: Found ${pkg}`));
        console.log('---------------------------------------------');
        console.log(`Total found: ${foundCount}`);
        process.exit(1);
    } else {
        console.log(`✅ No compromised package versions found in ${lockfileName}.`);
    }
}

checkLockfile();