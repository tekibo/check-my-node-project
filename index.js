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

const SUPPORTED_LOCKFILE = 'pnpm-lock.yaml'; // Define the only supported file name

/**
 * Parses command line arguments to find the lockfile path.
 */
function getLockfileName() {
    const lockfileArg = process.argv.find(arg => arg.startsWith('--lockfile='));
    if (lockfileArg) {
        return lockfileArg.split('=')[1].trim();
    }
    return null;
}

async function checkLockfile() {
    
    // Check 1: Get lockfile name from user
    const lockfileName = getLockfileName();
    if (!lockfileName) {
        console.error('❌ Error: Please specify the lockfile using --lockfile=<filename>.');
        console.error(`Example: npx check-my-node-project --lockfile=${SUPPORTED_LOCKFILE}`);
        process.exit(1);
    }

    // 🌟 NEW: Enforce PNPM Lockfile
    if (lockfileName !== SUPPORTED_LOCKFILE) {
        console.error(`❌ Error: Currently, this tool only supports '${SUPPORTED_LOCKFILE}'.`);
        console.error(`Please use the command: npx check-my-node-project --lockfile=${SUPPORTED_LOCKFILE}`);
        console.log('\nFuture updates will include support for other package managers.');
        process.exit(1);
    }
    // 🌟 END NEW VALIDATION

    const lockfilePath = resolve(process.cwd(), lockfileName);
    
    // 2. Check if files exist
    if (!existsSync(lockfilePath)) {
        console.error(`❌ Error: Lockfile '${lockfileName}' not found in the current directory.`);
        process.exit(1);
    }
    if (!existsSync(listPath)) {
        console.error(`❌ Error: Tool's internal '${LIST_FILE}' not found. Check tool installation.`);
        process.exit(1);
    }

    // 3. Read and parse the malicious list (now internal to the tool)
    const listContent = readFileSync(listPath, 'utf8');
    const targets = listContent
        .split('\n')
        .map(line => line.trim())
        .filter(line => line)
        .map(line => {
            const match = line.match(/^(@?[\w\-\/]+)\s+\((v?[\d\.]+)\)$/);
            if (!match) return null;
            return {
                name: match[1],
                version: match[2].replace(/^v/, '')
            };
        })
        .filter(item => item !== null);

    console.log(`🔍 Scanning '${lockfileName}' for ${targets.length} malicious packages...\n`);

    // 4. Read and parse the lockfile
    const lockfileContent = readFileSync(lockfilePath, 'utf8');
    let lockfile;
    try {
        lockfile = parse(lockfileContent);
    } catch (e) {
        console.error(`❌ Error parsing ${lockfileName}. Please ensure it is a valid YAML file.`);
        process.exit(1);
    }

    let foundCount = 0;
    const foundPackages = [];
    
    // --- START OF CORE LOGIC (PNPM SPECIFIC) ---
    // This logic relies on the lockfile being pnpm-lock.yaml
    const packages = lockfile.packages || {};

    for (const packagePath in packages) {
        if (Object.hasOwnProperty.call(packages, packagePath)) {
            // Logic for extracting name and version from pnpm package path
            const parts = packagePath.split('/');
            const name = parts[1].startsWith('@') ? `${parts[1]}/${parts[2]}` : parts[1];
            
            const versionAndHash = parts[parts.length - 1]; 
            const versionMatch = versionAndHash.match(/^([\d\.]+)/);
            const baseVersion = versionMatch ? versionMatch[1] : null;

            if (!baseVersion) continue;

            targets.forEach(target => {
                if (name === target.name && baseVersion === target.version) {
                    const identifier = `${target.name}@${target.version}`;
                    if (!foundPackages.includes(identifier)) {
                        foundCount++;
                        foundPackages.push(identifier);
                    }
                }
            });
        }
    }
    // --- END OF CORE LOGIC ---

    // 5. Output results
    if (foundCount > 0) {
        console.log('⚠️  POTENTIAL COMPROMISED PACKAGES FOUND ⚠️');
        console.log('---------------------------------------------');
        foundPackages.forEach(pkg => console.log(`ALARM: Found ${pkg} in ${lockfileName}`));
        console.log('---------------------------------------------');
        console.log(`Total found: ${foundCount}`);
        process.exit(1);
    } else {
        console.log(`✅ No matching compromised package versions found in ${lockfileName}.`);
    }
}

checkLockfile();