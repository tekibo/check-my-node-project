check-my-node-project

A self-contained command-line interface (CLI) tool designed to scan Node.js lockfiles for known supply chain vulnerabilities by checking against an internally maintained list of malicious packages and versions.

Note: As of the initial release, this tool currently only supports and validates PNPM lockfiles (pnpm-lock.yaml). Future versions are planned to extend support to package-lock.json (npm) and yarn.lock.

📦 Installation

To use the tool globally, install it directly from npm:

npm install -g check-my-node-project


Alternatively, you can run it without a global install using npx (recommended).

🚀 Usage

Run the tool from the root directory of your project where your lockfile resides. You must specify the lockfile name using the --lockfile argument.

PNPM Audit Example

# To check your pnpm lockfile
npx check-my-node-project --lockfile=pnpm-lock.yaml


Expected Output

✅ Clean Scan

If no matching malicious packages are found:

🔍 Scanning 'pnpm-lock.yaml' for 15 malicious packages...

✅ No matching compromised package versions found in pnpm-lock.yaml.


⚠️ Found Vulnerability

If a malicious package is detected, the process will exit with an error code (1) and list the compromised packages:

🔍 Scanning 'pnpm-lock.yaml' for 15 malicious packages...

⚠️  POTENTIAL COMPROMISED PACKAGES FOUND ⚠️
---------------------------------------------
ALARM: Found some-malicious-package@1.0.5 in pnpm-lock.yaml
---------------------------------------------
Total found: 1


🛠️ How it Works

The CLI is executed with the --lockfile argument.

The script validates that the specified file is pnpm-lock.yaml (due to current limitations).

The script reads the malicious_list.txt file, which is packaged directly inside the check-my-node-project npm module.

It reads and parses the lockfile provided by the user (from the current working directory).

It compares every package and version in the lockfile against the internal malicious list.

It reports any exact matches found.

📝 Malicious List Format

The internal malicious_list.txt must follow this specific format for each entry:

# Package names are followed by a version in parenthesis
compromised-package (1.2.3)
@scope/another-bad-pkg (v4.0.0)
