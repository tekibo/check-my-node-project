# check-my-node-project

A self-contained command-line interface (CLI) tool designed to scan Node.js lockfiles for known supply chain vulnerabilities by checking against an internally maintained list of malicious packages and versions.

> **Note:** Currently supports only **PNPM lockfiles (`pnpm-lock.yaml`)**.  
> Future updates will add support for `package-lock.json` (npm) and `yarn.lock`.

---

## 📦 Installation

Install globally:

```sh
npm install -g check-my-node-project
```

Or run without installing (recommended):

```sh
npx check-my-node-project --lockfile=pnpm-lock.yaml
```

---

## 🚀 Usage

Run this from the **root directory** of your Node project.  
You must specify the lockfile using the `--lockfile` argument.

### PNPM Audit Example

```sh
npx check-my-node-project --lockfile=pnpm-lock.yaml
```

---

## ✅ Expected Output

### Clean Scan

```
🔍 Scanning 'pnpm-lock.yaml' for 15 malicious packages...

✅ No matching compromised package versions found in pnpm-lock.yaml.
```

### ⚠️ Found Vulnerability

```
🔍 Scanning 'pnpm-lock.yaml' for 15 malicious packages...

⚠️  POTENTIAL COMPROMISED PACKAGES FOUND ⚠️
---------------------------------------------
ALARM: Found some-malicious-package@1.0.5 in pnpm-lock.yaml
---------------------------------------------
Total found: 1
```

---

## 🛠️ How It Works

1. CLI runs using the `--lockfile` argument.
2. Validates the file name (currently must be `pnpm-lock.yaml`).
3. Reads the internal `malicious_list.txt` file bundled in the npm module.
4. Parses the user’s lockfile from the current working directory.
5. Compares every package + version entry against the malicious list.
6. Reports exact matches and exits with code **1** if any are found.

---

## 📝 Malicious List Format

The internal `malicious_list.txt` must follow this structure:

```
compromised-package (1.2.3)
@scope/another-bad-pkg (v4.0.0)
```

Package name followed by exact version inside parentheses.

---
