```md
# check-my-node-project

A powerful security scanner for `pnpm-lock.yaml`.  
It detects malicious packages **anywhere** in the lockfile — including deeply nested PNPM inline deps such as:

```

(pkg@1.2.3)
(parent(dep@4.5.6)(other@7.8.9))

```

It also supports a **custom malicious list file** passed by users.

---

# ✨ Features

- Detects malicious packages:
  - Top-level `packages:` section
  - Nested inline PNPM deps inside parentheses
  - Dev/prod environments
  - Scoped or unscoped names (`@scope/name` ↔ `scope/name`)
- Custom malicious list supported (user-provided `.txt` file)
- Advanced flags:
  - `--json`
  - `--silent`
  - `--fail-on-safe`
  - `--include-dev`
  - `--strict`
  - `--malicious=<file.txt>` ← **NEW**
- Severity scoring + clean terminal output

---

# 📦 Installation

```

npm install -g check-my-node-project

```

or run directly:

```

npx check-my-node-project --lockfile=pnpm-lock.yaml

```

---

# 📁 Required Files

### 1. Lockfile  
`pnpm-lock.yaml` must exist, or you must point to it:

```

--lockfile=path/to/pnpm-lock.yaml

```

### 2. Malicious list  
By default the tool uses the built-in `malicious_list.txt`, but you can override it:

```

--malicious=my-list.txt

```

---

# 🔥 Custom Malicious List Support

### Pass a custom `.txt` file:

```

npx check-my-node-project --lockfile=pnpm-lock.yaml --malicious=my-custom-threats.txt

```

### Format of the file:

```

@scope/package (v1.2.3)
package-name (v4.5.6)
somepkg (3.2.1)

```

Both `v1.2.3` and `1.2.3` are accepted.

### Notes:
- The tool normalizes names:
  - `@scope/pkg` matches nested `(scope/pkg@1.2.3)`
- Multiple entries allowed
- Blank lines ignored
- Duplicates removed automatically

---

# 🚀 Usage

### Basic scan

```

npx check-my-node-project --lockfile=pnpm-lock.yaml

```

### Scan with external malicious list

```

npx check-my-node-project --lockfile=pnpm-lock.yaml --malicious=bad-packages.txt

```

---

# 🏷 CLI Flags

### `--malicious=<file.txt>`
Use a custom threats list instead of the bundled one.

```

--malicious=my-threats.txt

```

---

### `--json`
Output machine-readable JSON.

### `--silent`
Suppress human logs (JSON still prints if `--json` is active).

### `--fail-on-safe`
Even safe versions of malicious packages cause exit code `1`.

### `--include-dev`
Dev-only malicious packages do **not** cause failure.

### `--strict`
Any dangerous package (dev or prod) causes failure.

---

# 🔍 Detection Rules

### ✔ Safe match  
Package exists, but version is *not* the malicious one:

```

✔ lodash@4.17.21 — Safe (malicious version is 4.17.20)

```

### ❌ Dangerous match  
Exact malicious version installed:

```

❌ better-sqlite3@12.4.1 — Malicious version INSTALLED!

```

### 🌀 Nested match  
Detected inside PNPM's nested dependency graph:

```

❌ accordproject/concerto-types@3.24.1 (nested)

```

---

# 📊 Exit Codes

| Flag mode | What causes failure |
|----------|----------------------|
| **Default** | Any dangerous pkg |
| **--include-dev** | Only prod-dangerous pkgs |
| **--strict** | Any dangerous pkg (prod or dev) |
| **--fail-on-safe** | ANY appearance of a malicious package |
| **--json** | Output only, exit code follows the above rules |

---

# 🔧 Examples

### Normal scan

```

npx check-my-node-project --lockfile=pnpm-lock.yaml

```

### Strict scan for CI

```

npx check-my-node-project --lockfile=pnpm-lock.yaml --strict

```

### Treat dev deps as harmless

```

npx check-my-node-project --lockfile=pnpm-lock.yaml --include-dev

```

### Fail even on safe versions

```

npx check-my-node-project --lockfile=pnpm-lock.yaml --fail-on-safe

```

### Use a custom malicious list

```

npx check-my-node-project --lockfile=pnpm-lock.yaml --malicious=custom.txt

```

### JSON + silent (script-friendly)

```

npx check-my-node-project --lockfile=pnpm-lock.yaml --json --silent

```

---

# 🙌 Summary

This tool is designed to thoroughly scan PNPM projects for **known malicious packages**, even if they appear in obscure or deeply nested dependency structures.

You can now:

- Provide your own `.txt` list  
- Control strictness levels  
- Differentiate dev/prod  
- Use JSON or silent mode  
- Fail builds the exact way you want  

Ready to plug into any workflow or local audit.
```
