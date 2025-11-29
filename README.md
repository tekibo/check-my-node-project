# check-my-node-project

A powerful security scanner for PNPM lockfiles.  
It detects malicious packages **anywhere** in a `pnpm-lock.yaml`, including deeply nested PNPM inline dependencies such as:

```
(pkgA@1.2.3)
(parent(dep@4.5.6)(other@7.8.9))
```

It now supports **positional lockfile paths** and **custom malicious list files**.

---

# ✨ Key Features

- Scans:
  - Standard top-level `packages:` entries
  - Inline PNPM nested deps like `(better-sqlite3@12.4.1)`
- Matches scoped & unscoped names:
  - `@scope/name` ⇔ `scope/name`
- Supports:
  - Passing a custom malicious list via `--malicious=file.txt`
  - Passing lockfile path as a **positional argument**
  - Dev/Prod separation
- Strict security modes (`--strict`, `--fail-on-safe`)
- JSON mode (`--json`)
- Clean terminal output

---

# 📦 Installation

```bash
npm install -g check-my-node-project
```

or use via `npx`:

```bash
npx check-my-node-project
```

---

# 📁 How the Tool Finds the Lockfile

### ✔ Default behavior
If you run:

```bash
npx check-my-node-project
```

It automatically looks for:

```
./pnpm-lock.yaml
```

in the current directory.

---

### ✔ Provide a custom lockfile path
You can provide a lockfile path as a **positional argument**:

```bash
npx check-my-node-project ./frontend/pnpm-lock.yaml
npx check-my-node-project ../project/pnpm-lock.yaml
```

### ✔ Provide a directory
If you pass a directory, it will automatically look for:

```
<that-directory>/pnpm-lock.yaml
```

Example:

```bash
npx check-my-node-project ./frontend
```

---

# 🔥 Malicious List File Support

### Default list  
If you do nothing, the tool uses its internal built-in file:

```
malicious_list.txt
```

(This is bundled inside the package.)

---

### Provide your own list  
Users can supply their own `.txt` file:

```bash
npx check-my-node-project ./pnpm-lock.yaml --malicious=my-bad-packages.txt
```

### File format

```
package-name (v1.2.3)
@scope/name (v4.5.6)
anotherpkg (3.2.1)
```

Accepts both:

- `v1.2.3`
- `1.2.3`

Blank lines are ignored.

---

# 🚀 Usage Examples

### Basic scan (default lockfile)
```bash
npx check-my-node-project
```

### Scan a specific lockfile
```bash
npx check-my-node-project ./path/to/pnpm-lock.yaml
```

### Scan a folder containing a lockfile
```bash
npx check-my-node-project ./frontend
```

### Use a custom malicious list
```bash
npx check-my-node-project ./pnpm-lock.yaml --malicious=custom-list.txt
```

---

# 🏷 CLI Flags

### `--malicious=<file.txt>`
Use a user-provided malicious list.

```
--malicious=my-bad.txt
```

---

### `--json`
Output machine-readable JSON only.

### `--silent`
Suppress all human logs (JSON still prints if `--json` is used).

### `--fail-on-safe`
Even safe versions of malicious packages cause exit code `1`.

### `--include-dev`
Dev-only malicious packages do **not** cause failure.

### `--strict`
Any dangerous package (prod or dev) will cause failure.

---

# 🔍 Detection Logic

### ✔ Safe version
Package exists, but version does NOT match the malicious version:

```
✔ lodash@4.17.21 — Safe (malicious version is 4.17.20)
```

### ❌ Dangerous version
Exact malicious version discovered:

```
❌ better-sqlite3@12.4.1 — Malicious version INSTALLED!
```

### 🌀 Nested inline deps
Anything like this gets scanned too:

```
(accprdproject/concerto-types@3.24.1)
(parent(depth@1.0.0)(better-sqlite3@12.4.1))
```

---

# 📊 Exit Codes

The exit code depends on flags:

| Flag mode | Fails when… |
|----------|--------------|
| **Default** | Any *dangerous* package |
| **--include-dev** | Only *prod/unknown* dangerous packages |
| **--strict** | Any dangerous package (prod or dev) |
| **--fail-on-safe** | ANY match at all (safe or dangerous) |
| **--json** | Follows above rules, prints JSON |

---

# 🔧 JSON Example

```bash
npx check-my-node-project --json
```

Example output:

```json
{
  "lockfile": "./pnpm-lock.yaml",
  "maliciousList": "./malicious_list.txt",
  "matches": [
    {
      "name": "better-sqlite3",
      "version": "12.4.1",
      "status": "danger",
      "nested": true,
      "env": "unknown"
    }
  ],
  "summary": {
    "dangerProd": 1,
    "dangerDev": 0
  },
  "flags": {
    "json": true,
    "silent": false,
    "failOnSafe": false,
    "includeDev": false,
    "strict": false
  },
  "exitCode": 1
}
```

---

# 🙌 Summary

`check-my-node-project` is a hardened PNPM lockfile scanner with:

* Full nested dependency analysis
* Custom malicious list support
* Automatic lockfile discovery
* Strict + flexible validation modes
* JSON output for tooling
* Scoped name normalization
* Simple, intuitive UX

It’s built to ensure **no malicious package — anywhere in your graph — escapes detection**.

Enjoy a cleaner, safer supply chain.
