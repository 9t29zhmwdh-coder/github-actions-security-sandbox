# Getting Started

This guide walks you through getting the **GitHub Actions Security Sandbox Simulator** (`ghass`) running on your machine, step by step, assuming zero prior experience with Rust or the command line.

The tool is a command-line program only: there is no installer, no desktop app, and it never contacts GitHub or the internet. It just reads YAML workflow files from your disk and prints a report.

Pick the section for your operating system below.

---

## Windows

### 1. Open a terminal

Right-click the **Start** button and choose **Terminal** (or **Windows PowerShell** on older versions of Windows).

### 2. Check if Rust is already installed

Type the following and press Enter:

```powershell
rustc --version
cargo --version
```

If you see version numbers (e.g. `rustc 1.79.0`), skip to step 4.

If instead you see something like `'rustc' is not recognized as an internal or external command`, Rust is either not installed or not available on your system PATH.

### 3. Install Rust

Go to [https://rustup.rs](https://rustup.rs) and download **rustup-init.exe**. Run it and accept the default options in the installer. When it finishes, **close your terminal window completely and open a new one** (this refreshes the PATH so the `cargo` and `rustc` commands are found). Repeat step 2 to confirm the install worked.

### 4. Get the code

You do not need to know Git to do this:

1. Go to the repository page: [https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox)
2. Click the green **Code** button, then **Download ZIP**.
3. Extract the ZIP file somewhere you can find it, e.g. `C:\Tools\github-actions-security-sandbox`.

<!-- TODO: Screenshot of the green "Code" → "Download ZIP" button -->

If you do have Git installed and prefer it, you can instead run:

```powershell
git clone https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox.git
```

### 5. Build the tool

Open a terminal **inside the extracted/cloned folder** (e.g. type `cd C:\Tools\github-actions-security-sandbox`), then run:

```powershell
cargo build --release
```

This downloads the required dependencies and compiles the tool. It can take a few minutes the first time.

### 6. Run it

Try it out immediately on the bundled example workflow: no GitHub account, token, or network access required:

```powershell
.\target\release\ghass.exe scan examples\vulnerable_workflow.yml
```

You should see a table of security findings printed directly in your terminal (things like script injection risks or unpinned actions), each with a severity and a short description.

To scan your own project's workflows instead:

```powershell
.\target\release\ghass.exe scan .github\workflows
```

### Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `'cargo' is not recognized...` even after installing Rust | Terminal was opened before Rust finished installing, so PATH wasn't refreshed | Close the terminal window fully and open a new one |
| `cargo build --release` fails with linker errors (e.g. `link.exe not found`) | Missing C++ Build Tools, which Rust needs on Windows to link the final executable | Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (select "Desktop development with C++" during install), then retry |
| Build seems to hang or fails while downloading dependencies | Corporate proxy or firewall blocking access to crates.io | Configure your proxy for Cargo, or try from a network without proxy restrictions |
| `ghass.exe` not found when running | You are not inside the project folder, or the build didn't finish successfully | Confirm `cargo build --release` completed with no errors, and check you're running the command from the folder that contains `target\release\` |

---

## Linux

### 1. Open a terminal

This depends on your desktop environment. Most distributions let you search for "Terminal" in the application menu (e.g. press the Super/Windows key and type `terminal`). Common terminal apps include GNOME Terminal, Konsole, and xterm.

### 2. Check if Rust is already installed

```bash
rustc --version
cargo --version
```

If you see version numbers, skip to step 4. If you see `command not found`, Rust is not installed.

### 3. Install Rust

Go to [https://rustup.rs](https://rustup.rs): it shows a one-line command to run. It looks like this:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen prompts (the default installation option is fine). Once it finishes, either restart your terminal or run the command it suggests (usually `source "$HOME/.cargo/env"`) so `cargo` and `rustc` become available. Repeat step 2 to confirm.

### 4. Get the code

If you're not familiar with Git:

1. Go to [https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox)
2. Click the green **Code** button, then **Download ZIP**.
3. Extract it, e.g. `unzip github-actions-security-sandbox-main.zip`.

If you have Git installed, this is quicker:

```bash
git clone https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox.git
```

### 5. Build the tool

From inside the project folder:

```bash
cd github-actions-security-sandbox
cargo build --release
```

### 6. Run it

Try the bundled example first, no credentials required:

```bash
./target/release/ghass scan examples/vulnerable_workflow.yml
```

This prints a table of security findings for that sample workflow file directly in your terminal.

To scan your own project:

```bash
./target/release/ghass scan .github/workflows
```

### Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `cargo: command not found` even after installing | Shell session wasn't reloaded after install | Close and reopen the terminal, or run `source "$HOME/.cargo/env"` |
| `cargo build --release` fails with a linker error (e.g. `cc: command not found`) | No C compiler/linker installed, which Rust needs on Linux | Install build essentials, e.g. `sudo apt install build-essential` (Debian/Ubuntu) or the equivalent for your distribution |
| Dependency download fails or times out | Network/proxy blocking access to crates.io | Check your network or proxy settings and retry |
| `Permission denied` when running `./target/release/ghass` | Execute bit not set (rare, usually set automatically by cargo) | Run `chmod +x target/release/ghass` |

---

## macOS

### 1. Open a terminal

Press **Cmd+Space** to open Spotlight, type `Terminal`, and press Enter.

### 2. Check if Rust is already installed

```bash
rustc --version
cargo --version
```

If you see version numbers, skip to step 4. If you see `command not found`, Rust is not installed.

### 3. Install Rust

Go to [https://rustup.rs](https://rustup.rs) and run the one-line install command shown there:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Accept the default options. Afterwards, restart your terminal (or run `source "$HOME/.cargo/env"`) and repeat step 2 to confirm.

### 4. Get the code

Without Git:

1. Go to [https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox)
2. Click the green **Code** button, then **Download ZIP**.
3. Double-click the downloaded ZIP file in Finder to extract it.

With Git:

```bash
git clone https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox.git
```

### 5. Build the tool

```bash
cd github-actions-security-sandbox
cargo build --release
```

### 6. Run it

Try the bundled example first, no credentials required:

```bash
./target/release/ghass scan examples/vulnerable_workflow.yml
```

You should see a table of security findings for the sample workflow printed in your terminal.

To scan your own project:

```bash
./target/release/ghass scan .github/workflows
```

### Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `cargo: command not found` even after installing | Terminal session wasn't reloaded after install | Close and reopen Terminal, or run `source "$HOME/.cargo/env"` |
| `cargo build --release` fails with a linker/`clang` error | Missing Xcode Command Line Tools | Run `xcode-select --install` and retry |
| Dependency download fails or times out | Network/proxy blocking access to crates.io | Check your network or proxy settings and retry |
| "cannot be opened because the developer cannot be verified" | Not applicable here: this only affects downloaded pre-built binaries, not something you compile yourself with `cargo build` | N/A, safe to ignore if you built from source |

---

## What the tool actually does

`ghass` performs entirely local static analysis of GitHub Actions workflow YAML files. It never runs the workflows and never contacts GitHub or any other service; it only reads files from disk. When you run a scan, it prints a table of findings (e.g. script injection risks, unpinned actions, excessive permissions, secret exposure), each with a severity level and CWE reference. You can also export results as JSON, Markdown, HTML, or SARIF (for GitHub Advanced Security) using the `--format` flag; see the [README](README.md) for the full list of options.

## Uninstalling

There is nothing to "uninstall" in the traditional sense. Just delete the `target/` folder (the build output) and the project folder itself. The tool never writes files anywhere else on your system.
