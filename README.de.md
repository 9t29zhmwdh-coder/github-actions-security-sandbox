<div align="center">
  <img src="RayStudio.png" alt="RayStudio Logo" width="120"/>
  <h1>GitHub Actions Security Sandbox Simulator</h1>
</div>

> 🇬🇧 [English Version](README.md)

**Statische Analyse und Angriffssimulation für GitHub Actions Workflows. Erkennt Injection-Vektoren, Supply-Chain-Risiken, ueberprivilegierte Berechtigungen und Secret-Exposition. Generiert priorisierte Findings mit konkreten Behebungshinweisen.**

Ausgerichtet an den [Microsoft Security DevOps](https://learn.microsoft.com/de-de/azure/defender-for-cloud/azure-devops-extension) Grundsaetzen. Der SARIF 2.1.0-Output integriert sich nativ in [GitHub Advanced Security (GHAS)](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) für Enterprise Security Workflows.

[![CI](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox/actions) ![Platform](https://img.shields.io/badge/Platform-Windows_%7C_Ubuntu-lightgrey) ![Rust](https://img.shields.io/badge/Rust-CE422B?logo=rust&logoColor=white) ![AI | Claude Code](https://img.shields.io/badge/AI-Claude_Code-black?logo=anthropic&logoColor=white) ![AI | Copilot](https://img.shields.io/badge/AI-Copilot-black?logo=github&logoColor=white) [![Release](https://img.shields.io/github/v/release/9t29zhmwdh-coder/github-actions-security-sandbox?color=3F8E7E)](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox/releases) [![License](https://img.shields.io/github/license/9t29zhmwdh-coder/github-actions-security-sandbox?color=lightgrey)](LICENSE)

---

## Erkannte Angriffsvektoren

| Angriffsvektor | Schweregrad | CWE |
|---|---|---|
| Script-Injection via unbegruengte Context-Expressions | Critical | CWE-78 |
| Pwn Request (pull_request_target + PR-Head-Checkout) | Critical | CWE-913 |
| Ueberprivilegierte Berechtigungen (write-all, contents: write) | High | CWE-250 |
| Secrets an Drittanbieter-Actions weitergegeben | High | CWE-522 |
| Nicht-gepinnte Actions (veraenderlicher Branch-Verweis) | High | CWE-829 |
| Nicht-gepinnte Actions (semantischer Versions-Tag) | Medium | CWE-829 |
| Self-Hosted Runner ohne Isolation | Medium | CWE-653 |
| Secret-Werte in Umgebungsvariablen | Informational | CWE-532 |

---

## Schnellstart

```bash
git clone https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox
cd github-actions-security-sandbox
cargo build --release

# Einzelne Workflow-Datei scannen
./target/release/ghass scan examples/vulnerable_workflow.yml

# Alle Workflows in einem Verzeichnis scannen
./target/release/ghass scan .github/workflows

# Findings als Markdown exportieren
./target/release/ghass scan .github/workflows --format md --output report.md

# SARIF für GitHub Advanced Security exportieren
./target/release/ghass scan .github/workflows --format sarif --output results.sarif

# Nur High und hoeher anzeigen
./target/release/ghass scan .github/workflows --min-severity high
```

---

## Ausgabeformate

| Format | Flag | Anwendungsfall |
|---|---|---|
| Tabelle (Standard) | `--format table` | Interaktive Terminal-Auswertung |
| JSON | `--format json` | CI-Pipelines, Ticketsystem-Integration |
| Markdown | `--format md` | PR-Kommentare, Confluence, interne Berichte |
| HTML | `--format html` | Browser-Berichte für Stakeholder |
| SARIF | `--format sarif` | GitHub Advanced Security, Code Scanning |

---

## Severity-Klassifikation

| Schweregrad | Beschreibung |
|---|---|
| Critical | Unmittelbares Risiko zur Code-Ausfuehrung oder vollstaendiger Secret-Exposition. Vor dem Merge beheben. |
| High | Erhebliches Risiko, das mit moderatem Aufwand ausgenutzt werden kann. |
| Medium | Erfordert spezifische Bedingungen zur Ausnutzung; im naechsten Sprint beheben. |
| Low | Defense-in-depth-Verbesserung mit begrenzter direkter Auswirkung. |
| Informational | Korrektes Nutzungsmuster; zur Vollstaendigkeit pruefen. |

---

## Architektur

Das Tool ist als Rust-Workspace mit drei Crates aufgebaut:

| Crate | Aufgabe |
|---|---|
| `ghass-core` | Datenmodelle, Finding-Typen, Report-Serialisierung (JSON, Markdown, HTML, SARIF) |
| `ghass-scan` | YAML-Workflow-Parser, alle Security-Analyzer |
| `ghass-cli` | CLI-Binaer (`ghass`), Ausgabe-Formatierung, Schweregrad-Filter |

---

## Keine Credentials erforderlich

Dieses Tool fuehrt ausschliesslich lokale statische Analyse durch. Es liest YAML-Dateien von der Festplatte. Es werden keine API-Credentials benoetigt oder verwendet.

---

**Autor:** [Rafael Yilmaz](https://github.com/9t29zhmwdh-coder) · **Status:** Active · ![version](https://img.shields.io/github/v/release/9t29zhmwdh-coder/github-actions-security-sandbox?label=\&color=6b7280\&style=flat-square) · **Lizenz:** MIT
