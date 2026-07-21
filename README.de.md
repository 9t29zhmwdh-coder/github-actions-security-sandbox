<div align="center">
  <img src="RayStudio.png" alt="RayStudio Logo" width="120"/>
  <h1>GitHub Actions Security Sandbox Simulator</h1>
</div>

[🇬🇧 English Version](README.md)

**Statische Analyse und Angriffssimulation für GitHub Actions Workflows. Erkennt Injection-Vektoren, Supply-Chain-Risiken, überprivilegierte Berechtigungen und Secret-Exposition. Generiert priorisierte Findings mit konkreten Behebungshinweisen.**

Ausgerichtet an den [Microsoft Security DevOps](https://learn.microsoft.com/de-de/azure/defender-for-cloud/azure-devops-extension) Grundsätzen. Der SARIF 2.1.0-Output integriert sich nativ in [GitHub Advanced Security (GHAS)](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) für Enterprise Security Workflows.

[![CI](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox/actions) [![CodeQL](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox/security/code-scanning) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/9t29zhmwdh-coder/github-actions-security-sandbox/badge)](https://securityscorecards.dev/viewer/?uri=github.com/9t29zhmwdh-coder/github-actions-security-sandbox) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13706/badge)](https://www.bestpractices.dev/projects/13706)

![Platform](https://img.shields.io/badge/Platform-Windows_%7C_Ubuntu-lightgrey) ![Rust](https://img.shields.io/badge/Rust-CE422B?logo=rust&logoColor=white) ![AI | Claude Code](https://img.shields.io/badge/AI-Claude_Code-black?logo=anthropic&logoColor=white) ![AI | Copilot](https://img.shields.io/badge/AI-Copilot-black?logo=github&logoColor=white) [![Release](https://img.shields.io/github/v/release/9t29zhmwdh-coder/github-actions-security-sandbox?color=3F8E7E)](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox/releases) [![License](https://img.shields.io/github/license/9t29zhmwdh-coder/github-actions-security-sandbox?color=lightgrey)](LICENSE)

> **So läuft das:** Das ist ein Kommandozeilen-Tool, keine Desktop-App und kein Server. `ghass scan` läuft einmal gegen lokale YAML-Dateien und beendet sich; es gibt keinen Installer und keinen Hintergrundprozess. Es kontaktiert nie GitHub und führt keinen der gescannten Workflows aus, es liest nur die YAML.

![github-actions-security-sandbox](docs/screenshot.png)

---

> 🌱 Neu hier? → [Schritt-für-Schritt-Anleitung für Einsteiger](GETTING_STARTED.md)

---

**In der Praxis:** Zeig auf deinen `.github/workflows`-Ordner und bekomm eine priorisierte Tabelle echter, ausnutzbarer Fehlkonfigurationen (Script-Injection, Pwn Requests, ungepinnte Actions, Secret-Exposition) direkt im Terminal, oder als SARIF-Export für GitHub Advanced Security.

## Erkannte Angriffsvektoren

| Angriffsvektor | Schweregrad | CWE |
|---|---|---|
| Script-Injection via nicht vertrauenswürdige Context-Expressions | Critical | CWE-78 |
| Pwn Request (pull_request_target + PR-Head-Checkout) | Critical | CWE-913 |
| Überprivilegierte Berechtigungen (write-all, contents: write) | High | CWE-250 |
| Secrets an Drittanbieter-Actions weitergegeben | High | CWE-522 |
| Nicht-gepinnte Actions (veränderlicher Branch-Verweis) | High | CWE-829 |
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

# Nur High und höher anzeigen
./target/release/ghass scan .github/workflows --min-severity high

# Scan mit zusätzlicher organisationsspezifischer Regel-Policy
./target/release/ghass scan .github/workflows --rules examples/custom-rules.yml
```

---

## Eigene Regeln (Custom Rules)

Neben den eingebauten Analysern kann `ghass` eigene Policy-Regeln aus einer YAML-Datei auswerten, übergeben via `--rules`. Jede Regel matcht automatisch auf Step-, Job- oder Workflow-Ebene, abgeleitet davon, welche Bedingung sie verwendet:

```yaml
rules:
  - id: no-docker-actions
    title: "Docker-basierte Actions sind per Policy nicht erlaubt"
    severity: Medium
    description: "Die Organisationsrichtlinie verbietet uses: docker://... Steps."
    remediation: "Durch eine gepinnte Composite- oder JavaScript-Action ersetzen."
    match:
      uses_matches: "^docker://"

  - id: no-writeall-on-self-hosted
    title: "write-all-Berechtigung auf einem Self-Hosted Runner"
    severity: Critical
    match:
      all:
        - runs_on_contains: "self-hosted"
        - job_write_all
```

Verfügbare Bedingungen: `uses_matches` (Regex gegen `uses` eines Steps), `run_contains`, `env_key_contains` (Step-Ebene), `runs_on_contains`, `job_write_all` (Job-Ebene), `trigger_equals`, `workflow_write_all` (Workflow-Ebene), sowie `all`, `any` und `not` zum Kombinieren. Treffer aus Custom Rules erscheinen in jedem Ausgabeformat neben den eingebauten Findings, markiert mit `Custom Rule: <id>`. Ein vollständiges Beispiel steht in `examples/custom-rules.yml`.

---

## Deinstallation / Datenbereinigung

Lösche das `target/` Build-Verzeichnis und exportierte Report-Dateien (`report.md`, `results.sarif` usw.). Das Tool schreibt sonst nirgendwo hin, es liest nur Workflow-YAML-Dateien.

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
| Critical | Unmittelbares Risiko zur Code-Ausführung oder vollständiger Secret-Exposition. Vor dem Merge beheben. |
| High | Erhebliches Risiko, das mit moderatem Aufwand ausgenutzt werden kann. |
| Medium | Erfordert spezifische Bedingungen zur Ausnutzung; im nächsten Sprint beheben. |
| Low | Defense-in-depth-Verbesserung mit begrenzter direkter Auswirkung. |
| Informational | Korrektes Nutzungsmuster; zur Vollständigkeit prüfen. |

---

## Architektur

Das Tool ist als Rust-Workspace mit drei Crates aufgebaut:

| Crate | Aufgabe |
|---|---|
| `ghass-core` | Datenmodelle, Finding-Typen, Report-Serialisierung (JSON, Markdown, HTML, SARIF) |
| `ghass-scan` | YAML-Workflow-Parser, alle Security-Analyzer |
| `ghass-cli` | CLI-Binär (`ghass`), Ausgabe-Formatierung, Schweregrad-Filter |

---

## GitHub-Action-Integration

Kopiere `.github/workflows/ghass-check-template.yml` aus diesem Repository in dein eigenes Projekt, um Workflows automatisch bei jedem Push und wöchentlich nach Zeitplan zu scannen. Die Findings werden als SARIF-Ergebnisse an GitHub Advanced Security übermittelt.

Siehe [docs/attack_vectors.md](docs/attack_vectors.md) für Hardening-Muster zu jedem Finding-Typ.

---

## Keine Credentials erforderlich

Dieses Tool führt ausschliesslich lokale statische Analyse durch. Es liest YAML-Dateien von der Festplatte. Es werden keine API-Credentials benötigt oder verwendet.

---

**Autor:** [Rafael Yilmaz](https://github.com/9t29zhmwdh-coder) · **Status:** Active · ![version](https://img.shields.io/github/v/release/9t29zhmwdh-coder/github-actions-security-sandbox?color=6b7280&style=flat-square) · **Lizenz:** MIT
