# Walkthrough — SBOM Generator with GUI

## Summary

Enhanced [SBOM_Generator.py](file:///SBOM_Generator.py) with:
1. **Interactive PySide6 GUI** — dark-themed, matching ThreatPilot branding
2. **Direct vs Transitive dependency tracking** — lockfile parsers tag dependencies as "transitive"
3. **Per-ecosystem breakdown table** — shows Direct / Transitive / Total per language

## GUI Features

The GUI launches when running without arguments (`python SBOM_Generator.py`):

| Feature | Description |
|---|---|
| **Source Folder picker** | Browse button → `QFileDialog` to select the project root |
| **Output Path picker** | Browse button → Save-as dialog, auto-fills to `<source>/sbom.spdx.json` |
| **Generate SBOM button** | Runs scan on a worker thread (non-blocking UI) |
| **Stat cards** | Three cards showing Total Components, Direct, and Transitive counts |
| **Ecosystem table** | Sorted by total count, with color-coded Direct (green), Transitive (amber), Total (blue) columns |
| **Scan log** | Monospace log area showing which manifest files were found |

### Dual-mode entry point

```
python SBOM_Generator.py             → GUI mode (PySide6)
python SBOM_Generator.py ./my-repo   → CLI mode (as before)
```

Falls back to CLI mode if PySide6 is not installed.

## Direct vs Transitive Classification

| Scope | Source files | Rationale |
|---|---|---|
| **Direct** | `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.cfg`, `package.json`, `go.mod`, `pom.xml`, `build.gradle`, `*.csproj`, `packages.config`, `conanfile.txt`, `vcpkg.json`, `Cargo.toml`, `Gemfile`, `composer.json`, `Package.swift`, `pubspec.yaml`, `mix.exs`, `*.cabal`, `stack.yaml`, `build.sbt` | Manifest files list what the developer explicitly declared |
| **Transitive** | `package-lock.json`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `Package.resolved`, `pubspec.lock` | Lock files contain the full resolved dependency tree |

## What Changed

- **`_pkg()` helper** — new `scope` parameter (default `"direct"`)
- **7 lockfile parsers** — now pass `scope="transitive"`
- **`scan_repository()`** — new `log_callback` parameter for GUI integration
- **`ECOSYSTEM_NAMES`** — moved to module-level constant (shared by CLI and GUI)
- **`print_summary()`** — now shows Direct/Transitive rows in the CLI table
- **`_launch_gui()`** — full PySide6 GUI with `ScanWorker` thread and `SBOMGeneratorWindow`
- **`__main__`** — CLI if args provided, else GUI

## How to Run

```powershell
# GUI mode
python SBOM_Generator.py

# CLI mode
python SBOM_Generator.py "F:\some-project"
```
