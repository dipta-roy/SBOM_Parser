"""
Universal SBOM Generator — Multi-Language Support

Generates an SPDX 2.3 JSON SBOM by scanning a repository for dependency
manifests across all major language ecosystems.

Supported ecosystems and manifest files:
  Python     : requirements.txt, Pipfile, pyproject.toml, setup.cfg
  Node/npm   : package.json, package-lock.json
  Go         : go.mod, go.sum
  Java/Kotlin: pom.xml, build.gradle, build.gradle.kts
  .NET / C#  : *.csproj, packages.config, Directory.Packages.props
  C / C++    : conanfile.txt, vcpkg.json
  Rust       : Cargo.toml, Cargo.lock
  Ruby       : Gemfile, Gemfile.lock
  PHP        : composer.json, composer.lock
  Swift      : Package.swift, Package.resolved
  Dart/Flutter: pubspec.yaml, pubspec.lock
  Elixir     : mix.exs
  Haskell    : *.cabal, stack.yaml
  Scala      : build.sbt

Usage:
  python generate_sbom.py [path_to_repository]   # CLI mode
  python generate_sbom.py                         # GUI mode (requires PySide6)
"""

import os
import json
import uuid
import datetime
import re
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _pkg(name: str, version: str, pkg_type: str, scope: str = "direct") -> dict:
    """Create a normalised package dict."""
    return {
        "name": name.strip(),
        "version": version.strip() if version else "UNKNOWN",
        "type": pkg_type,
        "scope": scope,
    }


def _clean_version(version: str) -> str:
    """Strip common semver range prefixes (^, ~, >=, etc.)."""
    return re.sub(r'^[~^>=<!\s]+', '', version).split(',')[0].strip()


# ---------------------------------------------------------------------------
# Python Parsers
# ---------------------------------------------------------------------------

def parse_requirements_txt(filepath: str) -> list[dict]:
    """Parse pip requirements.txt files."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # Handle inline comments
                line = line.split('#')[0].strip()
                # Handle extras like package[extra]==1.0
                match = re.match(r'^([a-zA-Z0-9\-_.]+)(?:\[.*?\])?\s*[=><~!]+\s*(.*)$', line)
                if match:
                    packages.append(_pkg(match.group(1), _clean_version(match.group(2)), "pypi"))
                elif re.match(r'^[a-zA-Z0-9\-_.]+(?:\[.*?\])?$', line):
                    name = re.match(r'^([a-zA-Z0-9\-_.]+)', line).group(1)
                    packages.append(_pkg(name, "UNKNOWN", "pypi"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_pipfile(filepath: str) -> list[dict]:
    """Parse Pipfile (TOML-like, but uses tomllib)."""
    packages = []
    try:
        with open(filepath, 'rb') as f:
            data = tomllib.load(f)
        for section in ('packages', 'dev-packages'):
            deps = data.get(section, {})
            for name, spec in deps.items():
                if isinstance(spec, str):
                    version = _clean_version(spec) if spec != "*" else "UNKNOWN"
                elif isinstance(spec, dict):
                    version = _clean_version(spec.get('version', '*'))
                    if version == '*':
                        version = "UNKNOWN"
                else:
                    version = "UNKNOWN"
                packages.append(_pkg(name, version, "pypi"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_pyproject_toml(filepath: str) -> list[dict]:
    """Parse pyproject.toml — handles PEP 621 and Poetry formats."""
    packages = []
    try:
        with open(filepath, 'rb') as f:
            data = tomllib.load(f)

        # PEP 621: [project] dependencies
        project = data.get('project', {})
        for dep_str in project.get('dependencies', []):
            match = re.match(r'^([a-zA-Z0-9\-_.]+)(?:\[.*?\])?\s*([=><~!].+)?$', dep_str)
            if match:
                name = match.group(1)
                version = _clean_version(match.group(2)) if match.group(2) else "UNKNOWN"
                packages.append(_pkg(name, version, "pypi"))

        # PEP 621: [project.optional-dependencies]
        for group_deps in project.get('optional-dependencies', {}).values():
            for dep_str in group_deps:
                match = re.match(r'^([a-zA-Z0-9\-_.]+)(?:\[.*?\])?\s*([=><~!].+)?$', dep_str)
                if match:
                    name = match.group(1)
                    version = _clean_version(match.group(2)) if match.group(2) else "UNKNOWN"
                    packages.append(_pkg(name, version, "pypi"))

        # Poetry: [tool.poetry.dependencies]
        poetry = data.get('tool', {}).get('poetry', {})
        for section in ('dependencies', 'dev-dependencies'):
            for name, spec in poetry.get(section, {}).items():
                if name == 'python':
                    continue
                if isinstance(spec, str):
                    version = _clean_version(spec) if spec != "*" else "UNKNOWN"
                elif isinstance(spec, dict):
                    version = _clean_version(spec.get('version', '*'))
                    if version == '*':
                        version = "UNKNOWN"
                else:
                    version = "UNKNOWN"
                packages.append(_pkg(name, version, "pypi"))

        # Poetry group dependencies: [tool.poetry.group.*.dependencies]
        for group in poetry.get('group', {}).values():
            for name, spec in group.get('dependencies', {}).items():
                if name == 'python':
                    continue
                if isinstance(spec, str):
                    version = _clean_version(spec) if spec != "*" else "UNKNOWN"
                elif isinstance(spec, dict):
                    version = _clean_version(spec.get('version', '*'))
                    if version == '*':
                        version = "UNKNOWN"
                else:
                    version = "UNKNOWN"
                packages.append(_pkg(name, version, "pypi"))

    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_setup_cfg(filepath: str) -> list[dict]:
    """Parse setup.cfg [options] install_requires."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find the install_requires block
        match = re.search(
            r'\[options\]\s*\n(.*?)(?=\n\[|\Z)',
            content, re.DOTALL
        )
        if not match:
            return packages

        options_block = match.group(1)
        # Find install_requires value (multi-line)
        req_match = re.search(
            r'install_requires\s*=\s*\n?((?:[ \t]+[^\n]+\n?)*)',
            options_block
        )
        if req_match:
            for line in req_match.group(1).splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                dep_match = re.match(r'^([a-zA-Z0-9\-_.]+)(?:\[.*?\])?\s*([=><~!].+)?$', line)
                if dep_match:
                    name = dep_match.group(1)
                    version = _clean_version(dep_match.group(2)) if dep_match.group(2) else "UNKNOWN"
                    packages.append(_pkg(name, version, "pypi"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Node / npm Parsers
# ---------------------------------------------------------------------------

def parse_package_json(filepath: str) -> list[dict]:
    """Parse npm package.json."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
            for name, version in data.get(section, {}).items():
                packages.append(_pkg(name, _clean_version(version), "npm"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_package_lock_json(filepath: str) -> list[dict]:
    """Parse npm package-lock.json (v2/v3 format with packages)."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # v2/v3 format: "packages" key with "node_modules/..." entries
        pkgs = data.get('packages', {})
        for path, info in pkgs.items():
            if not path:  # root package
                continue
            name = path.split('node_modules/')[-1]
            version = info.get('version', 'UNKNOWN')
            packages.append(_pkg(name, version, "npm", scope="transitive"))

        # v1 format fallback: "dependencies" key
        if not pkgs:
            def _walk_lock_deps(deps: dict):
                for name, info in deps.items():
                    version = info.get('version', 'UNKNOWN')
                    packages.append(_pkg(name, version, "npm", scope="transitive"))
                    _walk_lock_deps(info.get('dependencies', {}))
            _walk_lock_deps(data.get('dependencies', {}))

    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Go Parsers
# ---------------------------------------------------------------------------

def parse_go_mod(filepath: str) -> list[dict]:
    """Parse go.mod require blocks."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Single-line requires: require github.com/foo/bar v1.2.3
        for m in re.finditer(r'^require\s+(\S+)\s+(v[\d.]+\S*)', content, re.MULTILINE):
            packages.append(_pkg(m.group(1), m.group(2), "golang"))

        # Block requires
        for block in re.finditer(r'require\s*\((.*?)\)', content, re.DOTALL):
            for line in block.group(1).splitlines():
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                # Skip indirect dependencies
                if '// indirect' in line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    packages.append(_pkg(parts[0], parts[1], "golang"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_go_sum(filepath: str) -> list[dict]:
    """Parse go.sum for pinned dependency versions."""
    packages = []
    seen = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].split('/')[0]  # strip /go.mod suffix
                    key = f"{name}@{version}"
                    if key not in seen:
                        seen.add(key)
                        packages.append(_pkg(name, version, "golang", scope="transitive"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Java / Kotlin Parsers
# ---------------------------------------------------------------------------

def parse_pom_xml(filepath: str) -> list[dict]:
    """Parse Maven pom.xml for dependencies."""
    packages = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        # Handle Maven namespace
        ns = ''
        ns_match = re.match(r'\{(.*?)\}', root.tag)
        if ns_match:
            ns = ns_match.group(1)

        def _find(element, tag):
            if ns:
                return element.findall(f'{{{ns}}}{tag}')
            return element.findall(tag)

        def _find_one(element, tag):
            if ns:
                return element.find(f'{{{ns}}}{tag}')
            return element.find(tag)

        # Find all <dependency> elements
        for deps_section in [root] + list(root.iter()):
            if deps_section.tag.endswith('dependencies'):
                for dep in _find(deps_section, 'dependency'):
                    group_id = _find_one(dep, 'groupId')
                    artifact_id = _find_one(dep, 'artifactId')
                    version_el = _find_one(dep, 'version')

                    if artifact_id is not None:
                        gid = group_id.text if group_id is not None else ''
                        aid = artifact_id.text
                        ver = version_el.text if version_el is not None else 'UNKNOWN'
                        # Skip property-placeholder versions like ${project.version}
                        if ver and ver.startswith('${'):
                            ver = 'UNKNOWN'
                        name = f"{gid}:{aid}" if gid else aid
                        packages.append(_pkg(name, ver, "maven"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_build_gradle(filepath: str) -> list[dict]:
    """Parse Gradle build files (build.gradle / build.gradle.kts)."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Groovy DSL:  implementation 'group:artifact:version'
        # Kotlin DSL:  implementation("group:artifact:version")
        patterns = [
            # Quoted strings with configuration keyword
            r'(?:implementation|api|compile|runtime|testImplementation|testCompile|'
            r'classpath|annotationProcessor|kapt|compileOnly|runtimeOnly)\s*'
            r'[(\s]+["\']([^"\']+:[^"\']+:[^"\']+)["\']',
            # Kotlin DSL with parentheses
            r'(?:implementation|api|compile|runtime|testImplementation|testCompile|'
            r'classpath|annotationProcessor|kapt|compileOnly|runtimeOnly)\s*\(\s*'
            r'["\']([^"\']+:[^"\']+:[^"\']+)["\']',
        ]

        seen = set()
        for pattern in patterns:
            for m in re.finditer(pattern, content):
                dep_str = m.group(1)
                parts = dep_str.split(':')
                if len(parts) >= 3:
                    group, artifact, version = parts[0], parts[1], parts[2]
                    key = f"{group}:{artifact}"
                    if key not in seen:
                        seen.add(key)
                        packages.append(_pkg(f"{group}:{artifact}", version, "maven"))
                elif len(parts) == 2:
                    key = dep_str
                    if key not in seen:
                        seen.add(key)
                        packages.append(_pkg(dep_str, "UNKNOWN", "maven"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# .NET / C# Parsers
# ---------------------------------------------------------------------------

def parse_csproj(filepath: str) -> list[dict]:
    """Parse .NET .csproj / .fsproj / .vbproj for <PackageReference> elements."""
    packages = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()

        # .csproj files may or may not have an XML namespace
        for elem in root.iter():
            tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
            if tag == 'PackageReference':
                name = elem.get('Include') or elem.get('include') or ''
                version = elem.get('Version') or elem.get('version') or ''
                if not version:
                    # Version might be a child element
                    for child in elem:
                        child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                        if child_tag == 'Version' and child.text:
                            version = child.text
                            break
                if name:
                    packages.append(_pkg(name, version or "UNKNOWN", "nuget"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_packages_config(filepath: str) -> list[dict]:
    """Parse NuGet packages.config XML."""
    packages = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        for pkg_elem in root.findall('.//package'):
            name = pkg_elem.get('id', '')
            version = pkg_elem.get('version', 'UNKNOWN')
            if name:
                packages.append(_pkg(name, version, "nuget"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_directory_packages_props(filepath: str) -> list[dict]:
    """Parse Directory.Packages.props (central package management)."""
    packages = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        for elem in root.iter():
            tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
            if tag == 'PackageVersion':
                name = elem.get('Include') or elem.get('include') or ''
                version = elem.get('Version') or elem.get('version') or 'UNKNOWN'
                if name:
                    packages.append(_pkg(name, version, "nuget"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# C / C++ Parsers
# ---------------------------------------------------------------------------

def parse_conanfile_txt(filepath: str) -> list[dict]:
    """Parse Conan conanfile.txt [requires] section."""
    packages = []
    try:
        in_requires = False
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('['):
                    in_requires = line.lower() in ('[requires]', '[build_requires]', '[tool_requires]')
                    continue
                if in_requires and line and not line.startswith('#'):
                    # format: name/version or name/version@user/channel
                    match = re.match(r'^([a-zA-Z0-9\-_.]+)/([a-zA-Z0-9\-_.]+)', line)
                    if match:
                        packages.append(_pkg(match.group(1), match.group(2), "conan"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_vcpkg_json(filepath: str) -> list[dict]:
    """Parse vcpkg.json manifest."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for dep in data.get('dependencies', []):
            if isinstance(dep, str):
                packages.append(_pkg(dep, "UNKNOWN", "vcpkg"))
            elif isinstance(dep, dict):
                name = dep.get('name', '')
                version = dep.get('version>=', dep.get('version', 'UNKNOWN'))
                if name:
                    packages.append(_pkg(name, str(version), "vcpkg"))

        # Overrides may have pinned versions
        for override in data.get('overrides', []):
            name = override.get('name', '')
            version = override.get('version', 'UNKNOWN')
            if name:
                packages.append(_pkg(name, str(version), "vcpkg"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Rust Parsers
# ---------------------------------------------------------------------------

def parse_cargo_toml(filepath: str) -> list[dict]:
    """Parse Rust Cargo.toml [dependencies] tables."""
    packages = []
    try:
        with open(filepath, 'rb') as f:
            data = tomllib.load(f)

        for section in ('dependencies', 'dev-dependencies', 'build-dependencies'):
            deps = data.get(section, {})
            for name, spec in deps.items():
                if isinstance(spec, str):
                    packages.append(_pkg(name, _clean_version(spec), "cargo"))
                elif isinstance(spec, dict):
                    version = spec.get('version', 'UNKNOWN')
                    packages.append(_pkg(name, _clean_version(version) if version != 'UNKNOWN' else version, "cargo"))

        # Workspace dependencies: [workspace.dependencies]
        workspace_deps = data.get('workspace', {}).get('dependencies', {})
        for name, spec in workspace_deps.items():
            if isinstance(spec, str):
                packages.append(_pkg(name, _clean_version(spec), "cargo"))
            elif isinstance(spec, dict):
                version = spec.get('version', 'UNKNOWN')
                packages.append(_pkg(name, _clean_version(version) if version != 'UNKNOWN' else version, "cargo"))

    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_cargo_lock(filepath: str) -> list[dict]:
    """Parse Rust Cargo.lock for pinned versions."""
    packages = []
    try:
        with open(filepath, 'rb') as f:
            data = tomllib.load(f)

        for pkg_entry in data.get('package', []):
            name = pkg_entry.get('name', '')
            version = pkg_entry.get('version', 'UNKNOWN')
            if name:
                packages.append(_pkg(name, version, "cargo", scope="transitive"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Ruby Parsers
# ---------------------------------------------------------------------------

def parse_gemfile(filepath: str) -> list[dict]:
    """Parse Ruby Gemfile."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # gem 'name', '~> 1.2.3'  or  gem "name", ">= 2.0"
                match = re.match(
                    r'''gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?''',
                    line
                )
                if match:
                    name = match.group(1)
                    version = _clean_version(match.group(2)) if match.group(2) else "UNKNOWN"
                    packages.append(_pkg(name, version, "gem"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_gemfile_lock(filepath: str) -> list[dict]:
    """Parse Ruby Gemfile.lock for resolved versions."""
    packages = []
    try:
        in_specs = False
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                # Look for the "specs:" section under GEM
                if stripped == 'specs:':
                    in_specs = True
                    continue
                if in_specs:
                    # Packages are indented with 4 spaces, sub-dependencies with 6+
                    if line.startswith('    ') and not line.startswith('      '):
                        match = re.match(r'\s+(\S+)\s+\((\S+)\)', line)
                        if match:
                            packages.append(_pkg(match.group(1), match.group(2), "gem", scope="transitive"))
                    elif not line.startswith(' '):
                        in_specs = False
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# PHP Parsers
# ---------------------------------------------------------------------------

def parse_composer_json(filepath: str) -> list[dict]:
    """Parse PHP composer.json."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for section in ('require', 'require-dev'):
            for name, version in data.get(section, {}).items():
                # Skip PHP platform requirements
                if name in ('php', 'ext-*') or name.startswith('ext-'):
                    continue
                packages.append(_pkg(name, _clean_version(version), "composer"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_composer_lock(filepath: str) -> list[dict]:
    """Parse PHP composer.lock for resolved versions."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for section in ('packages', 'packages-dev'):
            for pkg_info in data.get(section, []):
                name = pkg_info.get('name', '')
                version = pkg_info.get('version', 'UNKNOWN')
                # Strip leading 'v' from versions like 'v2.3.1'
                if version.startswith('v'):
                    version = version[1:]
                if name:
                    packages.append(_pkg(name, version, "composer", scope="transitive"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Swift Parsers
# ---------------------------------------------------------------------------

def parse_package_swift(filepath: str) -> list[dict]:
    """Parse Swift Package.swift for .package(url:...) declarations."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # .package(url: "https://github.com/user/repo.git", from: "1.0.0")
        # .package(url: "...", .upToNextMajor(from: "2.0.0"))
        # .package(url: "...", exact: "1.2.3")
        for m in re.finditer(
            r'\.package\s*\(\s*url:\s*"([^"]+)".*?(?:from:\s*"([^"]+)"|exact:\s*"([^"]+)"|'
            r'\.upToNextMajor\s*\(\s*from:\s*"([^"]+)"|\.upToNextMinor\s*\(\s*from:\s*"([^"]+)")',
            content, re.DOTALL
        ):
            url = m.group(1)
            version = m.group(2) or m.group(3) or m.group(4) or m.group(5) or "UNKNOWN"
            # Extract package name from URL
            name = url.rstrip('/').split('/')[-1]
            if name.endswith('.git'):
                name = name[:-4]
            packages.append(_pkg(name, version, "swift"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_package_resolved(filepath: str) -> list[dict]:
    """Parse Swift Package.resolved (v2 format)."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # v2 format
        pins = data.get('pins', [])
        # v1 format fallback
        if not pins:
            obj = data.get('object', {})
            pins = obj.get('pins', [])

        for pin in pins:
            name = pin.get('identity', pin.get('package', ''))
            state = pin.get('state', {})
            version = state.get('version') or state.get('revision', 'UNKNOWN')
            if name:
                packages.append(_pkg(name, version or "UNKNOWN", "swift", scope="transitive"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Dart / Flutter Parsers
# ---------------------------------------------------------------------------

def parse_pubspec_yaml(filepath: str) -> list[dict]:
    """Parse Dart/Flutter pubspec.yaml (line-based, no pyyaml dependency)."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        in_deps = False
        indent_level = 0

        for line in lines:
            stripped = line.rstrip()
            if not stripped or stripped.lstrip().startswith('#'):
                continue

            # Detect top-level keys
            if not line[0].isspace() and ':' in line:
                key = line.split(':')[0].strip()
                if key in ('dependencies', 'dev_dependencies'):
                    in_deps = True
                    indent_level = 0
                    continue
                else:
                    in_deps = False
                    continue

            if in_deps:
                # Check indentation — only first-level children of dependencies
                current_indent = len(line) - len(line.lstrip())
                if indent_level == 0:
                    indent_level = current_indent

                if current_indent == indent_level:
                    # name: ^1.2.3  or  name: ">=1.0.0"  or  name:  (with sub-keys)
                    match = re.match(r'\s+(\S+)\s*:\s*(.*)', line)
                    if match:
                        name = match.group(1)
                        value = match.group(2).strip().strip('"').strip("'")
                        if name in ('flutter', 'flutter_test', 'flutter_localizations'):
                            continue  # SDK dependencies
                        if value and not value.startswith('{') and value != 'null':
                            version = _clean_version(value)
                            packages.append(_pkg(name, version, "pub"))
                        else:
                            packages.append(_pkg(name, "UNKNOWN", "pub"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_pubspec_lock(filepath: str) -> list[dict]:
    """Parse Dart/Flutter pubspec.lock (line-based)."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        current_name = None
        for line in lines:
            stripped = line.rstrip()
            if not stripped:
                continue
            indent = len(line) - len(line.lstrip())
            # Package names are at indent level 2
            if indent == 2 and ':' in stripped:
                current_name = stripped.strip().rstrip(':')
            # Version is at indent level 4
            elif indent == 4 and current_name and stripped.strip().startswith('version:'):
                version = stripped.split(':', 1)[1].strip().strip('"').strip("'")
                packages.append(_pkg(current_name, version, "pub", scope="transitive"))
                current_name = None
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Elixir Parser
# ---------------------------------------------------------------------------

def parse_mix_exs(filepath: str) -> list[dict]:
    """Parse Elixir mix.exs deps function."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Match {:name, "~> 1.0"} or {:name, ">= 2.0.0"}
        for m in re.finditer(r'\{:(\w+)\s*,\s*"([^"]+)"', content):
            name = m.group(1)
            version = _clean_version(m.group(2))
            packages.append(_pkg(name, version, "hex"))

        # Match {:name, "~> 1.0", optional: true} and similar
        for m in re.finditer(r'\{:(\w+)\s*,\s*"([^"]+)"\s*,', content):
            name = m.group(1)
            version = _clean_version(m.group(2))
            # Avoid duplicates from the first pattern
            if not any(p['name'] == name for p in packages):
                packages.append(_pkg(name, version, "hex"))

    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Haskell Parsers
# ---------------------------------------------------------------------------

def parse_cabal(filepath: str) -> list[dict]:
    """Parse Haskell .cabal files for build-depends."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find build-depends blocks (may be multi-line)
        for block_match in re.finditer(
            r'build-depends\s*:\s*(.*?)(?=\n\S|\Z)',
            content, re.DOTALL | re.IGNORECASE
        ):
            deps_text = block_match.group(1)
            # Split by comma
            for dep in re.split(r',', deps_text):
                dep = dep.strip()
                if not dep:
                    continue
                match = re.match(r'^([a-zA-Z0-9\-]+)\s*(.*)$', dep)
                if match:
                    name = match.group(1)
                    version_spec = match.group(2).strip()
                    if name.lower() == 'base':
                        continue  # Skip the base library
                    version = "UNKNOWN"
                    # Try to extract version from spec like >=1.0 && <2.0
                    ver_match = re.search(r'[\d]+(?:\.[\d]+)*', version_spec)
                    if ver_match:
                        version = ver_match.group(0)
                    packages.append(_pkg(name, version, "hackage"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


def parse_stack_yaml(filepath: str) -> list[dict]:
    """Parse Haskell stack.yaml extra-deps (line-based)."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            in_extra_deps = False
            for line in f:
                stripped = line.strip()
                if stripped.startswith('extra-deps:'):
                    in_extra_deps = True
                    continue
                if in_extra_deps:
                    if stripped.startswith('-'):
                        # - package-name-1.2.3
                        dep = stripped.lstrip('- ').strip()
                        # Remove @sha256 or similar suffixes
                        dep = dep.split('@')[0]
                        # Split name and version: last segment after '-' that starts with a digit
                        parts = dep.rsplit('-', 1)
                        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
                            packages.append(_pkg(parts[0], parts[1], "hackage"))
                        else:
                            packages.append(_pkg(dep, "UNKNOWN", "hackage"))
                    elif not line[0].isspace() and ':' in stripped:
                        in_extra_deps = False
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# Scala Parser
# ---------------------------------------------------------------------------

def parse_build_sbt(filepath: str) -> list[dict]:
    """Parse Scala build.sbt for library dependencies."""
    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # "group" %% "artifact" % "version"  (Scala cross-build)
        # "group" % "artifact" % "version"   (Java artifact)
        for m in re.finditer(
            r'"([^"]+)"\s*%%?\s*"([^"]+)"\s*%\s*"([^"]+)"',
            content
        ):
            group = m.group(1)
            artifact = m.group(2)
            version = m.group(3)
            packages.append(_pkg(f"{group}:{artifact}", version, "maven"))
    except Exception as e:
        print(f"  ⚠ Error parsing {filepath}: {e}")
    return packages


# ---------------------------------------------------------------------------
# PARSERS Registry
# ---------------------------------------------------------------------------

# Maps exact filenames (or special keys) to parser functions.
# Special keys prefixed with '*' are handled via glob matching in scan_repository.
PARSERS: dict[str, callable] = {
    # Python
    "requirements.txt":          parse_requirements_txt,
    "Pipfile":                   parse_pipfile,
    "pyproject.toml":            parse_pyproject_toml,
    "setup.cfg":                 parse_setup_cfg,
    # Node / npm
    "package.json":              parse_package_json,
    "package-lock.json":         parse_package_lock_json,
    # Go
    "go.mod":                    parse_go_mod,
    "go.sum":                    parse_go_sum,
    # Java / Kotlin
    "pom.xml":                   parse_pom_xml,
    "build.gradle":              parse_build_gradle,
    "build.gradle.kts":          parse_build_gradle,
    # .NET / C#
    "packages.config":           parse_packages_config,
    "Directory.Packages.props":  parse_directory_packages_props,
    # C / C++
    "conanfile.txt":             parse_conanfile_txt,
    "vcpkg.json":                parse_vcpkg_json,
    # Rust
    "Cargo.toml":                parse_cargo_toml,
    "Cargo.lock":                parse_cargo_lock,
    # Ruby
    "Gemfile":                   parse_gemfile,
    "Gemfile.lock":              parse_gemfile_lock,
    # PHP
    "composer.json":             parse_composer_json,
    "composer.lock":             parse_composer_lock,
    # Swift
    "Package.swift":             parse_package_swift,
    "Package.resolved":          parse_package_resolved,
    # Dart / Flutter
    "pubspec.yaml":              parse_pubspec_yaml,
    "pubspec.lock":              parse_pubspec_lock,
    # Elixir
    "mix.exs":                   parse_mix_exs,
    # Haskell
    "stack.yaml":                parse_stack_yaml,
    # Scala
    "build.sbt":                 parse_build_sbt,
}

# File extensions that use glob matching (not exact filename)
GLOB_PARSERS: dict[str, callable] = {
    ".csproj":  parse_csproj,
    ".fsproj":  parse_csproj,
    ".vbproj":  parse_csproj,
    ".cabal":   parse_cabal,
}

# Directories to skip during tree walk
SKIP_DIRS = {
    'node_modules', '.git', 'venv', '.venv', 'env', '.env',
    'vendor', 'target', 'bin', 'obj', 'build', 'dist',
    '__pycache__', '.tox', '.mypy_cache', '.gradle',
    '.dart_tool', '.pub-cache', '_build', 'deps',
    '.stack-work', 'Pods', '.build',
}


# ---------------------------------------------------------------------------
# SPDX 2.3 Generator
# ---------------------------------------------------------------------------

def generate_spdx(packages: list[dict], output_file: str, project_name: str = "Project") -> None:
    """Generate an SPDX 2.3 JSON SBOM document."""
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name}-SBOM",
        "documentNamespace": f"http://spdx.org/spdxdocs/{project_name}-SBOM-{uuid.uuid4()}",
        "creationInfo": {
            "creators": [
                "Tool: ThreatPilot-SBOM-Generator"
            ],
            "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "packages": [],
        "relationships": []
    }

    # Root package representing the repository
    root_package = {
        "name": project_name,
        "SPDXID": "SPDXRef-Root",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False
    }
    spdx_doc["packages"].append(root_package)

    spdx_doc["relationships"].append({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Root"
    })

    seen_ids = set()
    for pkg in packages:
        # Create a safe SPDXID
        safe_name = re.sub(r'[^a-zA-Z0-9\-]', '-', pkg['name'])
        safe_version = re.sub(r'[^a-zA-Z0-9\-.]', '-', pkg['version'])
        spdx_id = f"SPDXRef-{pkg['type']}-{safe_name}-{safe_version}"

        # Ensure uniqueness
        if spdx_id in seen_ids:
            continue
        seen_ids.add(spdx_id)

        spdx_pkg = {
            "name": pkg['name'],
            "SPDXID": spdx_id,
            "versionInfo": pkg['version'],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:{pkg['type']}/{pkg['name']}@{pkg['version']}"
                }
            ]
        }
        spdx_doc["packages"].append(spdx_pkg)

        spdx_doc["relationships"].append({
            "spdxElementId": "SPDXRef-Root",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id
        })

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(spdx_doc, f, indent=2)


# ---------------------------------------------------------------------------
# Repository Scanner
# ---------------------------------------------------------------------------

def scan_repository(repo_path: str, log_callback=None) -> list[dict]:
    """Walk the repository tree and parse all recognised manifest files.

    Args:
        repo_path: Root directory to scan.
        log_callback: Optional callable(str) to receive progress messages.
    """
    all_packages = []
    files_scanned = 0

    def _log(msg: str):
        if log_callback:
            log_callback(msg)
        else:
            print(msg)

    for root, dirs, files in os.walk(repo_path):
        # Remove directories we want to skip (mutate in-place for os.walk)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)

            # Exact-name match
            if filename in PARSERS:
                rel_path = os.path.relpath(filepath, repo_path)
                _log(f"  📦 {rel_path}")
                result = PARSERS[filename](filepath)
                all_packages.extend(result)
                files_scanned += 1
                continue

            # Extension-based (glob) match
            _, ext = os.path.splitext(filename)
            if ext in GLOB_PARSERS:
                rel_path = os.path.relpath(filepath, repo_path)
                _log(f"  📦 {rel_path}")
                result = GLOB_PARSERS[ext](filepath)
                all_packages.extend(result)
                files_scanned += 1

    _log(f"\n  Manifest files scanned: {files_scanned}")
    return all_packages


# ---------------------------------------------------------------------------
# Ecosystem display names
# ---------------------------------------------------------------------------

ECOSYSTEM_NAMES = {
    'pypi': 'Python (PyPI)',
    'npm': 'Node.js (npm)',
    'golang': 'Go',
    'maven': 'Java/Scala (Maven)',
    'nuget': '.NET (NuGet)',
    'conan': 'C/C++ (Conan)',
    'vcpkg': 'C/C++ (vcpkg)',
    'cargo': 'Rust (Cargo)',
    'gem': 'Ruby (Gems)',
    'composer': 'PHP (Composer)',
    'swift': 'Swift (SPM)',
    'pub': 'Dart/Flutter (Pub)',
    'hex': 'Elixir (Hex)',
    'hackage': 'Haskell (Hackage)',
}


# ---------------------------------------------------------------------------
# Summary Printer (CLI)
# ---------------------------------------------------------------------------

def print_summary(packages: list[dict]) -> None:
    """Print a per-ecosystem summary table."""
    counts = defaultdict(int)
    for pkg in packages:
        counts[pkg['type']] += 1

    direct = sum(1 for p in packages if p.get('scope') == 'direct')
    transitive = sum(1 for p in packages if p.get('scope') == 'transitive')

    print("\n╔══════════════════════════════════════════╗")
    print("║        SBOM Generation Summary           ║")
    print("╠══════════════════════════════════════════╣")
    print(f"║ {'Ecosystem':<28} {'Packages':>10} ║")
    print("╠══════════════════════════════════════════╣")

    for ptype, count in sorted(counts.items(), key=lambda x: -x[1]):
        label = ECOSYSTEM_NAMES.get(ptype, ptype)
        print(f"║ {label:<28} {count:>10} ║")

    print("╠══════════════════════════════════════════╣")
    print(f"║ {'Direct dependencies':<28} {direct:>10} ║")
    print(f"║ {'Transitive dependencies':<28} {transitive:>10} ║")
    print(f"║ {'Total unique':<28} {len(packages):>10} ║")
    print("╚══════════════════════════════════════════╝")


# ---------------------------------------------------------------------------
# Main (CLI)
# ---------------------------------------------------------------------------

def main(repo_path: str) -> None:
    repo_path = os.path.abspath(repo_path)
    project_name = os.path.basename(repo_path) or "Project"

    print(f"\n🔍 Scanning repository: {repo_path}\n")
    print("  Supported ecosystems: Python, Node/npm, Go, Java, .NET/C#,")
    print("  C/C++, Rust, Ruby, PHP, Swift, Dart/Flutter, Elixir, Haskell, Scala\n")

    all_packages = scan_repository(repo_path)

    # Deduplicate packages (type + name + version)
    unique_packages = {
        f"{p['type']}|{p['name']}|{p['version']}": p
        for p in all_packages
    }
    deduped = list(unique_packages.values())

    output_path = os.path.join(repo_path, 'sbom.spdx.json')
    generate_spdx(deduped, output_path, project_name)

    print_summary(deduped)
    print(f"\n✅ SBOM saved to: {output_path}\n")


# ---------------------------------------------------------------------------
# GUI (PySide6)
# ---------------------------------------------------------------------------

# Dark-theme stylesheet matching ThreatPilot branding
_GUI_STYLESHEET = """
QWidget {
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
    color: #e6edf3;
}

QMainWindow, #central {
    background-color: #0d1117;
}

/* ── Header banner ────────────────────────────────────────────── */
#header_banner {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #161b22, stop:1 #1c2633);
    border-bottom: 1px solid #30363d;
}
#header_title {
    color: #f0f6fc;
}
#header_subtitle {
    color: #8b949e;
}

/* ── Cards ────────────────────────────────────────────────────── */
.card {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
}

/* ── Stat boxes ───────────────────────────────────────────────── */
#stat_total, #stat_direct, #stat_transitive {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
}
#stat_value {
    font-size: 32px;
    font-weight: bold;
}
#stat_label {
    color: #8b949e;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* ── Input fields ─────────────────────────────────────────────── */
QLineEdit {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 12px;
    color: #e6edf3;
    selection-background-color: #1f6feb;
}
QLineEdit:focus {
    border-color: #58a6ff;
}
QLineEdit:read-only {
    background-color: #161b22;
    color: #8b949e;
}

/* ── Buttons ──────────────────────────────────────────────────── */
QPushButton {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 18px;
    color: #e6edf3;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #30363d;
    border-color: #58a6ff;
}
QPushButton:pressed {
    background-color: #1c2128;
}
QPushButton:disabled {
    background-color: #161b22;
    color: #484f58;
    border-color: #21262d;
}

#btn_generate {
    background-color: #238636;
    border: 1px solid #2ea043;
    color: #ffffff;
    font-size: 14px;
    padding: 10px 28px;
    border-radius: 8px;
}
#btn_generate:hover {
    background-color: #2ea043;
    border-color: #3fb950;
}
#btn_generate:pressed {
    background-color: #196c2e;
}
#btn_generate:disabled {
    background-color: #1a2e1f;
    border-color: #1a2e1f;
    color: #3d6b47;
}

/* ── Table ────────────────────────────────────────────────────── */
QTableWidget {
    background-color: #0d1117;
    alternate-background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    gridline-color: #21262d;
    selection-background-color: #1f6feb;
    color: #e6edf3;
}
QTableWidget::item {
    padding: 6px 10px;
}
QHeaderView::section {
    background-color: #161b22;
    border: none;
    border-bottom: 2px solid #30363d;
    border-right: 1px solid #21262d;
    padding: 8px 10px;
    font-weight: 700;
    color: #8b949e;
    text-transform: uppercase;
    font-size: 11px;
}

/* ── Log area ─────────────────────────────────────────────────── */
QTextEdit {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 8px;
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    color: #8b949e;
}

/* ── Labels ───────────────────────────────────────────────────── */
#section_label {
    font-size: 13px;
    font-weight: 700;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* ── Scrollbar ────────────────────────────────────────────────── */
QScrollBar:vertical {
    background: #0d1117;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #30363d;
    border-radius: 4px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background: #484f58;
}
QScrollBar::add-line, QScrollBar::sub-line,
QScrollBar::add-page, QScrollBar::sub-page {
    background: none;
    border: none;
}
"""


def _launch_gui():
    """Launch the PySide6 GUI for SBOM generation."""
    from PySide6.QtCore import Qt, QThread, Signal
    from PySide6.QtGui import QFont, QIcon, QColor
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QLineEdit, QFileDialog, QTextEdit,
        QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
        QSizePolicy, QSpacerItem,
    )

    # ── Worker thread ─────────────────────────────────────────
    class ScanWorker(QThread):
        """Run the scan + SPDX generation off the main thread."""
        log = Signal(str)
        finished_signal = Signal(list, str)  # (packages, output_path)
        error = Signal(str)

        def __init__(self, repo_path: str, output_path: str):
            super().__init__()
            self.repo_path = repo_path
            self.output_path = output_path

        def run(self):
            try:
                pkgs = scan_repository(self.repo_path, log_callback=self.log.emit)
                # Deduplicate
                unique = {
                    f"{p['type']}|{p['name']}|{p['version']}": p
                    for p in pkgs
                }
                deduped = list(unique.values())
                project_name = os.path.basename(self.repo_path) or "Project"
                generate_spdx(deduped, self.output_path, project_name)
                self.finished_signal.emit(deduped, self.output_path)
            except Exception as exc:
                self.error.emit(str(exc))

    # ── Main window ───────────────────────────────────────────
    class SBOMGeneratorWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("ThreatPilot — SBOM Generator")
            self.setMinimumSize(780, 700)
            self.resize(860, 760)
            self._worker = None
            self._build_ui()

        # ── UI construction ───────────────────────────────────
        def _build_ui(self):
            central = QWidget()
            central.setObjectName("central")
            self.setCentralWidget(central)
            root = QVBoxLayout(central)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(0)

            # ── Header banner ─────────────────────────────────
            banner = QWidget()
            banner.setObjectName("header_banner")
            banner_lay = QVBoxLayout(banner)
            banner_lay.setContentsMargins(28, 22, 28, 18)
            banner_lay.setSpacing(4)

            title = QLabel("SBOM Generator")
            title.setObjectName("header_title")
            title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            banner_lay.addWidget(title)

            subtitle = QLabel(
                "Scan any project for dependencies across 14 ecosystems · "
                "Python · Node · Go · Java · .NET · C++ · Rust · Ruby · PHP · Swift · Dart · Elixir · Haskell · Scala"
            )
            subtitle.setObjectName("header_subtitle")
            subtitle.setWordWrap(True)
            subtitle.setFont(QFont("Segoe UI", 10))
            banner_lay.addWidget(subtitle)

            root.addWidget(banner)

            # ── Body ──────────────────────────────────────────
            body = QWidget()
            body_lay = QVBoxLayout(body)
            body_lay.setContentsMargins(24, 20, 24, 20)
            body_lay.setSpacing(18)

            # ── Source folder row ─────────────────────────────
            src_lbl = QLabel("SOURCE FOLDER")
            src_lbl.setObjectName("section_label")
            body_lay.addWidget(src_lbl)

            src_row = QHBoxLayout()
            src_row.setSpacing(8)
            self._src_edit = QLineEdit()
            self._src_edit.setPlaceholderText("Select the project/repository folder to scan…")
            src_row.addWidget(self._src_edit)
            btn_browse_src = QPushButton("Browse…")
            btn_browse_src.setFixedWidth(100)
            btn_browse_src.clicked.connect(self._browse_source)
            src_row.addWidget(btn_browse_src)
            body_lay.addLayout(src_row)

            # ── Output path row ───────────────────────────────
            out_lbl = QLabel("OUTPUT PATH")
            out_lbl.setObjectName("section_label")
            body_lay.addWidget(out_lbl)

            out_row = QHBoxLayout()
            out_row.setSpacing(8)
            self._out_edit = QLineEdit()
            self._out_edit.setPlaceholderText("sbom.spdx.json (defaults to source folder)")
            out_row.addWidget(self._out_edit)
            btn_browse_out = QPushButton("Browse…")
            btn_browse_out.setFixedWidth(100)
            btn_browse_out.clicked.connect(self._browse_output)
            out_row.addWidget(btn_browse_out)
            body_lay.addLayout(out_row)

            # ── Generate button ───────────────────────────────
            btn_row = QHBoxLayout()
            btn_row.addStretch()
            self._btn_gen = QPushButton("  ▶  Generate SBOM  ")
            self._btn_gen.setObjectName("btn_generate")
            self._btn_gen.setCursor(Qt.CursorShape.PointingHandCursor)
            self._btn_gen.clicked.connect(self._on_generate)
            btn_row.addWidget(self._btn_gen)
            btn_row.addStretch()
            body_lay.addLayout(btn_row)

            # ── Stat cards ────────────────────────────────────
            self._stats_container = QWidget()
            self._stats_container.setVisible(False)
            stats_lay = QHBoxLayout(self._stats_container)
            stats_lay.setContentsMargins(0, 0, 0, 0)
            stats_lay.setSpacing(14)

            self._stat_total = self._make_stat_card("stat_total", "0", "Total Components", "#58a6ff")
            self._stat_direct = self._make_stat_card("stat_direct", "0", "Direct", "#3fb950")
            self._stat_transitive = self._make_stat_card("stat_transitive", "0", "Transitive", "#d29922")
            stats_lay.addWidget(self._stat_total)
            stats_lay.addWidget(self._stat_direct)
            stats_lay.addWidget(self._stat_transitive)
            body_lay.addWidget(self._stats_container)

            # ── Ecosystem table ───────────────────────────────
            tbl_lbl = QLabel("ECOSYSTEM BREAKDOWN")
            tbl_lbl.setObjectName("section_label")
            self._tbl_label = tbl_lbl
            tbl_lbl.setVisible(False)
            body_lay.addWidget(tbl_lbl)

            self._table = QTableWidget(0, 4)
            self._table.setHorizontalHeaderLabels(["Ecosystem", "Direct", "Transitive", "Total"])
            self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
            self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
            self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
            self._table.setColumnWidth(1, 100)
            self._table.setColumnWidth(2, 110)
            self._table.setColumnWidth(3, 90)
            self._table.verticalHeader().setVisible(False)
            self._table.setAlternatingRowColors(True)
            self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self._table.setVisible(False)
            self._table.setMaximumHeight(220)
            body_lay.addWidget(self._table)

            # ── Log output ────────────────────────────────────
            log_lbl = QLabel("SCAN LOG")
            log_lbl.setObjectName("section_label")
            body_lay.addWidget(log_lbl)

            self._log = QTextEdit()
            self._log.setReadOnly(True)
            self._log.setMaximumHeight(150)
            self._log.setPlaceholderText("Scan output will appear here…")
            body_lay.addWidget(self._log)

            body_lay.addStretch()
            root.addWidget(body, 1)

        # ── Helpers ───────────────────────────────────────────
        def _make_stat_card(self, obj_name: str, value: str, label: str, accent: str) -> QFrame:
            card = QFrame()
            card.setObjectName(obj_name)
            card.setProperty("class", "card")
            card.setMinimumHeight(90)
            lay = QVBoxLayout(card)
            lay.setContentsMargins(18, 14, 18, 14)
            lay.setSpacing(4)
            lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

            val_lbl = QLabel(value)
            val_lbl.setObjectName("stat_value")
            val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val_lbl.setStyleSheet(f"color: {accent};")
            lay.addWidget(val_lbl)

            txt_lbl = QLabel(label)
            txt_lbl.setObjectName("stat_label")
            txt_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(txt_lbl)

            # Store references for later update
            card._val_label = val_lbl
            return card

        # ── Slots ─────────────────────────────────────────────
        def _browse_source(self):
            path = QFileDialog.getExistingDirectory(self, "Select Project Folder")
            if path:
                self._src_edit.setText(path)
                # Auto-fill output path if empty
                if not self._out_edit.text():
                    self._out_edit.setText(os.path.join(path, "sbom.spdx.json"))

        def _browse_output(self):
            path, _ = QFileDialog.getSaveFileName(
                self, "Save SBOM As", self._out_edit.text() or "sbom.spdx.json",
                "SPDX JSON (*.spdx.json);;JSON Files (*.json);;All Files (*)"
            )
            if path:
                self._out_edit.setText(path)

        def _on_generate(self):
            src = self._src_edit.text().strip()
            if not src or not os.path.isdir(src):
                self._log.setPlainText("⚠ Please select a valid source folder.")
                return

            out = self._out_edit.text().strip()
            if not out:
                out = os.path.join(src, "sbom.spdx.json")
                self._out_edit.setText(out)

            self._log.clear()
            self._log.append(f"🔍 Scanning: {src}\n")
            self._btn_gen.setEnabled(False)
            self._btn_gen.setText("  ⏳  Scanning…  ")

            # Hide previous results
            self._stats_container.setVisible(False)
            self._table.setVisible(False)
            self._tbl_label.setVisible(False)

            self._worker = ScanWorker(src, out)
            self._worker.log.connect(self._on_log)
            self._worker.finished_signal.connect(self._on_finished)
            self._worker.error.connect(self._on_error)
            self._worker.start()

        def _on_log(self, msg: str):
            self._log.append(msg)

        def _on_error(self, msg: str):
            self._log.append(f"\n❌ Error: {msg}")
            self._btn_gen.setEnabled(True)
            self._btn_gen.setText("  ▶  Generate SBOM  ")

        def _on_finished(self, packages: list, output_path: str):
            self._btn_gen.setEnabled(True)
            self._btn_gen.setText("  ▶  Generate SBOM  ")

            total = len(packages)
            direct = sum(1 for p in packages if p.get('scope') == 'direct')
            transitive = sum(1 for p in packages if p.get('scope') == 'transitive')

            # Update stat cards
            self._stat_total._val_label.setText(str(total))
            self._stat_direct._val_label.setText(str(direct))
            self._stat_transitive._val_label.setText(str(transitive))
            self._stats_container.setVisible(True)

            # Build ecosystem table
            eco_data: dict[str, dict] = {}  # type -> {direct: int, transitive: int}
            for p in packages:
                t = p['type']
                if t not in eco_data:
                    eco_data[t] = {'direct': 0, 'transitive': 0}
                eco_data[t][p.get('scope', 'direct')] += 1

            self._table.setRowCount(0)
            sorted_ecos = sorted(eco_data.items(),
                                 key=lambda x: x[1]['direct'] + x[1]['transitive'],
                                 reverse=True)
            for eco_type, counts in sorted_ecos:
                row = self._table.rowCount()
                self._table.insertRow(row)

                name = ECOSYSTEM_NAMES.get(eco_type, eco_type)
                d = counts['direct']
                t = counts['transitive']

                name_item = QTableWidgetItem(name)
                name_item.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))
                self._table.setItem(row, 0, name_item)

                direct_item = QTableWidgetItem(str(d))
                direct_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                direct_item.setForeground(QColor("#3fb950"))
                self._table.setItem(row, 1, direct_item)

                trans_item = QTableWidgetItem(str(t))
                trans_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                trans_item.setForeground(QColor("#d29922"))
                self._table.setItem(row, 2, trans_item)

                total_item = QTableWidgetItem(str(d + t))
                total_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                total_item.setForeground(QColor("#58a6ff"))
                total_item.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
                self._table.setItem(row, 3, total_item)

            self._table.setVisible(True)
            self._tbl_label.setVisible(True)

            self._log.append(f"\n✅ SBOM saved to: {output_path}")
            self._log.append(f"   Total: {total}  ·  Direct: {direct}  ·  Transitive: {transitive}")

    # ── Launch ────────────────────────────────────────────────
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(_GUI_STYLESHEET)
    win = SBOMGeneratorWindow()
    win.show()
    # Only exec if we created the app
    if not QApplication.instance() or app.topLevelWidgets() == [win]:
        sys.exit(app.exec())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # CLI mode — path was provided
        main(sys.argv[1])
    else:
        # GUI mode
        try:
            _launch_gui()
        except ImportError:
            # PySide6 not available, fall back to scanning current directory
            print("PySide6 not found — running in CLI mode on current directory.")
            main(".")
