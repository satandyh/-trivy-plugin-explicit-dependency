# trivy-plugin-explicit-dependency
A [Trivy](https://github.com/aquasecurity/trivy) plugin that scans the filesystem and skips all packages except for explicitly specified dependencies.

Inside You will find 2 versions:

- rust (by default)
- bash

If You want to use bash version - You need just copy `trivy-explicit-dependency_shell` to ~/.trivy/

## Requirements

OS: linux (arch amd64)

Dependencies:

- bash (if you want to use shell version)
- no any (if you want to use rust version)

Tested with trivy v0.30.4
## Working with
Plugin analyze files where explicit dependency listed. **So if in Your project this file has different name this plugin will not work!**

For this moment plugin support next languages.

| **Language** | **File** *       | **Filesystem** |
| ------------ | ---------------- | :------------: |
| Node.js      | package.json     |       ✅        |
| Ruby         | gemspec          |       -        |
| Python       | requirements.txt |       ✅        |
|              | Pipfile          |       ✅        |
|              | pyproject.toml   |       ✅        |
| PHP          |                  |       -        |
| .NET         |                  |       -        |
| Java         | pom.xml          |       -        |
| Go           | go.mod           |       -        |
|              | go.sum           |       -        |
| Rust         |                  |       -        |

*Filename case insensitive.
## Install

```bash
$ trivy plugin install github.com/satandyh/trivy-plugin-explicit-dependency
$ trivy exp-dep -- -h
A Trivy plugin that scans the filesystem and skips all packages except for explicitly specified dependencies.
Important! You have to use '--' to pass flags to plugin. Without it all flags will be passed as global for shell version.

Usage:
  trivy exp-dep -- [-h,--help] -p PROJECT_PATH [--global] [TRIVY OPTION]

Options:
  --            Flag indicating that all options after should pass to plugin.
  -h, --help    Show usage.
  -p, --path    Directory where to scan.
  --global      Indicate taht all flags after will be passed as trivy global/fs options.
                Positional, should be after "-p/-h/--" options.

Examples:
  # Scan fs
  trivy exp-dep -- -p /path/to/project
  # Scan fs and filter by severity
  trivy exp-dep -- --path /path/to/project --global --severity CRITICAL
```

## Usage
Plugin's options should to be passed after `--`.

Trivy's options need to be passed after `--global`.

```bash
# Scan fs
$ trivy exp-dep -- -p /path/to/project

# Scan fs and filter by severity
$ trivy exp-dep -- --path /path/to/project --global --severity CRITICAL
```
