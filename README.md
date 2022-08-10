# trivy-plugin-explicit-dependency
A [Trivy](https://github.com/aquasecurity/trivy) plugin that scans the filesystem and leaves only explicit dependency packages

## Install

```bash
$ trivy plugin install github.com/satandyh/trivy-plugin-explicit-dependency
$ trivy exp-dep -h
Usage: trivy exp-dep [-h,--help] path/to/file
 A Trivy that scans the filesystem and leaves only explicit dependency packages.

Options:
  -h, --help    Show usage.

Examples:
  # Scan a Filesystem
  trivy exp-dep /path/to/project

  # Scan a Filesystem and filter by severity
  trivy exp-dep /path/to/project -- --severity CRITICAL
```

## Usage
Trivy's options need to be passed after `--`.

```bash
# Scan a Filesystem
$ trivy exp-dep /path/to/project

# Scan a Filesystem and filter by severity
$ trivy exp-dep /path/to/project -- --severity CRITICAL
```
