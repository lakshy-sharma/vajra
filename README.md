# Vajra

An endpoint detection and response system which is engineered to be soft on your systems and your security teams.

A huge shoutout to [Kraken](https://github.com/botherder/kraken) which is my inspiration to start this project.

Made with :heart: in India

## Goals

The goal here is to build a modern endpoint detection and response system which is capable for performing routine system scans, remediation of malicious files, etc.

**What makes us different?**

1. Reducing memory and cpu footprint on your systems through modern languages and better programming practices.
2. The fact that we pay extra attention to minimizing alert fatigue.
3. We utilize a coarse AI system *(fine tuning is pending)* for scanning files just to ensure that the system doesnt miss files not in strict yara rules.

For roadmap and feature dvelopment plans please refer to TODO.md

## Current Features

1. File scanning and filesystem monitoring.
2. Process scanning and process monitoring.
3. Locally persistent storage for detections.

## Resources Required

1. **CPUs**: 3 *(Can be configured to go lower if you are comfortable with going slower)*
2. **RAM**: 100 mb

## Platform Support Matrix

|OS|amd64|arm64
|-|-|-|
|Ubuntu 24.04+|Yes|Planned|
|Debian Trixie+|Yes|Planned|
|Fedora 42+|Planned|Planned|
|Windows 11|Not Started|Not Started|
|MacOS|Not Started|Not Started|

## Contributing

Before you begin contributing. You need to know how to make a build setup.

### Build Dependencies

*Because every chef needs to get his ingredients correct.*

**Debian**
```
build-essential
clang
llvm
libbpf-dev
linux-headers-$(uname -r)
libyara-dev
linux-tools-$(uname -r)
```

**RHEL**
```
clang
llvm
libbpf-devel
kernel-devel
yara-devel
```

### Build Your Own Binary

To trigger a build run this command

On a Linux machine with amd64 architecture
```
make linux_amd64
```

On a Linux machine with arn64 architecture
```
make linux_arm64
```

## Security

If you spot any security issues please let me know in personal at lakshy.d.sharma@gmail.com.
I shall make best effort to understand your concerns and fix them quickly.
Thank you for your awareness and concern in advance.
