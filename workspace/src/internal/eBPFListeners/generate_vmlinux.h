#!/bin/bash
set -e

echo "Generating vmlinux.h from BTF..."

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "Error: bpftool not found. Installing..."
    
    if [ -f /etc/debian_version ]; then
        sudo apt-get update
        sudo apt-get install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r)
    elif [ -f /etc/redhat-release ]; then
        sudo dnf install -y bpftool
    elif [ -f /etc/arch-release ]; then
        sudo pacman -S bpf
    else
        echo "Please install bpftool manually"
        exit 1
    fi
fi

# Check if BTF is available
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "Error: BTF not available on this system"
    echo "Your kernel must be compiled with CONFIG_DEBUG_INFO_BTF=y"
    exit 1
fi

# Generate vmlinux.h
echo "Generating vmlinux.h..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

echo "vmlinux.h generated successfully!"
echo "File size: $(du -h vmlinux.h | cut -f1)"