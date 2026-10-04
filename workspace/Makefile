# Build variables
RELEASE_DIR  := ./release
SRC          := ./src
EBPF_SRC     := $(SRC)/internal/ebpf/c
EBPF_OUT     := $(SRC)/internal/ebpf
DEB_SKEL     := ./deb_skel

# Deployment variables
PACKAGE_NAME := vajra
VERSION      := $(shell cat version)

# ── Architecture targets ─────────────────────────────────────
# amd64 and arm64 are the only supported targets.
# eBPF objects are cross-compiled by clang regardless of host arch.

all: linux_amd64

# ── eBPF generation ──────────────────────────────────────────
# Requires:
#   clang (>= 14)
#   bpftool (for vmlinux.h generation)
#   go install github.com/cilium/ebpf/cmd/bpf2go@latest
#
# Run once per developer machine, or whenever ebpf_events.c changes.
# The generated .go and .o files are committed to the repo so that
# developers without a full BPF toolchain can still build.

.PHONY: generate-vmlinux
generate-vmlinux:
	@echo "Generating vmlinux.h from running kernel BTF..."
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: /sys/kernel/btf/vmlinux not found."; \
		echo "Your kernel must be compiled with CONFIG_DEBUG_INFO_BTF=y"; \
		exit 1; \
	fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(EBPF_SRC)/vmlinux.h
	@echo "vmlinux.h written to $(EBPF_SRC)/vmlinux.h"

.PHONY: generate-ebpf
generate-ebpf: generate-vmlinux
	@echo "Running bpf2go — compiling eBPF C and generating Go bindings..."
	cd $(EBPF_OUT) && \
		go generate .
	@echo "eBPF generation complete."

# The go:generate directive that lives in internal/ebpf/listener.go
# invokes this command. We document it here for clarity:
#
#   //go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
#       -cc clang \
#       -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_$(GOARCH)" \
#       -target amd64,arm64 \
#       -output-dir . \
#       bpf ./c/ebpf_events.c -- -I./c
#
# Output files (committed to repo):
#   internal/ebpf/bpf_x86_bpfel.go   + bpf_x86_bpfel.o
#   internal/ebpf/bpf_arm64_bpfel.go + bpf_arm64_bpfel.o

# ── amd64 build ──────────────────────────────────────────────

.PHONY: linux_amd64
linux_amd64: ARCH    := amd64
linux_amd64: DEB_BASE := ./$(PACKAGE_NAME)_$(VERSION)_amd64
linux_amd64:
	@echo "Building $(PACKAGE_NAME) — version: $(VERSION) arch: amd64"
	@echo "============================================"
	cd $(SRC) && \
		GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w" -o $(PACKAGE_NAME) main.go
	mkdir -p $(RELEASE_DIR)
	mv $(SRC)/$(PACKAGE_NAME) $(RELEASE_DIR)/$(PACKAGE_NAME)
	$(MAKE) _deb ARCH=amd64 DEB_BASE=$(DEB_BASE)
	@echo "Build complete — $(RELEASE_DIR)/$(PACKAGE_NAME)_$(VERSION)_amd64.deb"
	@echo "============================================"

# ── arm64 build ──────────────────────────────────────────────

.PHONY: linux_arm64
linux_arm64: ARCH    := arm64
linux_arm64: DEB_BASE := ./$(PACKAGE_NAME)_$(VERSION)_arm64
linux_arm64:
	@echo "Building $(PACKAGE_NAME) — version: $(VERSION) arch: arm64"
	@echo "============================================"
	cd $(SRC) && \
		GOOS=linux GOARCH=arm64 \
		go build -ldflags="-s -w" -o $(PACKAGE_NAME) main.go
	mkdir -p $(RELEASE_DIR)
	mv $(SRC)/$(PACKAGE_NAME) $(RELEASE_DIR)/$(PACKAGE_NAME)
	$(MAKE) _deb ARCH=arm64 DEB_BASE=$(DEB_BASE)
	@echo "Build complete — $(RELEASE_DIR)/$(PACKAGE_NAME)_$(VERSION)_arm64.deb"
	@echo "============================================"

# ── deb packaging (internal target) ─────────────────────────
# Called by linux_amd64 and linux_arm64 with ARCH and DEB_BASE set.

.PHONY: _deb
_deb:
	@echo "Building deb package..."
	cp -r $(DEB_SKEL) $(DEB_BASE)
	sed -i 's/<PACKAGE_NAME>/$(PACKAGE_NAME)/' $(DEB_BASE)/DEBIAN/control
	sed -i 's/<VERSION>/$(VERSION)/'           $(DEB_BASE)/DEBIAN/control
	sed -i 's/<ARCH>/$(ARCH)/'                 $(DEB_BASE)/DEBIAN/control
	cp $(RELEASE_DIR)/$(PACKAGE_NAME) $(DEB_BASE)/opt/$(PACKAGE_NAME)/$(PACKAGE_NAME)
	dpkg-deb --build $(DEB_BASE)
	mv $(DEB_BASE).deb $(RELEASE_DIR)/
	rm -rf $(DEB_BASE)

# ── Development helpers ───────────────────────────────────────

# Run the agent locally without packaging (requires root for eBPF).
.PHONY: run
run:
	cd $(SRC) && go run main.go

# Run all tests.
.PHONY: test
test:
	cd $(SRC) && go test ./...

# Vet + staticcheck.
.PHONY: lint
lint:
	cd $(SRC) && go vet ./...
	cd $(SRC) && staticcheck ./...

# Remove release artifacts. Does NOT remove generated eBPF files
# because those are committed and expensive to regenerate.
.PHONY: clean
clean:
	rm -rf $(RELEASE_DIR)
	rm -f  $(SRC)/$(PACKAGE_NAME)

# Remove generated eBPF files as well. Forces full regeneration.
# Only needed if you change ebpf_events.c or vmlinux.h.
.PHONY: clean-ebpf
clean-ebpf: clean
	rm -f $(EBPF_SRC)/vmlinux.h
	rm -f $(EBPF_OUT)/bpf_x86_bpfel.go
	rm -f $(EBPF_OUT)/bpf_x86_bpfel.o
	rm -f $(EBPF_OUT)/bpf_arm64_bpfel.go
	rm -f $(EBPF_OUT)/bpf_arm64_bpfel.o

.PHONY: help
help:
	@echo ""
	@echo "Vajra EDR — build targets"
	@echo ""
	@echo "  make                  Build for linux/amd64 (default)"
	@echo "  make linux_amd64      Build binary + deb for amd64"
	@echo "  make linux_arm64      Build binary + deb for arm64"
	@echo ""
	@echo "  make generate-vmlinux Generate vmlinux.h from running kernel"
	@echo "  make generate-ebpf    Generate vmlinux.h + run bpf2go"
	@echo ""
	@echo "  make run              Run agent locally (needs root)"
	@echo "  make test             Run all tests"
	@echo "  make lint             vet + staticcheck"
	@echo ""
	@echo "  make clean            Remove release artifacts"
	@echo "  make clean-ebpf       Remove release artifacts + generated eBPF files"
	@echo ""
