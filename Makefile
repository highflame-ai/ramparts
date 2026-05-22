# MCP Scanner Multi-Architecture Build Makefile
# Supports cross-compilation for multiple platforms and architectures

# ============================================================================
# CONFIGURATION
# ============================================================================

# Project information
PROJECT_NAME := ramparts
VERSION := $(shell grep '^version = ' Cargo.toml | cut -d'"' -f2)
AUTHOR := $(shell grep '^authors = ' Cargo.toml | cut -d'"' -f2 | cut -d'<' -f1 | xargs)

# Build directories
BUILD_DIR := target
RELEASE_DIR := $(BUILD_DIR)/release
DIST_DIR := dist
BIN_DIR := $(DIST_DIR)/bin

# Rust toolchain
RUST_VERSION := $(shell rustc --version | cut -d' ' -f2)
CARGO := cargo
RUSTUP := rustup

# Clippy strict-gate flags. Promote dead_code + unused_* warnings to
# errors so PRs can't leave orphaned functions, fields, imports, or
# unneeded `mut` keywords behind. Mirrors the gate enforced in
# highflame-firehog's pr-check.yml; `--all-targets` covers tests +
# benches (without it, test code is silently unlinted).
#
# `-D unused` is the lint group that includes dead_code,
# unused_imports, unused_variables, unused_mut, unused_must_use,
# unused_assignments, unused_macros, and friends. `-D warnings`
# alone would also catch these (they're warn-by-default), but
# keeping `-D unused` explicit documents the intent so a future
# reader doesn't accidentally `#[allow(dead_code)]`-pepper the
# codebase under the impression it's a soft hint.
CLIPPY_STRICT_FLAGS := -D warnings -D unused

# ============================================================================
# ARCHITECTURE DETECTION
# ============================================================================

# Detect current architecture and OS
HOST_ARCH := $(shell uname -m)
HOST_OS := $(shell uname -s)

# Map host architecture to Rust target
ifeq ($(HOST_OS),Darwin)
    ifeq ($(HOST_ARCH),x86_64)
        CURRENT_TARGET := x86_64-apple-darwin
    else ifeq ($(HOST_ARCH),arm64)
        CURRENT_TARGET := aarch64-apple-darwin
    else
        CURRENT_TARGET := x86_64-apple-darwin
    endif
else ifeq ($(HOST_OS),Linux)
    ifeq ($(HOST_ARCH),x86_64)
        CURRENT_TARGET := x86_64-unknown-linux-gnu
    else ifeq ($(HOST_ARCH),aarch64)
        CURRENT_TARGET := aarch64-unknown-linux-gnu
    else
        CURRENT_TARGET := x86_64-unknown-linux-gnu
    endif
else ifeq ($(HOST_OS),MINGW32_NT-10.0)
    CURRENT_TARGET := x86_64-pc-windows-gnu
else ifeq ($(HOST_OS),MINGW64_NT-10.0)
    CURRENT_TARGET := x86_64-pc-windows-gnu
else
    CURRENT_TARGET := x86_64-unknown-linux-gnu
endif

# ============================================================================
# TARGET ARCHITECTURES
# ============================================================================

# Linux targets
LINUX_TARGETS := x86_64-unknown-linux-gnu \
                 aarch64-unknown-linux-gnu \
                 x86_64-unknown-linux-musl \
                 aarch64-unknown-linux-musl

# macOS targets
MACOS_TARGETS := x86_64-apple-darwin \
                 aarch64-apple-darwin

# Windows targets
WINDOWS_TARGETS := x86_64-pc-windows-gnu \
                   x86_64-pc-windows-msvc \
                   aarch64-pc-windows-msvc

# All targets
ALL_TARGETS := $(LINUX_TARGETS) $(MACOS_TARGETS) $(WINDOWS_TARGETS)

# ============================================================================
# BUILD CONFIGURATION
# ============================================================================

# Build profiles
PROFILES := debug release

# Features (if any)
FEATURES :=

# Default target - build for current architecture
.DEFAULT_GOAL := build

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Check if target is installed
define check_target
	@echo "Checking if $(1) is installed..."
	@$(RUSTUP) target list --installed | grep -q "$(1)" || \
		(echo "Installing $(1)..." && $(RUSTUP) target add $(1))
endef

# Build for specific target
define build_target
	@echo "Building for $(1)..."
	@$(CARGO) build --target $(1) --release $(if $(FEATURES),--features $(FEATURES),)
endef

# Copy binary to distribution directory
define copy_binary
	@mkdir -p $(BIN_DIR)
	@if [ -f "$(BUILD_DIR)/$(1)/release/$(PROJECT_NAME)$(2)" ]; then \
		echo "Copying $(PROJECT_NAME)$(2) for $(1)..."; \
		cp "$(BUILD_DIR)/$(1)/release/$(PROJECT_NAME)$(2)" "$(BIN_DIR)/$(PROJECT_NAME)-$(1)$(2)"; \
	else \
		echo "Binary not found for $(1)"; \
	fi
endef

# ============================================================================
# MAIN TARGETS
# ============================================================================

.PHONY: help
help: ## Show this help message
	@echo "Ramparts Multi-Architecture Build System"
	@echo "======================================="
	@echo ""
	@echo "Current System:"
	@echo "  OS: $(HOST_OS)"
	@echo "  Architecture: $(HOST_ARCH)"
	@echo "  Target: $(CURRENT_TARGET)"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Target architectures:"
	@echo "  Linux:   $(LINUX_TARGETS)"
	@echo "  macOS:   $(MACOS_TARGETS)"
	@echo "  Windows: $(WINDOWS_TARGETS)"
	@echo ""
	@echo "Examples:"
	@echo "  make build                    # Build for current architecture"
	@echo "  make ci-check                 # Run all CI quality checks (PR prep)"
	@echo "  make build-linux-x86_64      # Build for Linux x86_64"
	@echo "  make build-macos-aarch64     # Build for macOS ARM64"
	@echo "  make build-all               # Build for all targets"
	@echo "  make package                 # Create distribution packages"

.PHONY: build
build: ## Build for current architecture (auto-detected) with quality checks
	@echo "Running quality checks before build..."
	@echo "Checking code formatting..."
	@$(CARGO) fmt --all -- --check || (echo "❌ Code formatting check failed. Run 'make fmt' to fix." && exit 1)
	@echo "✅ Code formatting check passed"
	@echo "Running clippy linting (strict gate)..."
	@$(CARGO) clippy --all-features --all-targets -- $(CLIPPY_STRICT_FLAGS) || (echo "❌ Clippy check failed. Fix the warnings above." && exit 1)
	@echo "✅ Clippy check passed"
	@$(CARGO) clippy --all-targets --all-features -- -W clippy::all -W clippy::pedantic -A clippy::missing_docs_in_private_items -A clippy::module_name_repetitions
	@echo "✅ Extended Clippy check passed"
	@echo "Building for current architecture: $(CURRENT_TARGET)"
	$(call check_target,$(CURRENT_TARGET))
	$(call build_target,$(CURRENT_TARGET))
	$(call copy_binary,$(CURRENT_TARGET),$(if $(findstring windows,$(CURRENT_TARGET)),.exe,))
	@echo "✅ Build complete for $(CURRENT_TARGET)"

.PHONY: clean
clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	@$(CARGO) clean
	@rm -rf $(DIST_DIR)
	@echo "Clean complete"

.PHONY: fmt-check
fmt-check: ## Check code formatting (does not modify files)
	@echo "Checking code formatting..."
	@$(CARGO) fmt --all -- --check
	@echo "Formatting check complete"

.PHONY: check
check: ## Check code without building (all features)
	@echo "Checking code (all features)..."
	@$(CARGO) check --all-features
	@echo "Code check complete"

.PHONY: test
test: ## Run tests (all features)
	@echo "Running tests (all features)..."
	@$(CARGO) test --all-features
	@echo "Tests complete"

.PHONY: lint
lint: ## Run clippy linting (strict gate — same as CI)
	@echo "Running clippy (strict gate, all features, all targets)..."
	@$(CARGO) clippy --all-features --all-targets -- $(CLIPPY_STRICT_FLAGS)
	@echo "Clippy complete"

.PHONY: fmt
fmt: ## Format code
	@echo "Formatting code..."
	@$(CARGO) fmt
	@echo "Formatting complete"

.PHONY: audit
audit: ## Audit dependencies
	@echo "Auditing dependencies..."
	@$(CARGO) audit
	@echo "Audit complete"

# ============================================================================
# INDIVIDUAL TARGET BUILDS
# ============================================================================

# Linux builds
.PHONY: build-linux-x86_64
build-linux-x86_64: ## Build for Linux x86_64
	$(call check_target,x86_64-unknown-linux-gnu)
	$(call build_target,x86_64-unknown-linux-gnu)
	$(call copy_binary,x86_64-unknown-linux-gnu,)

.PHONY: build-linux-aarch64
build-linux-aarch64: ## Build for Linux ARM64
	$(call check_target,aarch64-unknown-linux-gnu)
	$(call build_target,aarch64-unknown-linux-gnu)
	$(call copy_binary,aarch64-unknown-linux-gnu,)

.PHONY: build-linux-x86_64-musl
build-linux-x86_64-musl: ## Build for Linux x86_64 (musl)
	$(call check_target,x86_64-unknown-linux-musl)
	$(call build_target,x86_64-unknown-linux-musl)
	$(call copy_binary,x86_64-unknown-linux-musl,)

.PHONY: build-linux-aarch64-musl
build-linux-aarch64-musl: ## Build for Linux ARM64 (musl)
	$(call check_target,aarch64-unknown-linux-musl)
	$(call build_target,aarch64-unknown-linux-musl)
	$(call copy_binary,aarch64-unknown-linux-musl,)

# macOS builds
.PHONY: build-macos-x86_64
build-macos-x86_64: ## Build for macOS x86_64
	$(call check_target,x86_64-apple-darwin)
	$(call build_target,x86_64-apple-darwin)
	$(call copy_binary,x86_64-apple-darwin,)

.PHONY: build-macos-aarch64
build-macos-aarch64: ## Build for macOS ARM64
	$(call check_target,aarch64-apple-darwin)
	$(call build_target,aarch64-apple-darwin)
	$(call copy_binary,aarch64-apple-darwin,)

# Windows builds
.PHONY: build-windows-x86_64-gnu
build-windows-x86_64-gnu: ## Build for Windows x86_64 (GNU)
	$(call check_target,x86_64-pc-windows-gnu)
	$(call build_target,x86_64-pc-windows-gnu)
	$(call copy_binary,x86_64-pc-windows-gnu,.exe)

.PHONY: build-windows-x86_64-msvc
build-windows-x86_64-msvc: ## Build for Windows x86_64 (MSVC)
	$(call check_target,x86_64-pc-windows-msvc)
	$(call build_target,x86_64-pc-windows-msvc)
	$(call copy_binary,x86_64-pc-windows-msvc,.exe)

.PHONY: build-windows-aarch64-msvc
build-windows-aarch64-msvc: ## Build for Windows ARM64 (MSVC)
	$(call check_target,aarch64-pc-windows-msvc)
	$(call build_target,aarch64-pc-windows-msvc)
	$(call copy_binary,aarch64-pc-windows-msvc,.exe)

# ============================================================================
# BATCH BUILDS
# ============================================================================

.PHONY: build-linux
build-linux: ## Build for all Linux targets
	@echo "Building for all Linux targets..."
	@$(MAKE) build-linux-x86_64
	@$(MAKE) build-linux-aarch64
	@$(MAKE) build-linux-x86_64-musl
	@$(MAKE) build-linux-aarch64-musl
	@echo "Linux builds complete"

.PHONY: build-macos
build-macos: ## Build for all macOS targets
	@echo "Building for all macOS targets..."
	@$(MAKE) build-macos-x86_64
	@$(MAKE) build-macos-aarch64
	@echo "macOS builds complete"

.PHONY: build-windows
build-windows: ## Build for all Windows targets
	@echo "Building for all Windows targets..."
	@$(MAKE) build-windows-x86_64-gnu
	@$(MAKE) build-windows-x86_64-msvc
	@$(MAKE) build-windows-aarch64-msvc
	@echo "Windows builds complete"

.PHONY: build-all
build-all: ## Build for all targets
	@echo "Building for all targets..."
	@$(MAKE) build-linux
	@$(MAKE) build-macos
	@$(MAKE) build-windows
	@echo "All builds complete"

# ============================================================================
# PACKAGING
# ============================================================================

.PHONY: package
package: build-all ## Create distribution packages
	@echo "Creating distribution packages..."
	@mkdir -p $(DIST_DIR)/packages
	@echo "Creating README for distribution..."
	@echo "# Ramparts v$(VERSION) - Multi-Architecture Builds" > $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "This directory contains pre-built binaries for multiple platforms and architectures." >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "## Available Binaries" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "### Linux" >> $(DIST_DIR)/README.md
	@echo "- \`ramparts-x86_64-unknown-linux-gnu\` - Linux x86_64 (GNU)" >> $(DIST_DIR)/README.md
	@echo "- \`ramparts-aarch64-unknown-linux-gnu\` - Linux ARM64 (GNU)" >> $(DIST_DIR)/README.md
	@echo "- \`ramparts-x86_64-unknown-linux-musl\` - Linux x86_64 (musl)" >> $(DIST_DIR)/README.md
	@echo "- \`ramparts-aarch64-unknown-linux-musl\` - Linux ARM64 (musl)" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "### macOS" >> $(DIST_DIR)/README.md
	@echo "- \`ramparts-x86_64-apple-darwin\` - macOS x86_64" >> $(DIST_DIR)/README.md
	@echo "- \`ramparts-aarch64-apple-darwin\` - macOS ARM64" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "### Windows" >> $(DIST_DIR)/README.md
	@echo "- \`ramparts-x86_64-pc-windows-gnu.exe\` - Windows x86_64 (GNU)" >> $(DIST_DIR)/README.md
	@echo "- \`ramparts-x86_64-pc-windows-msvc.exe\` - Windows x86_64 (MSVC)" >> $(DIST_DIR)/README.md
	@echo "- \`ramparts-aarch64-pc-windows-msvc.exe\` - Windows ARM64 (MSVC)" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "## Installation" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "1. Download the appropriate binary for your platform" >> $(DIST_DIR)/README.md
	@echo "2. Make it executable (Linux/macOS): \`chmod +x ramparts-*\`" >> $(DIST_DIR)/README.md
	@echo "3. Move to a directory in your PATH: \`sudo mv ramparts-* /usr/local/bin/\`" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "## Usage" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "\`\`\`bash" >> $(DIST_DIR)/README.md
	@echo "# Basic scan" >> $(DIST_DIR)/README.md
	@echo "ramparts scan http://localhost:3000" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "# Start microservice" >> $(DIST_DIR)/README.md
	@echo "ramparts server --port 3000" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "# Get help" >> $(DIST_DIR)/README.md
	@echo "ramparts --help" >> $(DIST_DIR)/README.md
	@echo "\`\`\`" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "## Build Information" >> $(DIST_DIR)/README.md
	@echo "" >> $(DIST_DIR)/README.md
	@echo "- **Version**: $(VERSION)" >> $(DIST_DIR)/README.md
	@echo "- **Rust Version**: $(RUST_VERSION)" >> $(DIST_DIR)/README.md
	@echo "- **Build Date**: $(shell date -u +"%Y-%m-%d %H:%M:%S UTC")" >> $(DIST_DIR)/README.md
	@echo "- **Author**: $(AUTHOR)" >> $(DIST_DIR)/README.md
	@echo "Creating SHA256 checksums..."
	@cd $(BIN_DIR) && sha256sum * > ../checksums.txt
	@echo "Packaging complete"

.PHONY: package-linux
package-linux: build-linux ## Create Linux distribution package
	@echo "Creating Linux distribution package..."
	@mkdir -p $(DIST_DIR)/packages
	@tar -czf $(DIST_DIR)/packages/ramparts-$(VERSION)-linux.tar.gz -C $(BIN_DIR) \
		ramparts-x86_64-unknown-linux-gnu \
		ramparts-aarch64-unknown-linux-gnu \
		ramparts-x86_64-unknown-linux-musl \
		ramparts-aarch64-unknown-linux-musl
	@echo "Linux package created: $(DIST_DIR)/packages/ramparts-$(VERSION)-linux.tar.gz"

.PHONY: package-macos
package-macos: build-macos ## Create macOS distribution package
	@echo "Creating macOS distribution package..."
	@mkdir -p $(DIST_DIR)/packages
	@tar -czf $(DIST_DIR)/packages/ramparts-$(VERSION)-macos.tar.gz -C $(BIN_DIR) \
		ramparts-x86_64-apple-darwin \
		ramparts-aarch64-apple-darwin
	@echo "macOS package created: $(DIST_DIR)/packages/ramparts-$(VERSION)-macos.tar.gz"

.PHONY: package-windows
package-windows: build-windows ## Create Windows distribution package
	@echo "Creating Windows distribution package..."
	@mkdir -p $(DIST_DIR)/packages
	@cd $(BIN_DIR) && zip -r ../packages/ramparts-$(VERSION)-windows.zip \
		ramparts-x86_64-pc-windows-gnu.exe \
		ramparts-x86_64-pc-windows-msvc.exe \
		ramparts-aarch64-pc-windows-msvc.exe
	@echo "Windows package created: $(DIST_DIR)/packages/ramparts-$(VERSION)-windows.zip"

# ============================================================================
# DEVELOPMENT TARGETS
# ============================================================================

.PHONY: dev-setup
dev-setup: ## Setup development environment
	@echo "Setting up development environment..."
	@$(RUSTUP) update
	@$(RUSTUP) component add rustfmt clippy
	@echo "Development setup complete"

.PHONY: install-targets
install-targets: ## Install all target toolchains
	@echo "Installing target toolchains..."
	@for target in $(ALL_TARGETS); do \
		echo "Installing $$target..."; \
		$(RUSTUP) target add $$target; \
	done
	@echo "Target installation complete"

.PHONY: coverage
coverage: ## Run code coverage with tarpaulin (Linux only)
	@echo "Running code coverage (Linux only, requires cargo-tarpaulin)..."
	@which cargo-tarpaulin > /dev/null || cargo install cargo-tarpaulin
	@cargo tarpaulin --all-features --out Html --output-dir coverage
	@echo "Coverage report generated in coverage/"

.PHONY: integration-test
integration-test: ## Run integration tests (CLI, config, server startup)
	@echo "Running integration tests..."
	@cargo build --release
	@./target/release/$(PROJECT_NAME) --help
	@./target/release/$(PROJECT_NAME) init-config --force
	@echo "Testing server startup and shutdown..."
	@# Start server in background and capture PID
	@./target/release/$(PROJECT_NAME) server --port 3000 & SERVER_PID=$$!; \
		echo "Server started with PID: $$SERVER_PID"; \
		# Wait for server to start (max 10 seconds)
		sleep 2; \
		# Test if server is responding
		if curl -s http://localhost:3000/v1/ramparts/health > /dev/null 2>&1; then \
			echo "✅ Server is responding on port 3000"; \
		else \
			echo "❌ Server not responding on port 3000"; \
			exit 1; \
		fi; \
		# Kill server gracefully
		kill $$SERVER_PID 2>/dev/null || true; \
		# Wait for graceful shutdown (max 5 seconds)
		for i in 1 2 3 4 5; do \
			if ! kill -0 $$SERVER_PID 2>/dev/null; then \
				echo "✅ Server shutdown gracefully"; \
				break; \
			fi; \
			sleep 1; \
		done; \
		# Force kill if still running
		if kill -0 $$SERVER_PID 2>/dev/null; then \
			echo "⚠️  Force killing server process"; \
			kill -9 $$SERVER_PID 2>/dev/null || true; \
		fi; \
		# Clean up any remaining processes
		pkill -f "$(PROJECT_NAME) server" 2>/dev/null || true
	@echo "Integration tests complete"

.PHONY: ci-check
ci-check: ## Run all CI quality checks (format, clippy, tests, audit)
	@echo "🔍 Running CI quality checks..."
	@echo ""
	@echo "📝 Checking code formatting..."
	@$(CARGO) fmt --all -- --check || (echo "❌ Code formatting check failed. Run 'make fmt' to fix." && exit 1)
	@echo "✅ Code formatting check passed"
	@echo ""
	@echo "🔍 Running clippy linting (strict gate)..."
	@$(CARGO) clippy --all-features --all-targets -- $(CLIPPY_STRICT_FLAGS) || (echo "❌ Clippy check failed. Fix the warnings above." && exit 1)
	@echo "✅ Clippy check passed"
	@echo ""
	@echo "🧪 Running tests..."
	@$(CARGO) test --all-features || (echo "❌ Tests failed." && exit 1)
	@echo "✅ Tests passed"
	@echo ""
	@echo "🔒 Auditing dependencies..."
	@$(CARGO) audit || (echo "❌ Security audit failed." && exit 1)
	@echo "✅ Security audit passed"
	@echo ""
	@echo "🎉 All CI checks passed! Ready for PR."

.PHONY: ci-quality
ci-quality: fmt-check check lint test audit ## Run all CI quality checks
	@echo "All CI quality checks complete"

.PHONY: verify
verify: check test lint ## Run all verification steps
	@echo "All verification steps complete"

.PHONY: release
release: clean verify build-all package ## Create a complete release
	@echo "Release build complete"
	@echo "Distribution files available in: $(DIST_DIR)"

# ============================================================================
# UTILITY TARGETS
# ============================================================================

.PHONY: list-targets
list-targets: ## List all available targets
	@echo "Available targets:"
	@echo "  Linux:"
	@for target in $(LINUX_TARGETS); do \
		echo "    $$target"; \
	done
	@echo "  macOS:"
	@for target in $(MACOS_TARGETS); do \
		echo "    $$target"; \
	done
	@echo "  Windows:"
	@for target in $(WINDOWS_TARGETS); do \
		echo "    $$target"; \
	done

.PHONY: info
info: ## Show build information
	@echo "Ramparts Build Information"
	@echo "========================="
	@echo "Project: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Author: $(AUTHOR)"
	@echo "Rust Version: $(RUST_VERSION)"
	@echo "Build Directory: $(BUILD_DIR)"
	@echo "Distribution Directory: $(DIST_DIR)"
	@echo ""
	@echo "Current System:"
	@echo "  OS: $(HOST_OS)"
	@echo "  Architecture: $(HOST_ARCH)"
	@echo "  Target: $(CURRENT_TARGET)"
	@echo ""
	@echo "Available targets: $(words $(ALL_TARGETS))"
	@echo "Linux targets: $(words $(LINUX_TARGETS))"
	@echo "macOS targets: $(words $(MACOS_TARGETS))"
	@echo "Windows targets: $(words $(WINDOWS_TARGETS))"

.PHONY: size
size: build-all ## Show binary sizes
	@echo "Binary sizes:"
	@for binary in $(BIN_DIR)/*; do \
		if [ -f "$$binary" ]; then \
			size=$$(stat -f%z "$$binary" 2>/dev/null || stat -c%s "$$binary" 2>/dev/null || echo "unknown"); \
			echo "  $$(basename $$binary): $$size bytes"; \
		fi; \
	done

# ============================================================================
# DOCKER SUPPORT
# ============================================================================

.PHONY: docker-build
docker-build: ## Build using Docker (requires Dockerfile)
	@if [ -f Dockerfile ]; then \
		echo "Building with Docker..."; \
		docker build -t $(PROJECT_NAME):$(VERSION) .; \
		echo "Docker build complete"; \
	else \
		echo "Dockerfile not found. Creating basic Dockerfile..."; \
		echo "FROM rust:1.75 as builder" > Dockerfile; \
		echo "WORKDIR /app" >> Dockerfile; \
		echo "COPY . ." >> Dockerfile; \
		echo "RUN cargo build --release" >> Dockerfile; \
		echo "" >> Dockerfile; \
		echo "FROM debian:bookworm-slim" >> Dockerfile; \
		echo "RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*" >> Dockerfile; \
		echo "COPY --from=builder /app/target/release/ramparts /usr/local/bin/" >> Dockerfile; \
		echo "EXPOSE 3000" >> Dockerfile; \
		echo "CMD [\"ramparts\", \"server\"]" >> Dockerfile; \
		echo "Dockerfile created. Run 'make docker-build' again."; \
	fi

.PHONY: docker-run
docker-run: ## Run with Docker
	@echo "Running with Docker..."
	@docker run -p 3000:3000 $(PROJECT_NAME):$(VERSION) server --port 3000

# ============================================================================
# CI/CD SUPPORT
# ============================================================================

.PHONY: ci-build
ci-build: ## CI/CD build target
	@echo "Running CI build..."
	@$(MAKE) clean
	@$(MAKE) verify
	@$(MAKE) build-all
	@$(MAKE) package
	@echo "CI build complete"

.PHONY: ci-test
ci-test: ## CI/CD test target
	@echo "Running CI tests..."
	@$(MAKE) check
	@$(MAKE) test
	@$(MAKE) lint
	@echo "CI tests complete"

# ============================================================================
# CLEANUP
# ============================================================================

.PHONY: distclean
distclean: clean ## Deep clean including distribution files
	@echo "Performing deep clean..."
	@rm -rf $(DIST_DIR)
	@rm -rf target
	@echo "Deep clean complete"

.PHONY: help-targets
help-targets: ## Show help for specific target builds
	@echo "Target-specific build commands:"
	@echo ""
	@echo "Current Architecture (Auto-detected):"
	@echo "  make build                    # Build for current architecture"
	@echo ""
	@echo "Linux:"
	@echo "  make build-linux-x86_64      # Linux x86_64 (GNU)"
	@echo "  make build-linux-aarch64     # Linux ARM64 (GNU)"
	@echo "  make build-linux-x86_64-musl # Linux x86_64 (musl)"
	@echo "  make build-linux-aarch64-musl# Linux ARM64 (musl)"
	@echo "  make build-linux             # All Linux targets"
	@echo ""
	@echo "macOS:"
	@echo "  make build-macos-x86_64      # macOS x86_64"
	@echo "  make build-macos-aarch64     # macOS ARM64"
	@echo "  make build-macos             # All macOS targets"
	@echo ""
	@echo "Windows:"
	@echo "  make build-windows-x86_64-gnu # Windows x86_64 (GNU)"
	@echo "  make build-windows-x86_64-msvc# Windows x86_64 (MSVC)"
	@echo "  make build-windows-aarch64-msvc# Windows ARM64 (MSVC)"
	@echo "  make build-windows           # All Windows targets"
	@echo ""
	@echo "Packaging:"
	@echo "  make package-linux           # Linux distribution package"
	@echo "  make package-macos           # macOS distribution package"
	@echo "  make package-windows         # Windows distribution package"
	@echo "  make package                 # All packages" 
