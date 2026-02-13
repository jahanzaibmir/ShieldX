# ShieldX Rust Analysis Engine Makefile
# Wraps cargo commands for convenience

.PHONY: all build release debug clean test run install help

# Default target
all: release

# Build release version (optimized)
release:
	@echo [BUILD] Compiling Rust engine (release mode)...
	cargo build --release
	@echo [SUCCESS] Build complete: target\release\shieldx-engine.exe

# Build debug version (faster compilation, with debug symbols)
debug:
	@echo [BUILD] Compiling Rust engine (debug mode)...
	cargo build
	@echo [SUCCESS] Build complete: target\debug\shieldx-engine.exe

# Alias for release
build: release

# Clean build artifacts
clean:
	@echo [CLEAN] Removing build artifacts...
	cargo clean
	@if exist state.json del state.json
	@if exist shieldx_report.json del shieldx_report.json
	@echo [CLEAN] Done!

# Run tests
test:
	@echo [TEST] Running unit tests...
	cargo test

# Run with example state file
run:
	@echo [RUN] Running analysis engine...
	@if exist state.json (.\target\release\shieldx-engine.exe state.json) else (echo Error: state.json not found!)

# Check code without building
check:
	@echo [CHECK] Checking code...
	cargo check

# Format code
fmt:
	@echo [FORMAT] Formatting Rust code...
	cargo fmt

# Run clippy linter
lint:
	@echo [LINT] Running clippy...
	cargo clippy

# Install to system (copy to parent directory)
install: release
	@echo [INSTALL] Installing shieldx-engine.exe...
	@copy /Y target\release\shieldx-engine.exe ..\
	@echo [INSTALL] Done! Installed to parent directory

# Update dependencies
update:
	@echo [UPDATE] Updating dependencies...
	cargo update

# Build documentation
doc:
	@echo [DOC] Building documentation...
	cargo doc --no-deps --open

# Full rebuild
rebuild: clean release

# Help
help:
	@echo ShieldX Rust Engine Makefile
	@echo.
	@echo Available targets:
	@echo   make          - Build release version (default)
	@echo   make release  - Build optimized release version
	@echo   make debug    - Build debug version (faster)
	@echo   make clean    - Remove build artifacts
	@echo   make rebuild  - Clean and rebuild
	@echo   make test     - Run unit tests
	@echo   make run      - Run with state.json
	@echo   make check    - Check code without building
	@echo   make fmt      - Format code
	@echo   make lint     - Run clippy linter
	@echo   make install  - Copy exe to parent directory
	@echo   make update   - Update dependencies
	@echo   make doc      - Build and open documentation
	@echo   make help     - Show this help
	@echo.
	@echo Examples:
	@echo   make clean ^&^& make     - Clean rebuild
	@echo   make test ^&^& make run  - Test then run
