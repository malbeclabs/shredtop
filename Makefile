.PHONY: help fmt fmt-check clippy check build release test ci clean

help:
	@awk 'BEGIN{FS=":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt: ## Format all crates
	cargo fmt --all

fmt-check: ## Check formatting (CI)
	cargo fmt --all -- --check

clippy: ## Lint with clippy, warnings as errors
	cargo clippy --workspace --all-targets -- -D warnings

check: ## Fast type-check (works on macOS)
	cargo check --workspace --all-targets

build: ## Debug build (Linux x86_64)
	cargo build --workspace

release: ## Release build (Linux x86_64)
	cargo build --workspace --release

test: ## Run tests
	cargo test --workspace --all-targets --locked

ci: fmt-check clippy test ## Run the same checks CI runs

clean: ## Remove target/
	cargo clean
