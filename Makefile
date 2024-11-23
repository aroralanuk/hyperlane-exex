BUILD_PATH = "target"
# Extra flags for Cargo, if needed.
CARGO_INSTALL_EXTRA_FLAGS ?=

# List of features to use when building.
# No jemalloc on Windows
ifeq ($(OS),Windows_NT)
    FEATURES ?=
else
    FEATURES ?= jemalloc
endif

# Cargo profile for builds. Default is for local builds, CI uses an override.
PROFILE ?= release

# Determine the number of parallel jobs
CARGO_BUILD_JOBS := $(shell nproc)

##@ Build

.PHONY: install-exex
install-exex: ## Build and install the op-reth binary under `~/.cargo/bin`.
	cargo install --path . --bin hyperlane-reth --force --locked \
		--profile "$(PROFILE)" \
		--jobs $(CARGO_BUILD_JOBS) \
		$(CARGO_INSTALL_EXTRA_FLAGS)


.PHONY: build-exex
build-exex: ## Build the op-reth binary into `target` directory.
	cargo build --bin hyperlane-reth \
		--profile maxperf \
		--features jemalloc,asm-keccak \
		--jobs $(CARGO_BUILD_JOBS)

.PHONY: lint
lint:
	make fmt && \
	make lint-reth && \
	make lint-op-reth && \
	make lint-workspace

lint-reth:
	cargo +nightly clippy \
		--workspace \
    	--bin "reth" \
       	--features "$(FEATURES)" \
       	--fix \
       	--allow-staged \
       	--allow-dirty \
       	-- -D warnings

lint-op-reth:
	cargo +nightly clippy \
    	--workspace \
    	--bin "op-reth" \
    	--lib \
    	--examples \
    	--tests \
    	--benches \
    	--features "optimism,$(FEATURES)" \
    	-- -D warnings

lint-workspace:
	cargo +nightly clippy \
		--workspace \
		--all-features \
    	-- -D warnings
fmt:
	cargo +nightly fmt

test-reth:
	cargo test --all-features

test-doc:
	cargo test --doc --workspace --features "ethereum"
	cargo test --doc --workspace --features "optimism"

test:
	make test-reth && \
	make test-doc
