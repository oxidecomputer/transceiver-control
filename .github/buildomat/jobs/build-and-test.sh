#!/bin/bash
#:
#: name = "build-and-test (helios)"
#: variety = "basic"
#: target = "helios-latest"
#: rust_toolchain = "1.66"
#: output_rules = []
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

banner "fmt"
ptime -m cargo fmt -- --check

banner "no std chk"
ptime -m cargo check --no-default-features

banner "test"
ptime -m cargo test --all-targets
