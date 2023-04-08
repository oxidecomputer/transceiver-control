#!/bin/bash
#:
#: name = "bins"
#: variety = "basic"
#: target = "helios-latest"
#: rust_toolchain = "stable"
#: output_rules = [
#:	"=/out/xcvradm.gz",
#:	"=/out/xcvradm.sha256.txt",
#:	"=/out/xcvradm.gz.sha256.txt",
#: ]
#:
#: [[publish]]
#: from_output = "/out/xcvradm.gz"
#: series = "bins"
#: name = "xcvradm.gz"
#:
#: [[publish]]
#: from_output = "/out/xcvradm.gz.sha256.txt"
#: series = "bins"
#: name = "xcvradm.gz.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

pfexec mkdir -p /out
pfexec chown "$LOGNAME" /out

banner build
ptime -m cargo build --release --locked --bin xcvradm

banner output
mv target/release/xcvradm /out/xcvradm
digest -a sha256 /out/xcvradm > /out/xcvradm.sha256.txt
gzip /out/xcvradm
digest -a sha256 /out/xcvradm.gz > /out/xcvradm.gz.sha256.txt
