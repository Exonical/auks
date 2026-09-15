# auks-spank-sys

Hand-written Rust declarations for the stable, small SPANK ABI in
`slurm/spank.h`. Slurm provides the referenced symbols through the host
executable when it loads a plugin; this crate does not link a Slurm library.
