# Third-party notices

The project's original code is licensed under GPL-3.0-or-later. This does not
replace the separate licenses of third-party components.

Vendored components retain their upstream copyright/license notices and their
original licensing. Each vendored directory includes a `LICENSE`, dependency
metadata and `PATCHES.md` describing the local changes:

- `vendor/libp2p-mdns` — MIT, copyright 2018 Parity Technologies (UK) Ltd.
- `vendor/libp2p-rendezvous` — MIT, copyright 2021 COMIT Network.
- `vendor/libp2p-autonat` — MIT, copyright 2021 Protocol Labs.
- `vendor/libp2p-dcutr` — MIT, copyright 2021 Protocol Labs.

Registry dependencies and their transitive dependencies retain the licenses
specified by their package metadata and distributed license files. `Cargo.lock`
pins the source versions; this repository does not include their compiled code.
Redistributors of binaries must preserve the applicable dependency notices.
