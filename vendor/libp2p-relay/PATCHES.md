# Local patch: libp2p-relay 0.22.0

Source: crates.io `libp2p-relay` 0.22.0 (MIT), upstream
<https://github.com/libp2p/rust-libp2p>, revision
`7171dce2f90c05ba7892d4ba926abb1881db27c7`, `protocols/relay`.
Original source, upstream tests, manifests, standalone lock and VCS metadata are
retained. `LICENSE` reproduces the original source MIT notice.

The relay server tracks every connection, including auxiliary connections that
never reserved a circuit. Upstream emitted `ReservationClosed` whenever any
tracked connection closed, even when that connection's reservation state was
`None`. A live reservation on another connection from the same peer remained
active, but consumers of the public peer-only event could incorrectly clear it
from their status/accounting.

The local change emits `ReservationClosed` only when the closed connection had an
active reservation. Normal active-reservation closure and renewal still emit
exactly one closure event. No relay admission, quota, wire or cryptographic
protocol is changed. Two unit regressions cover auxiliary close with another live
reservation, and one closure after renewal despite repeated/auxiliary close events.

Run this crate's standalone tests, formatting and all-target strict Clippy in
addition to application checks; root package tests do not execute dependency
unit tests. Original retained upstream integration tests remain enabled.

The packaged manifest omitted its upstream workspace-only `quickcheck-ext` dev
dependency. Restored the standard `quickcheck = "1"` dev dependency used by that
wrapper: retained tests use only its unmodified `QuickCheck` and `TestResult`
re-exports. The standalone lock includes those test dependencies. Runtime
dependencies and retained upstream test logic are unchanged.
