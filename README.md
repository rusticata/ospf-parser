# ospf-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/ospf-parser.svg?branch=master)](https://travis-ci.org/rusticata/ospf-parser)
[![Crates.io Version](https://img.shields.io/crates/v/ospf-parser.svg)](https://crates.io/crates/ospf-parser)

<!-- cargo-sync-readme start -->

# OSPFv2 and OSPFv3 Parser

A parser for the Open Shortest Path First version 2 ([OSPFv2]) and OSPF for IPv6
(also known as [OSPFv3]) routing protocols,
implemented with the [nom](https://github.com/Geal/nom) parser combinator
framework in pure Rust.

The code is available on [Github](https://github.com/rusticata/ospf-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

[OSPFv2]: https://tools.ietf.org/html/rfc2328 "OSPF Version 2, RFC 2328"
[OSPFv3]: https://tools.ietf.org/html/rfc5340 "OSPF for IPv6, RFC 5340"

<!-- cargo-sync-readme end -->

## Changes

### 0.3.0

- Update to nom-derive 0.7 / nom 6

### 0.2.0

- Add support for OSPFv2 Opaque LSA (RFC5250)
- Upgrade to nom-derive 0.6 and fix some Verify errors

### 0.1.0

- Initial release

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
