//! # OSPFv2 and OSPFv3 Parser
//!
//! A parser for the Open Shortest Path First version 2 ([OSPFv2]) and OSPF for IPv6
//! (also known as [OSPFv3]) routing protocols,
//! implemented with the [nom](https://github.com/Geal/nom) parser combinator
//! framework in pure Rust.
//!
//! The code is available on [Github](https://github.com/rusticata/ospf-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! [OSPFv2]: https://tools.ietf.org/html/rfc2328 "OSPF Version 2, RFC 2328"
//! [OSPFv3]: https://tools.ietf.org/html/rfc5340 "OSPF for IPv6, RFC 5340"

#![deny(/*missing_docs,*/
        unstable_features,
        unused_import_braces, unused_qualifications)]
#![forbid(unsafe_code)]

pub extern crate nom;

mod ospfv2;
mod ospfv3;
mod parser;

pub use ospfv2::*;
pub use ospfv3::*;
pub use parser::*;
