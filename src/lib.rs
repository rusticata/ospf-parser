//! # OSPFv2 Parser
//!
//! A parser for the Open Shortest Path First version 2 ([OSPFv2]) routing protocol,
//! implemented with the [nom](https://github.com/Geal/nom) parser combinator
//! framework.
//!
//! The code is available on [Github](https://github.com/rusticata/ospf-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! [OSPFv2]: https://tools.ietf.org/html/rfc2328 "OSPF Version 2, RFC 2328"

pub extern crate nom;

mod ospf;
mod parser;

pub use ospf::*;
pub use parser::*;
