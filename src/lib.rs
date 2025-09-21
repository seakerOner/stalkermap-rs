//! # StalkerMap Core
//!
//! This crate provides a small input sanitation and validation framework
//! for interactive CLI applications.  
//!
//! The main idea is that you can define **filters** (`Sanatize`) that are applied
//! to user input in a loop, until the input matches all constraints.  
//!
//! ## Features
//! - Type validation for common Rust primitives (`u8`, `i32`, `bool`, etc.).
//! - Exact string matching.
//! - Matching against multiple allowed string options.
//! - Custom error messages via `FilterErrorMessage`.
//!
//! ## Example
//! ```rust,no_run
//! use stalkermap_core::{Terminal, Sanatize, DesiredType};
//!
//! let input = Terminal::ask(
//!     "Enter a number between 1 and 10:",
//!     vec![Sanatize::IsType(DesiredType::U8)],
//! );
//! println!("You entered: {}", input.answer);
//! ```

pub mod utils;
