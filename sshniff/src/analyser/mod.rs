//! The core of SSH packet and traffic analysis.
//! Leverage metadata like packet sizes and timing to classify packets and create session context.
pub mod utils;
pub mod core;
pub mod scan;
pub mod containers;
