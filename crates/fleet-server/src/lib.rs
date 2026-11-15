#![forbid(unsafe_code)]
//! SendBox fleet: the shared governance service for governed sessions.
//!
//! This crate is a scaffold for increment 2 of
//! <https://github.com/mbianchidev/sendbox/issues/87>. It serves health and
//! readiness probes, authenticates every `/v1` request, validates request
//! bodies against the shared `sendbox-governance` contract, and answers every
//! management operation with an explicit `501 Not Implemented` problem.

pub mod auth;
pub mod config;
pub mod db;
pub mod logging;
pub mod problem;
pub mod routes;
pub mod server;

pub use sendbox_governance::CONTRACT_VERSION;
