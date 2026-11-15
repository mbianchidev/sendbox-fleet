#![forbid(unsafe_code)]
//! SendBox fleet: the shared governance service for governed sessions.
//!
//! Increment 2 of <https://github.com/mbianchidev/sendbox/issues/87>: an
//! authenticated, multi-user management API and shared grant authority.
//! It enforces project-scoped roles, admits governed sessions, issues and
//! checks credential grants, records bounded, expiring exceptions, and keeps a
//! hash-chained central audit log. It never holds provider credentials.

pub mod admin;
pub mod audit;
pub mod auth;
pub mod config;
pub mod db;
pub mod governance;
pub mod logging;
pub mod problem;
pub mod routes;
pub mod server;
pub mod state;

pub use sendbox_governance::CONTRACT_VERSION;
