//! Tattle: a receipt of what your AI coding agents did to your machine.
//!
//! Reads local Claude Code and Codex logs, read-only and offline. Only
//! commands, file paths and tool names are used; prompts, replies and tool
//! output are never read. Secrets are masked before anything is shown.

pub mod demo;
pub mod detect;
pub mod html;
pub mod logs;
pub mod report;
pub mod rules;
pub mod shell;
pub mod term;
pub mod time;
