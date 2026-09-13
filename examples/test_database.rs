//! Offline template database maintenance for the integration suite (#710).
//!
//! Usage (the shell owns dotenv loading; this binary never mutates the
//! environment):
//!
//! ```text
//! test_database prepare    # create + migrate + freeze the template
//! test_database cleanup    # drop the template and every clone in the namespace
//! ```
//!
//! The only arguments are exactly one of `prepare` or `cleanup`; there are no
//! arbitrary database arguments. Errors are printed through [`DbTestError`]'s
//! sanitized `Display`, and cleanup prints only counts.

#[path = "../tests/support/template_database/mod.rs"]
mod template_database;

use chenxing_auth::db::test_timing::{self, Outcome, Timing};
use template_database::TemplateConfig;

#[tokio::main]
async fn main() {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    let command = arguments.next();
    if arguments.next().is_some() {
        usage();
    }
    let command = match command.as_deref() {
        Some("prepare") => "prepare",
        Some("cleanup") => "cleanup",
        _ => usage(),
    };

    let mut timing = Timing::from_env();
    let config = match TemplateConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("test_database: {error}");
            std::process::exit(1);
        }
    };

    if command == "prepare" {
        // Time the complete prepare operation.
        let phase = timing.phase_start();
        let result = config.prepare().await;
        timing.record(test_timing::PHASE_TEMPLATE_PREPARE, phase);
        match result {
            Ok(()) => {
                timing
                    .emit_template_prepare("test_database", "prepare", Outcome::Ok)
                    .await;
            }
            Err(error) => {
                timing
                    .emit_template_prepare("test_database", "prepare", Outcome::Error)
                    .await;
                eprintln!("test_database: prepare failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }

    match config.cleanup().await {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("test_database: cleanup failed: {error}");
            std::process::exit(1);
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: test_database prepare|cleanup");
    std::process::exit(2);
}
