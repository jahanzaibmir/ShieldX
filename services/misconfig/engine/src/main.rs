/**
 * ShieldX Analysis Engine v2.0
 * Ultimate SOC-Grade Security Analysis
 */

mod models;
mod analysis;
mod scoring;
mod reporter;

use std::env;
use std::fs;
use std::process;
use colored::Colorize;

fn main() {
    print_banner();
    
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("{}", "Usage: shieldx-engine <state.json>".red());
        eprintln!("{}", "   or: shieldx-engine --scan --input <state.json>".yellow());
        process::exit(1);
    }
    
    // Handle different argument formats
    let input_file = if args.len() == 2 {
        &args[1]
    } else if args.contains(&"--input".to_string()) {
        let idx = args.iter().position(|x| x == "--input").unwrap();
        if idx + 1 >= args.len() {
            eprintln!("{}", "Error: --input requires a file path".red());
            process::exit(1);
        }
        &args[idx + 1]
    } else {
        &args[args.len() - 1]
    };
    
    println!("{} {}", "📊 Analyzing:".cyan().bold(), input_file);
    
    // Read input file
    let content = match fs::read_to_string(input_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {}", "Error reading file:".red().bold(), e);
            process::exit(1);
        }
    };
    
    // Parse collector data
    let collector_data: models::CollectorData = match serde_json::from_str(&content) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{} {}", "JSON parsing failed:".red().bold(), e);
            eprintln!("{}", "Note: Make sure you're using the latest C collector output format".yellow());
            process::exit(1);
        }
    };
    
    println!("{}", "\n🔍 Running Security Analysis...".cyan().bold());
    
    // Run analysis
    let report = analysis::analyze(&collector_data);
    
    // Display report
    reporter::display_report(&report);
    
    // Save detailed report
    let report_json = serde_json::to_string_pretty(&report).unwrap();
    match fs::write("shieldx_report.json", &report_json) {
        Ok(_) => println!("\n{} {}", "✓".green().bold(), "Detailed report saved to shieldx_report.json"),
        Err(e) => eprintln!("{} {}", "Warning: Could not save report:".yellow(), e),
    }
}

fn print_banner() {
    println!("{}", r#"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ██╗  ██╗   ║
║   ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗╚██╗██╔╝   ║
║   ███████╗███████║██║█████╗  ██║     ██║  ██║ ╚███╔╝    ║
║   ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║ ██╔██╗    ║
║   ███████║██║  ██║██║███████╗███████╗██████╔╝██╔╝ ██╗   ║
║   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝   ║
║                                                           ║
║        🛡️  Advanced Security Analysis Engine v2.0        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"#.cyan());
}