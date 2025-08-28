PLC Secure Coding Practices Checker
plc_practices_checker is a command-line static analysis tool written in Rust to automatically check Programmable Logic Controller (PLC) source code against the "Top 20 Secure PLC Coding Practices." It helps developers and automation engineers identify and mitigate common security vulnerabilities in their industrial control system logic before deployment.

The tool parses PLC source files, builds an Abstract Syntax Tree (AST), and runs a series of rule-based checks to find potential security flaws.

Key Features
Static Analysis: Checks PLC code without needing to run it on actual hardware.

Multi-Language Support: Parses multiple common PLC programming languages.

Comprehensive Rule Set: Implements a significant portion of the Top 20 Secure PLC Coding Practices.

Policy-Driven Checks: Allows for custom, site-specific rules via an optional policy.json file.

Clear, Actionable Output: Reports violations with the rule number, line number, a clear reason, and a suggestion for remediation.

Command-Line Interface: Easy to integrate into automated workflows and CI/CD pipelines.

Supported PLC Languages
The checker currently supports the following PLC source file formats:

Siemens SCL (.scl, .st): Structured Control Language, a high-level, Pascal-like language.

PLCOpen XML (.xml): A standard, vendor-neutral format for exporting PLC projects, including logic from graphical languages like FBD and LD.

Instruction List (.il, .awl): A low-level, assembly-like language.

Implemented Security Rules
This tool checks for the following secure coding practices:

Rule 1: Modularize PLC Code (Checks for excessive complexity)

Rule 2: Track Operating Modes

Rule 4: Use PLC Flags as Integrity Checks (for division)

Rule 5: Use Checksum Integrity Checks

Rule 6: Validate Timers and Counters

Rule 7: Validate Paired Inputs/Outputs (Requires policy.json)

Rule 8: Validate HMI Input Variables

Rule 9: Validate Indirections (Array indexing)

Rule 10: Assign Designated Register Blocks (Requires policy.json)

Rules 11 & 12: Instrument for Plausibility Checks

Rule 15: Define a Safe Process State on Restart

Rule 16: Summarize PLC Cycle Times

Rule 17: Log PLC Uptime

Rule 18: Log PLC Hard Stops

Rule 19: Monitor PLC Memory Usage

Rule 20: Trap False Negatives/Positives for Critical Alerts

Getting Started
Prerequisites
You need to have the Rust toolchain (including cargo) installed on your system.

Building the Project
Clone the repository:

git clone <your-repository-url>
cd plc_practices_checker

Build the project using Cargo:

cargo build --release

The executable will be located at target/release/plc_practices_checker.

Usage
Run the checker from the command line, providing the path to the PLC source file you want to analyze.

./target/release/plc_practices_checker /path/to/your/program.scl

Using a Policy File
For rules that require site-specific configuration (like Rule 7 and Rule 10), you can provide an optional policy file.

./target/release/plc_practices_checker /path/to/your/program.scl --policy /path/to/policy.json

The Policy File
The policy.json file allows you to customize certain rules. If this file is not provided, the rules that depend on it will be skipped.

Example policy.json
{
  "pairs": [
    ["Motor_Fwd", "Motor_Rev"],
    ["Valve_Open", "Valve_Close"]
  ],
  "memory_areas": [
    { "address": "%MW100-%MW200", "access": "ReadOnly" },
    { "address": "%M50-%M80",     "access": "ReadWrite" }
  ]
}

pairs: Used by Rule 7. Defines pairs of signals (e.g., forward and reverse motor commands) that should never be active at the same time.

memory_areas: Used by Rule 10. Defines specific memory regions and their intended access level (e.g., ReadOnly). The tool will flag any write operations to a ReadOnly area.

Example Output
When violations are found, the tool prints a clear report to the console for each failed rule.

##Rule 4: Use PLC flags as integrity checks -- NOT FOLLOWED--Line 192: Division operation without status-word / zero-divisor guard Wrap division inside IF SW.OV=0 AND SW.OS=0 AND divisor<>0 THEN ...
##Rule 8: Validate HMI input variables -- NOT FOLLOWED--Line 100: HMI/DB variable 'HMI_Cut_Speed' used without prior sanitization Precede usage with range-checking IF or plausibility check.
##Rule 15: Define a safe restart state -- NOT FOLLOWED--Line 0: OB100 (Startup OB) not found Add OB100 and initialize outputs to safe state.

If a rule is followed, it is marked as OK.

##Rule 1: Modularize PLC Code -- OK
