//! Every shipped YARA rule file must compile and define at least one rule.
//!
//! This exists because a non-compiling rule file used to be skipped with a
//! warning, silently removing a whole detection category while scans still
//! reported "passed". It happened for real: a `*/` sequence inside a block
//! comment in `secrets_leakage.yar` terminated the comment early, costing four
//! rules. Nothing failed, nothing was logged at a visible level, and the loss
//! only surfaced when corpus measurement showed the detection rate collapse.
//!
//! The loader now treats a compile failure as a hard error. This test catches
//! it one step earlier, at CI time, and names the offending file.

#[test]
fn every_rule_file_compiles_and_defines_at_least_one_rule() {
    let mut failures = Vec::new();
    let mut checked = 0;

    for entry in std::fs::read_dir("rules/pre").expect("rules/pre must exist") {
        let path = entry.expect("directory entry must be readable").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yar") {
            continue;
        }
        checked += 1;

        let source = std::fs::read_to_string(&path).expect("rule file must be readable");
        let mut compiler = yara_x::Compiler::new();

        match compiler.add_source(source.as_str()) {
            Err(e) => failures.push(format!("{}: {e}", path.display())),
            Ok(_) => {
                let rules = compiler.build();
                if rules.iter().count() == 0 {
                    failures.push(format!(
                        "{}: compiled but defines no rules — a comment or condition \
                         probably swallowed the rule body",
                        path.display()
                    ));
                }
            }
        }
    }

    assert!(checked > 0, "no .yar files found in rules/pre");
    assert!(
        failures.is_empty(),
        "{} of {checked} rule files are broken:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
