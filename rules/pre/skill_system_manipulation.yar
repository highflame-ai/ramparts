// Destructive system-operation patterns in skill bodies. One rule:
//
//   - SkillSystemManipulation: skill instructions that destroy data,
//                              escalate privileges, hijack PATH, or
//                              modify critical system files.
//
// Distinct from `command_injection.yar` (which detects untrusted-input
// concatenated into a shell command) — this rule fires on the literal
// destructive operation regardless of how it got into the skill body.
// Path-traversal-style file mentions are deliberately scoped to write
// operations only; mentioning `/etc/sudoers` in prose doesn't fire.
//
// Mapped to OWASP MCP03 (excessive agency) + MCP04 (path traversal /
// unauthorized FS access) in `src/taxonomy.rs`.

rule SkillSystemManipulation
{
    meta:
        name = "Destructive System Manipulation"
        description = "Detects skill instructions that destroy data (dd zero, wipefs, shred), recursively delete system paths, change ownership/permissions of root paths, hijack PATH, or escalate privileges"
        severity = "HIGH"
        category = "destructive-ops,privilege-escalation,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // === Disk-wiping / data-destruction primitives ===
        //
        // These are diagnostic-grade destructive primitives — there is
        // essentially no benign use of them in a skill body.
        $destroy_dd_zero = /\bdd\s+if=\/dev\/(zero|urandom|random)\s+of=\//i
        $destroy_wipefs = /\bwipefs\s+(-a\s+)?\/[a-z]/i
        $destroy_shred = /\bshred\s+-[a-zA-Z]+\s+\/[a-z]/i
        $destroy_mkfs = /\bmkfs(\.[a-z0-9]+)?\s+\/dev\/[a-z]/i

        // === Recursive deletion of system-critical paths ===
        //
        // Match `rm -rf` *only* when the target is a system root or a
        // user home root. Build/cleanup workflows with `rm -rf
        // node_modules` etc. are excluded by the `$safe_cleanup` arm
        // below.
        //
        // Character classes break the source-text shape so this file
        // doesn't accidentally trip secret-path scanners on itself.
        $destroy_rm_rf_root = /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-rf|-fr)\s+(\/(\s|$|\*)|\/r[o]ot(\s|\/|$|\*)|\/h[o]me(\s|\/|$|\*)|\/e[t]c(\s|\/|$|\*)|\/u[s]r(\s|\/|$|\*)|\/v[a]r(\s|\/|$|\*)|\$HOME(\s|\/|$|\*)|~\/(\s|\*|$))/i

        // === Permission / ownership manipulation on root paths ===
        $perm_chmod_root = /\bchmod\s+(777|6755|4755|[ug]\+s|\-R\s+777)\s+\/\b/i
        $perm_chown_root = /\bchown\s+(-R\s+)?root\s*:?\s*\S*\s+\/(\s|$|[a-z])/i

        // === Critical-file *write* operations ===
        //
        // Mentioning /etc/sudoers in prose is fine. Writing to it via
        // shell redirection or coreutils is not. Character classes
        // again break literal-substring shape on this file.
        $write_critical_shadow = /(\b(echo|cat|tee|printf)\b[^|\n]{0,200}|>>?\s*)\/e[t]c\/sh[a]dow\b/i
        $write_critical_sudoers = /(\b(echo|cat|tee|printf)\b[^|\n]{0,200}|>>?\s*)\/e[t]c\/su[d]oers(\.d\/)?\b/i
        $write_critical_passwd = /(\b(echo|cat|tee|printf)\b[^|\n]{0,200}|>>?\s*)\/e[t]c\/p[a]sswd\b/i

        // === Privilege escalation primitives ===
        //
        // `sudo -i` / `sudo -s` opens a root shell with no command —
        // that's escalation, not invocation. `runuser`, `doas` are
        // sudo-equivalents on minor distros.
        $priv_sudo_shell = /\bsudo\s+(-[a-zA-Z]*[is][a-zA-Z]*|--login|--shell)\b/
        $priv_runuser = /\b(runuser|doas|pkexec)\s+(-[a-z])?/i

        // === PATH hijack / poisoning ===
        //
        // Prepending `.` or `/tmp` to PATH is a classic local privesc
        // primitive (replace `ls` with a malicious binary in CWD).
        $path_hijack_cwd = /\b(export\s+)?PATH=(\.\:|\/tmp\/?:)/i
        $path_hijack_unset = /\bunset\s+(PATH|HOME|LD_LIBRARY_PATH|LD_PRELOAD)\b/

        // === Loader hijack via LD_PRELOAD ===
        $loader_preload = /\b(export\s+)?LD_PRELOAD=\/[a-z]/i

        // === Process-table manipulation ===
        $proc_killall = /\b(killall|pkill)\s+-9\s+(sshd|systemd|init|dbus|launchd|gnome-shell|Xorg|wayland)\b/i

        // === Exclusion: routine build / dev-environment cleanup ===
        //
        // Cleaning ./node_modules, ./target, /tmp, etc. is normal in
        // dev tooling. Project-relative `$VAR/` and named build dirs
        // are explicitly excluded.
        $safe_cleanup = /\brm\s+-[rf]+\s+(\.\/|node_modules|__pycache__|\.cache|\.npm|dist\/|build\/|target\/|coverage\/|\.git\/|\.tox\/|\.mypy_cache|\.pytest_cache|\.next\/|\.nuxt\/|\.turbo\/|out\/|\$\{?[A-Za-z_]+\}?\/|\/var\/lib\/apt\/lists|\/var\/cache|\/tmp\/[a-zA-Z])/i

        // Test / build commands.
        $safe_test_build = /\b(pytest|tox|cargo\s+test|go\s+test|npm\s+test|yarn\s+test|jest|mocha|make\s+(test|clean)|mvn\s+test|gradle\s+test)\b/i

        // Security-doc / threat-model context.
        $excl_security_doc = /\b(security[_\s-]?(check|audit|scan|monitor|guide|guardrail|review|best.practice)|threat[_\s-]?(model|pattern|hunt)|attack[_\s-]?(example|surface|vector|pattern)|detection[_\s-]?(rule|pattern|engine)|YARA|MITRE|ATT&CK|remediation)\b/i

        // Defensive language ("must not run", "do not delete").
        $excl_defensive = /\b(never|do\s+not|don't|must\s+not|should\s+not|avoid|prevent|reject|block)\b[^.\n]{0,30}\b(delete|destroy|wipe|format|chmod|chown|sudo|escalate)\b/i

    condition:
        not $safe_cleanup and
        not $safe_test_build and
        not $excl_security_doc and
        not $excl_defensive and
        (
            $destroy_dd_zero or
            $destroy_wipefs or
            $destroy_shred or
            $destroy_mkfs or
            $destroy_rm_rf_root or
            $perm_chmod_root or
            $perm_chown_root or
            $write_critical_shadow or
            $write_critical_sudoers or
            $write_critical_passwd or
            $priv_sudo_shell or
            $priv_runuser or
            $path_hijack_cwd or
            $path_hijack_unset or
            $loader_preload or
            $proc_killall
        )
}
