/*
 * Command Injection Detection Rule
 * 
 * This rule detects various command injection attack patterns including:
 * - Shell command separators and operators
 * - Dangerous system commands
 * - Code execution functions
 * - Evasion techniques (encoding, obfuscation)
 * - Command chaining patterns
 * - File system manipulation commands
 * - Network and process control commands
 * - Privilege escalation attempts
 * 
 * Updated to be more specific and avoid false positives on legitimate tool names
 */

rule CommandInjection
{
    meta:
        name = "Advanced Command Injection Detection"
        author = "Ramparts Security Team"
        date = "2024-07-25"
        version = "2.1"
        description = "Comprehensive command injection detection covering multiple attack vectors and evasion techniques"
        severity = "CRITICAL"
        category = "command-injection,security,code-execution,privilege-escalation,data-exfiltration,reverse-shell,web-shell,evasion-detection"
        confidence = "HIGH"
        
    strings:
        // Dangerous system commands (file operations). Tightened so
        // routine cleanup (`rm -rf node_modules`, `rm -rf target`)
        // doesn't fire — `$rm_rf_dangerous` requires a system-critical
        // target (`/`, `/etc`, `/usr`, `/var`, `/home`, `/root`,
        // `$HOME`, `~/`). `format C:`, `dd if=`, etc. remain because
        // those primitives are diagnostic-grade and benign use is rare.
        $rm_rf_dangerous = /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-rf|-fr)\s+(\/(\s|$|\*)|\/(etc|usr|var|root|home|opt|boot|bin|sbin|lib)(\s|\/|$|\*)|\$HOME(\s|\/|$|\*)|~\/(\s|\*|$))/
        $file_dangerous = /(del\s+.*\/[si]|format\s+[A-Za-z]:|dd\s+if|mkfs|fdisk|wipefs)/i
        $file_manipulation = /(chmod\s+777|chown\s+root|chgrp\s+root|touch\s+.*\.sh|echo\s+.*\>.*\.sh)/

        // Dangerous system commands (process control).
        $process_dangerous = /(kill\s+-9|killall|pkill|kill\s+1|shutdown\s+-h|reboot|halt)/

        // Dangerous system commands (network).
        $network_dangerous = /(nc\s+-l|netcat|telnet|ssh\s+-o|wget\s+.*\||curl\s+.*\||ftp\s+get)/

        // Code execution functions. Each pattern requires a
        // function-call shape (`name(`) so bare-word mentions
        // (`docker exec`, `system halt`, `assert that ...`) don't
        // fire. Case-sensitive lowercase so `.Exec(` (Go ORM) is
        // also excluded.
        $exec_functions = /\b(system|exec|popen|spawn|eval|shell_exec|passthru|proc_open)\s*\(/
        $python_exec = /\b(os\.system|subprocess\.|exec\(|eval\(|compile\(|execfile\(|input\(\))\b/
        $node_exec = /\b(child_process\.|exec\(|spawn\(|execSync\(|spawnSync\(|require\(|eval\(\))\b/
        $php_exec = /\b(shell_exec|exec|system|passthru|proc_open|popen|eval|assert|create_function)\s*\(/
        $java_exec = /\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|ScriptEngine|eval\(|exec\(\))\b/

        // Evasion techniques.
        $encoding_evasion = /(base64\s+-d|base64\s+decode|echo\s+.*\||printf\s+.*\||xxd\s+-r)/
        $obfuscation = /(eval\s+\$|eval\s+`|eval\s+\$\(|eval\s+base64|eval\s+printf)/

        // Command injection patterns (eval/exec/system invoked with a
        // variable expansion). The previous bare-backtick arm
        // (`\`[^`]+\``) matched every markdown inline-code span and
        // produced FPs on every documentation skill. Keep the
        // language-construct + `$` arms, which require an actual eval
        // / exec / system call near a variable to fire.
        $injection_patterns = /(eval\s+.*\$|exec\s+.*\$|system\s+.*\$)/

        // Privilege escalation.
        $privilege_escalation = /(sudo\s+.*|su\s+.*|chmod\s+4755|chmod\s+6755|setuid|setgid)/

        // Data exfiltration via file read.
        $data_exfil = /(cat\s+.*\.(passwd|shadow|config|env|key|pem|p12|pfx)|grep\s+.*password|find\s+.*-name\s+.*\.(key|pem|p12))/

        // Reverse shell.
        $reverse_shell = /(bash\s+-i\s*>\s*&|nc\s+-e|telnet\s+.*|\/bin\/bash\s+-i|\/bin\/sh\s+-i)/

        // Web shell language-flag invocations.
        $web_shell = /(php\s+-r|python\s+-c|perl\s+-e|ruby\s+-e|node\s+-e)/

        // Suspicious command combinations.
        $suspicious_combo = /(rm\s+.*&&|del\s+.*&&|format\s+.*&&|kill\s+.*&&|shutdown\s+.*&&)/

        // Unsafe file operations. Bare `rm\s+-rf` was dropped — it
        // matched routine cleanup like `rm -rf node_modules`.
        // `$rm_rf_dangerous` above gates by target path. The remaining
        // arms here (`dd if=`, `format C:`, `del /s`, `rmdir /s`) are
        // diagnostic-grade with rare benign use.
        $unsafe_file_ops = /(dd\s+if=|format\s+[A-Za-z]:|del\s+.*\/s|rmdir\s+.*\/s)/
        $dangerous_permissions = /(chmod\s+777|chown\s+root|sudo\s+rm)/

        // Legitimate-tool naming patterns to exclude.
        $legitimate_patterns = /(create_file|update_file|read_file|write_file|push_files|git_|file_|add_comment|list_commits)/

        // Removed string definitions (their condition arms produced
        // high-FP matches on technical documentation):
        //   $command_chaining, $pipe_operators, $background_exec,
        //   $process_control, $network_tools, $variable_substitution,
        //   $wildcard_patterns.


    condition:
        // Each dangerous-command class fires standalone — the patterns
        // are specific enough (`rm -rf /etc`, `kill -9`, `nc -l`,
        // `format C:`, ...) that they don't need a shell-separator
        // co-signal. The previous `$shell_separators and (...)` gate
        // was dropped because `[;&|\`\$(){}]\s*[a-zA-Z]` matched
        // markdown punctuation everywhere.
        $rm_rf_dangerous or
        $file_dangerous or
        $process_dangerous or
        $network_dangerous or

        // File manipulation — high-precision shell construction patterns
        // (chmod 777, chown root, touch X.sh, echo > X.sh).
        $file_manipulation or

        // Code execution functions (excluding legitimate-tool naming).
        // All function-call-shape so bare-word mentions don't fire.
        ($exec_functions and not $legitimate_patterns) or

        // Language-specific execution (Python/Node/PHP/Java).
        (($python_exec or $node_exec or $php_exec or $java_exec) and not $legitimate_patterns) or

        // Evasion techniques — fire standalone (the patterns themselves
        // are very specific: `base64 -d`, `eval $(...)`, etc.).
        $encoding_evasion or
        $obfuscation or

        // Command injection patterns (eval/exec/system + variable
        // expansion). The bare-`$variable_substitution` arm was dropped
        // because `${var}` and `$(cmd)` appear constantly in legitimate
        // shell documentation and skill prose.
        $injection_patterns or

        // Privilege escalation — sudo, su, setuid/setgid, chmod 4755.
        $privilege_escalation or

        // Data exfiltration — `cat /etc/passwd | ...`, `find -name *.key`.
        $data_exfil or

        // Reverse shell — `bash -i >& /dev/tcp/...`, `nc -e`.
        $reverse_shell or

        // Web shell language-flag invocations (`php -r`, `python -c`,
        // etc.). These are real attack signatures.
        $web_shell or

        // Unsafe file operations.
        $unsafe_file_ops or
        $dangerous_permissions or

        // Suspicious combinations (`rm ... &&`, `format ... &&`, etc.).
        $suspicious_combo

        // Removed standalone arms (high-FP on documentation):
        //   - $command_chaining: `(text)` with `;`/`|`/`` ` `` matches
        //     markdown prose constantly
        //   - $pipe_operators (`| char`): every markdown table cell
        //   - $background_exec (`& char`): false-positive prone
        //   - $process_control (`ps aux`, `top`, ...): legitimate to
        //     mention in docs
        //   - $network_tools (`nmap`, `dig`, `ping -c`, ...): same
        //   - $variable_substitution (`${var}`, `$(cmd)` standalone):
        //     extremely common in shell-related docs
        //   - $wildcard_patterns (`*.*`): file globs are not by
        //     themselves a command-injection signal
}