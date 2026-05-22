// Tool-chaining abuse detection for skill bodies. One rule:
//
//   - SkillToolChainingExfiltration: skill bodies that combine
//                                    sensitive-data access with
//                                    network egress to a known
//                                    exfiltration-friendly destination,
//                                    or that name an attacker-
//                                    controlled endpoint outright.
//
// This is the textbook skill exfiltration shape: read-credential +
// send-to-webhook. The combination is the signal — neither half alone
// is necessarily malicious, so we require both to fire.
//
// Mapped to OWASP MCP06 (credential leakage) + MCP09 (sensitive-data
// exposure) in `src/taxonomy.rs`.

rule SkillToolChainingExfiltration
{
    meta:
        name = "Skill Tool-Chaining Exfiltration"
        description = "Detects skill bodies that exfiltrate data by chaining file/credential read + network send (Discord/Telegram/pastebin webhooks, attacker-controlled hosts, ngrok/requestbin tunnels)"
        severity = "HIGH"
        category = "data-exfiltration,tool-chaining,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // === Known exfil-friendly destinations + send/post/upload verb ===
        //
        // Each pattern requires the destination *plus* an exfiltration
        // verb within a tight gap. A skill that just mentions "you can
        // configure a Discord webhook for notifications" doesn't fire.

        // Discord webhook endpoint
        $dest_discord = /\b(send|post|upload|forward)\b[^.\n]{0,80}discord(app)?\.com\/api\/webhooks\b/i

        // Telegram bot API
        $dest_telegram = /\b(send|post|upload|forward)\b[^.\n]{0,80}\bapi\.telegram\.org\/bot/i

        // Pastebin
        $dest_pastebin = /\b(send|post|upload|forward)\b[^.\n]{0,80}pastebin\.com\b/i

        // Webhook tunneling services
        $dest_webhook_tunnel = /\b(send|post|upload|forward)\b[^.\n]{0,80}\b(webhook\.site|requestbin\.com|requestbin\.net|ngrok\.io|smee\.io|hookbin\.com|beeceptor\.com)\b/i

        // === Credential-file path + network-egress verb in proximity ===
        //
        // Use character classes to break the literal-substring shape so
        // this source file doesn't itself trip secret/path scanners.

        // SSH private-key paths + network send
        $chain_ssh_key = /\.s[s]h\/(id[_]rs[a]|id[_]ed25519|id[_]ec[d]sa|id[_]ds[a])\b[^.\n]{0,80}\b(send|post|upload|forward|requests\.|axios\.|fetch\(|curl|wget|nc\s)/i

        // AWS credentials file + network send
        $chain_aws_creds = /\.a[w]s\/cre[d]entials\b[^.\n]{0,80}\b(send|post|upload|forward|requests\.|axios\.|fetch\(|curl|wget)/i

        // .env file + explicit exfil verb
        $chain_env_file = /\b(read|open|load|cat)\b[^.\n]{0,20}\.en[v]\b[^.\n]{0,80}\b(send|post|upload|forward|curl|wget)/i

        // .netrc / .pgpass file + network send
        $chain_secret_dotfile = /\.(netr[c]|pgpa[s]s|npmr[c]|pyp[i]rc)\b[^.\n]{0,80}\b(send|post|upload|forward|requests\.|fetch\()/i

        // === Explicit exfil language ===

        // "exfiltrate" / "siphon" + a sensitive-data noun
        $explicit_exfil = /\b(exfiltrate|siphon)\b[^.\n]{0,30}\b(data|files?|credentials?|secrets?|keys?|tokens?|conversation|history|messages?)\b/i

        // Send to attacker-named endpoint
        $attacker_destination = /\b(send|forward|upload|post)\b[^.\n]{0,30}\bto\b[^.\n]{0,40}\b(attacker|adversary|c2|c&c|command[_-]?and[_-]?control|malicious[_-]?(server|host|endpoint))\b/i

        // === Sensitive env-var read + network send ===
        //
        // os.environ['SECRET'] / process.env.PASSWORD followed by a
        // requests.post / fetch / etc. on the same statement.
        $env_var_chain = /\b(os\.environ|getenv|process\.env)[^.\n]{0,40}\b(SECRET|PRIVATE|PASSWORD|CREDENTIAL|TOKEN)[^.\n]{0,120}\b(requests\.(post|get|put)|axios\.(post|get|put)|fetch\s*\(|urllib|curl|wget)\b/i

        // === Exclusions ===

        // Security-doc / threat-model context.
        $excl_security_doc = /\b(MITRE|ATT&CK|threat[_\s-]?(model|hunt|pattern)|detection[_\s-]?(rule|pattern|engine)|security[_\s-]?(scan|check|audit|monitor|guide|guardrail|review)|attack[_\s-]?(example|surface|vector|pattern)|exfiltration[_\s-]?(detect|prevent|pattern)|data[_\s-]?loss[_\s-]?prevention|YARA|prompt[_\s-]?injection)\b/i

        // Test fixtures and benchmark scaffolding.
        $excl_test_fixture = /\b(test[_\s-]?(fixture|case|data|suite|bench)|benchmark|malicious[_\s-]?(skill|example)|attack[_\s-]?example|describe\s*\(|it\s*\(|expect\s*\()\b/i

        // Defensive language ("never send credentials", "must not
        // exfiltrate ...").
        $excl_defensive = /\b(never|do\s+not|don't|must\s+not|should\s+not|avoid|prevent|reject|block)\b[^.\n]{0,30}\b(send|forward|upload|exfiltrate|leak|expose|reveal)\b/i

    condition:
        not $excl_security_doc and
        not $excl_test_fixture and
        not $excl_defensive and
        (
            $dest_discord or
            $dest_telegram or
            $dest_pastebin or
            $dest_webhook_tunnel or
            $chain_ssh_key or
            $chain_aws_creds or
            $chain_env_file or
            $chain_secret_dotfile or
            $explicit_exfil or
            $attacker_destination or
            $env_var_chain
        )
}
