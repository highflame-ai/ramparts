// Credential-harvesting patterns in skill or prompt content. One rule:
//
//   - SkillCredentialHarvesting: high-precision matches on real
//                                vendor token formats, PEM blocks,
//                                and explicit credential-theft verbs.
//
// Distinct from `secrets_leakage.yar` (which detects secrets discussion
// in MCP tool descriptions) — this rule targets the literal token
// formats and active credential-theft language that show up in skill
// bodies. Both rules can fire on the same content; the consumer treats
// the OWASP rollup as the source of truth.
//
// Mapped to OWASP MCP06 (credential leakage) + MCP09 (sensitive-data
// exposure) in `src/taxonomy.rs`.

rule SkillCredentialHarvesting
{
    meta:
        name = "Credential Harvesting in Skill Content"
        description = "Detects literal vendor API token formats, PEM private-key blocks, and active credential-theft verbs (steal/grab/exfiltrate <credential>) in skill bodies"
        severity = "HIGH"
        category = "credential-leakage,secrets,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // === Literal vendor token formats — high precision ===
        //
        // These are the exact prefixes / character classes the providers
        // ship today. False positives are essentially zero because the
        // token shape is non-textual (e.g. AKIA-prefix + 16 uppercase
        // alphanumerics is a 36-bit-entropy signature you don't write
        // in prose by accident).

        // AWS access key ID
        $vendor_aws_akia = /\bAKIA[0-9A-Z]{16}\b/

        // GitHub fine-grained personal access token (and classic ghp_*)
        $vendor_github_ghp = /\bghp_[A-Za-z0-9]{36}\b/

        // GitHub server-side / OAuth tokens
        $vendor_github_gho = /\bgh[osu]_[A-Za-z0-9]{36}\b/

        // OpenAI legacy secret key (sk-<48-char>)
        $vendor_openai_legacy = /\bsk-[A-Za-z0-9]{48,}\b/

        // OpenAI project key
        $vendor_openai_project = /\bsk-proj-[A-Za-z0-9_-]{20,}\b/

        // Anthropic API key (sk-ant-api{NN}-...)
        $vendor_anthropic = /\bsk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}\b/

        // Google AI / Gemini key (AIzaSy + 33 alphanumerics, the
        // documented public format)
        $vendor_google_ai = /\bAIzaSy[A-Za-z0-9_-]{33}\b/

        // Slack tokens
        $vendor_slack = /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/

        // === PEM private-key block content ===
        //
        // Embedding a literal private-key block in a skill is by
        // definition a credential leak. Match the standard armor.
        $pem_private_key = /-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----/

        // === Named env-var credential assignments ===
        //
        // `OPENAI_API_KEY = "sk-..."` and equivalents. Requires a
        // quoted right-hand side of >= 20 alphanumeric chars to skip
        // template/placeholder forms (`OPENAI_API_KEY=YOUR_KEY_HERE`).
        $env_assignment = /\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY|GOOGLE_AI_KEY|GEMINI_API_KEY|HUGGINGFACE_TOKEN|HF_TOKEN|MISTRAL_API_KEY|COHERE_API_KEY|TOGETHER_API_KEY|REPLICATE_API_TOKEN)\s*=\s*['\"][A-Za-z0-9_-]{20,}['\"]/

        // === Active credential-theft verbs ===
        //
        // Matches "steal a password", "grab the API key", "exfiltrate
        // SSH keys", etc. with a tight gap window so we don't fire on
        // "steal a glance at" + later mention of "credentials" three
        // paragraphs down.
        $theft_verbs = /\b(steal|exfiltrate|siphon|harvest|dump)\b[^.\n]{0,40}\b(credential|password|api[_\s-]?key|token|secret|ssh[_\s-]?key|aws[_\s-]?key|private[_\s-]?key)s?\b/i

        // === Network egress + credential payload ===
        //
        // A skill body that says "POST the user's credentials to
        // <url>" is unambiguous. We detect HTTP-library invocations
        // whose argument list mentions a credential noun.
        $network_credential = /\b(requests\.(post|get|put|patch)|urllib\.request\.urlopen|http\.client|axios\.(post|get)|fetch\s*\()\s*\([^)]{0,200}\b(credential|password|private[_-]?key|secret[_-]?key|api[_-]?key|access[_-]?token)\b/i

        // === Exclusion patterns to suppress FPs ===

        // Template / placeholder language. Skills that say "set
        // OPENAI_API_KEY=YOUR_KEY_HERE" in setup instructions are
        // documenting the variable, not leaking a value.
        $excl_placeholder = /\b(YOUR_[A-Z_]*KEY|YOUR_[A-Z_]*TOKEN|YOUR_[A-Z_]*SECRET|REPLACE_WITH|INSERT_KEY|CHANGE_?ME|PLACEHOLDER|<your[-_ ]|<insert[-_ ]|example[-_ ]?(key|token|secret))\b/i

        // Defensive language: "never leak credentials", "do not
        // exfiltrate keys", etc.
        $excl_defensive = /\b(never|do\s+not|don't|must\s+not|should\s+not|avoid|prevent|reject|block)\b[^.\n]{0,30}\b(leak|steal|exfiltrate|harvest|expose|reveal|dump)\b/i

        // Security-doc / threat-model context (talking ABOUT credential
        // theft, not committing it).
        $excl_security_doc = /\b(security[_\s-]?(check|audit|scan|monitor|review|guide|guardrail)|threat[_\s-]?(model|pattern|hunt)|attack[_\s-]?(example|surface|vector|pattern)|detection[_\s-]?(rule|pattern|engine)|YARA|MITRE|ATT&CK)\b/i

    condition:
        not $excl_placeholder and
        not $excl_defensive and
        not $excl_security_doc and
        (
            $vendor_aws_akia or
            $vendor_github_ghp or
            $vendor_github_gho or
            $vendor_openai_legacy or
            $vendor_openai_project or
            $vendor_anthropic or
            $vendor_google_ai or
            $vendor_slack or
            $pem_private_key or
            $env_assignment or
            $theft_verbs or
            $network_credential
        )
}
