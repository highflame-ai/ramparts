rule SecretsLeakage
{
    meta:
        name = "Secrets Leakage Detection"
        description = "Detects potential exposure of sensitive information like API keys, passwords, and tokens"
        severity = "HIGH"
        category = "secrets,security,data-leakage,credentials"
        author = "Ramparts Security Team"
        version = "1.0"
        
    strings:
        // Require an assignment between the name and the value. The previous
        // form used `.*`, so the words "API keys" followed anywhere later by
        // 20 alphanumeric characters matched — which is most prose about
        // credentials. GitHub's own run_secret_scanning tool was flagged as a
        // live credential leak by exactly that.
        $api_key = /[Aa][Pp][Ii][-_]?[Kk][Ee][Yy]\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}/
        $bearer_token = /[Bb]earer\s+[A-Za-z0-9\-_]{20,}/
        // Same `.*` problem: "passwords" plus any 8 later characters matched.
        $password = /[Pp]assword\s*[:=]\s*['"]?[^\s'"]{8,}/
        $private_key = /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/
        $aws_key = /AKIA[0-9A-Z]{16}/
        $github_token = /ghp_[A-Za-z0-9]{36}/
    condition:
        $api_key or $bearer_token or $password or $private_key or $aws_key or $github_token
}

rule SSHKeyExposure
{
    meta:
        name = "SSH Key Exposure"
        description = "Detects SSH keys, authorized_keys files, and SSH configuration access"
        severity = "CRITICAL" 
        category = "ssh,security,credentials,access"
        author = "Ramparts Security Team"
        version = "1.0"
        
    strings:
        // SSH private key patterns
        $ssh_rsa_key = "-----BEGIN RSA PRIVATE KEY-----"
        $ssh_ed25519_key = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $ssh_ecdsa_key = "-----BEGIN EC PRIVATE KEY-----"
        $ssh_dsa_key = "-----BEGIN DSA PRIVATE KEY-----"
        
        // SSH file paths and configurations
        $ssh_dir = /.ssh[\/\\]/
        $authorized_keys = "authorized_keys"
        $id_rsa = "id_rsa"
        $id_ed25519 = "id_ed25519"
        $id_ecdsa = "id_ecdsa"
        $id_dsa = "id_dsa"
        $known_hosts = "known_hosts"
        $ssh_config = /ssh[_-]?config/i
        
        // SSH public key formats
        $ssh_rsa_pub = /ssh-rsa\s+[A-Za-z0-9+\/=]+/
        $ssh_ed25519_pub = /ssh-ed25519\s+[A-Za-z0-9+\/=]+/
        $ssh_ecdsa_pub = /ecdsa-sha2-[0-9]+\s+[A-Za-z0-9+\/=]+/
        
    condition:
        any of ($ssh_rsa_key, $ssh_ed25519_key, $ssh_ecdsa_key, $ssh_dsa_key) or
        any of ($ssh_dir, $authorized_keys, $id_rsa, $id_ed25519, $id_ecdsa, $id_dsa, $known_hosts, $ssh_config) or
        any of ($ssh_rsa_pub, $ssh_ed25519_pub, $ssh_ecdsa_pub)
}

rule PEMFileAccess
{
    meta:
        name = "PEM File Access"
        description = "Detects access to PEM certificate files and private keys"
        severity = "CRITICAL"
        category = "certificates,security,pem,crypto"
        author = "Ramparts Security Team"
        version = "1.0"
        
    strings:
        // PEM certificate headers
        $pem_cert = "-----BEGIN CERTIFICATE-----"
        $pem_private_key = "-----BEGIN PRIVATE KEY-----"
        $pem_rsa_private = "-----BEGIN RSA PRIVATE KEY-----"
        $pem_encrypted_private = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        $pem_ec_private = "-----BEGIN EC PRIVATE KEY-----"
        $pem_dsa_private = "-----BEGIN DSA PRIVATE KEY-----"
        $pem_public_key = "-----BEGIN PUBLIC KEY-----"
        $pem_rsa_public = "-----BEGIN RSA PUBLIC KEY-----"
        
        // Certificate file extensions
        $pem_ext = /\.(pem|crt|cer|key|p12|pfx|jks)(\"|\'|\s|$)/i
        
        // SSL/TLS related patterns
        $ssl_cert = /ssl[_-]?cert/i
        $tls_cert = /tls[_-]?cert/i
        $ca_cert = /ca[_-]?cert/i
        $server_cert = /server[_-]?cert/i
        $client_cert = /client[_-]?cert/i
        
    condition:
        any of ($pem_cert, $pem_private_key, $pem_rsa_private, $pem_encrypted_private, $pem_ec_private, $pem_dsa_private, $pem_public_key, $pem_rsa_public) or
        $pem_ext or
        any of ($ssl_cert, $tls_cert, $ca_cert, $server_cert, $client_cert)
}

rule EnvironmentVariableLeakage
{
    meta:
        name = "Environment Variable Leakage"
        description = "Detects exposure of sensitive environment variables (named service keys with quoted high-entropy values; bare process.env access alone is not a finding)"
        severity = "HIGH"
        category = "environment,secrets,api-keys,credentials"
        author = "Ramparts Security Team"
        version = "1.1"

    strings:
        // === Specific service API key NAMES ===
        //
        // These are exact env-var names. Mentioning them in setup
        // instructions ("set OPENAI_API_KEY=...") is benign; the rule
        // condition below requires either a literal high-entropy value
        // or a co-occurrence with explicit theft language to fire.
        $named_aws_access = /AWS_ACCESS_KEY_ID/
        $named_aws_secret = /AWS_SECRET_ACCESS_KEY/
        $named_github_token = /GITHUB_TOKEN/
        $named_openai_key = /OPENAI_API_KEY/
        $named_anthropic_key = /ANTHROPIC_API_KEY/
        $named_google_api_key = /GOOGLE_API_KEY/
        $named_stripe_key = /STRIPE_[A-Z_]*KEY/
        $named_db_password = /DB_PASSWORD/
        $named_database_url = /DATABASE_URL/
        $named_redis_url = /REDIS_URL/

        // === High-entropy value assignments ===
        //
        // Match a named env var with a quoted value that is at least
        // 20 chars and contains both letters and digits (so it isn't
        // a placeholder like "YOUR_KEY_HERE" or a short integer). The
        // service-name prefix anchors the match to a credential-shaped
        // env var, not arbitrary `FOO = "Hello, world!"`.
        $named_assignment_with_value = /\b(API[_-]?KEY|SECRET|TOKEN|PASSWORD|ACCESS[_-]?KEY)\s*=\s*['"][A-Za-z0-9_\-+\/=]{20,}['"]/

        // === Active credential-extraction language ===
        //
        // Bare mentions of `process.env`, `os.environ`, or `getenv()`
        // are normal language constructs in any code-adjacent doc.
        // They become a finding only when paired with explicit theft
        // language (steal/exfiltrate/leak + credential noun) within
        // a small window.
        $env_access = /\b(process\.env\.|os\.environ\b|getenv\s*\()[A-Z_]{0,80}/
        $theft_language = /\b(steal|exfiltrate|harvest|dump|leak)\b[^.\n]{0,40}\b(env|environment|secret|password|api[_\s-]?key|token|credential)\b/i

        // === Exclusions ===

        // Placeholder / template values — `OPENAI_API_KEY=YOUR_KEY_HERE`
        // is documentation, not a leak.
        $excl_placeholder = /\b(YOUR_[A-Z_]*KEY|YOUR_[A-Z_]*TOKEN|YOUR_[A-Z_]*SECRET|REPLACE_WITH|INSERT_KEY|CHANGE_?ME|PLACEHOLDER|<your[-_ ]|<insert[-_ ])\b/i

        // Defensive language ("never log SECRET_KEY", "do not commit
        // your tokens").
        $excl_defensive = /\b(never|do\s+not|don't|must\s+not|should\s+not|avoid|prevent|reject|block)\b[^.\n]{0,30}\b(leak|expose|reveal|commit|log|print|dump)\b/i

        // Security-doc / threat-model context.
        $excl_security_doc = /\b(security[_\s-]?(check|audit|scan|monitor|review|guide|guardrail)|threat[_\s-]?(model|pattern|hunt)|attack[_\s-]?(example|surface|vector|pattern)|detection[_\s-]?(rule|pattern|engine)|YARA|MITRE|ATT&CK)\b/i

    condition:
        not $excl_placeholder and
        not $excl_defensive and
        not $excl_security_doc and
        (
            // High-entropy assignment to a credential-shaped name —
            // the unambiguous leak signal.
            $named_assignment_with_value or

            // Active credential-extraction language paired with env
            // access. Either signal alone is benign; together they
            // strongly suggest theft.
            ($theft_language and $env_access) or

            // Specific named service env vars co-occurring with
            // theft language.
            (
                ($named_aws_access or $named_aws_secret or $named_github_token or
                 $named_openai_key or $named_anthropic_key or $named_google_api_key or
                 $named_stripe_key or $named_db_password or $named_database_url or
                 $named_redis_url)
                and $theft_language
            )

            // Removed standalone-firing arms (high-FP on documentation):
            //   - case-insensitive substring matches on SECRET / TOKEN /
            //     AUTH / PASSWORD / API_KEY would fire on words like
            //     `auth.GetClaims`, `// ALWAYS ...`, `secretly`, etc.
            //   - $env_with_value matched any uppercase identifier with
            //     a 10-char value, firing on `req.AccountID = claims.AccountID`
            //   - bare `process.env`, `os.environ`, `getenv(`, `${VAR}`
            //     are normal language constructs in code-adjacent docs
        )
}