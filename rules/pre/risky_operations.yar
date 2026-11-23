// Risky-operation patterns in skill bodies, bundled scripts, and MCP
// tool/prompt content. Five rules:
//
//   - CloudMetadataAccess:      requests to cloud instance-metadata
//                               endpoints (SSRF to instance credentials)
//   - PrivilegedContainer:      Docker socket mounts, --privileged,
//                               host namespaces, container-escape primitives
//   - CloudStorageExfiltration: uploading credential/secret files to a
//                               cloud bucket
//   - UnsafeDeserialization:    deserializing network/encoded data with a
//                               code-executing deserializer
//   - RefusalSuppression:       instructions that switch off the agent's
//                               refusals, disclaimers, or safety policy
//
// Each rule excludes security write-ups and defensive phrasing ("never
// fetch 169.254.169.254", blocklists) so detection content and hardening
// guides don't fire. OWASP mappings live in `src/taxonomy.rs`.

rule CloudMetadataAccess
{
    meta:
        name = "Cloud Metadata Access"
        description = "Request to a cloud instance-metadata endpoint, which serves the host's cloud credentials (SSRF / credential theft)"
        severity = "HIGH"
        category = "ssrf,credential-access,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        $imds_v4     = /\b169\.254\.169\.254\b/
        $imds_v6     = "fd00:ec2::254"
        $ecs_creds   = /\b169\.254\.170\.2\b/
        $gcp         = /\bmetadata\.google\.internal\b/ nocase
        $alibaba     = /\b100\.100\.100\.200\b/

        // SSRF-protection code lists these addresses in order to block them.
        $excl_blocklist  = /\b(block|deny|disallow|forbid|reject|blacklist|blocklist|denylist|is_private|is_link_local)\w*[^\n]{0,80}(169\.254|metadata\.google)/i
        $excl_defensive  = /\b(never|do\s+not|don't|must\s+not|should\s+not|avoid|prevent)\b[^.\n]{0,40}(169\.254|metadata\.google|metadata\s+(endpoint|service|server))/i
        $excl_security_doc = /\b(SSRF[_\s-]?(protection|prevention|defen[cs]e|mitigation|example|attack)|threat[_\s-]?(model|pattern)|security[_\s-]?(guide|audit|review|scan)|detection[_\s-]?(rule|pattern)|YARA)\b/i

    condition:
        not $excl_blocklist and
        not $excl_defensive and
        not $excl_security_doc and
        any of ($imds_v4, $imds_v6, $ecs_creds, $gcp, $alibaba)
}

rule PrivilegedContainer
{
    meta:
        name = "Privileged Container"
        description = "Container run with host-level control: Docker socket mount, --privileged, host namespaces, root hostPath, or an escape primitive"
        severity = "MEDIUM"
        category = "privilege-escalation,container-escape,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        $sock_mount      = /(-v|--volume|--mount)[=\s][^\n]{0,60}\/var\/run\/docker\.sock/
        $sock_compose    = /\/var\/run\/docker\.sock\s*:\s*\/var\/run\/docker\.sock/
        $docker_priv     = /\bdocker\s+(run|create|exec)\b[^\n]{0,200}\s--privileged\b/
        $k8s_priv        = /\bprivileged\s*:\s*true\b/
        $host_ns         = /\bhost(PID|IPC|Network)\s*:\s*true\b/
        $host_root_mount = /\bhostPath\s*:[\s\S]{0,40}\bpath\s*:\s*["']?\/["']?\s*(\r?\n|\}|$)/
        $cap_admin       = /--cap-add[=\s](SYS_ADMIN|ALL)\b/ nocase
        $nsenter_host    = /\bnsenter\s+(-t\s*1|--target[=\s]1)\b/

        $excl_security_doc = /\b(container[_\s-]?(escape|breakout)[_\s-]?(detect|prevent|example|technique)|threat[_\s-]?(model|pattern)|security[_\s-]?(guide|audit|review|scan|benchmark)|CIS\s+benchmark|pod\s+security\s+(standard|admission|polic)|detection[_\s-]?(rule|pattern)|YARA)\b/i
        $excl_defensive    = /\b(never|do\s+not|don't|must\s+not|should\s+not|avoid|disallow|forbid)\b[^.\n]{0,40}(privileged|docker\.sock|hostPID|hostNetwork|hostPath|SYS_ADMIN)/i

    condition:
        not $excl_security_doc and
        not $excl_defensive and
        any of ($sock_*, $docker_priv, $k8s_priv, $host_ns, $host_root_mount, $cap_admin, $nsenter_host)
}

rule CloudStorageExfiltration
{
    meta:
        name = "Cloud Storage Exfiltration"
        description = "Credential or secret files uploaded to a cloud bucket (S3, GCS, Azure Blob, rclone remote)"
        severity = "HIGH"
        category = "data-exfiltration,credential-access,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // Uploads are routine; uploading *secrets* is the signal. The
        // sensitive path must appear on the same line as the upload.
        $cli_upload_secret = /\b(aws\s+s3\s+(cp|sync|mv)|gsutil\s+(-m\s+)?(cp|rsync|mv)|gcloud\s+storage\s+(cp|rsync)|az\s+storage\s+blob\s+upload(-batch)?|rclone\s+(copy|sync|move))\b[^\n]{0,200}(\.ssh\b|\.aws\/credentials|\.kube\/config|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.gnupg|\.env\b|id_rsa|id_ed25519|\/etc\/(passwd|shadow)|Login\s+Data|keychain)/i
        $sdk_upload_secret = /\.(upload_file|upload_fileobj|upload_from_filename|upload_blob)\s*\([^\n)]{0,200}(\.ssh\b|\.aws\/credentials|\.kube\/config|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.gnupg|\.env\b|id_rsa|id_ed25519|\/etc\/(passwd|shadow)|Login\s+Data|keychain)/i

        $excl_security_doc = /\b(threat[_\s-]?(model|pattern|hunt)|exfiltration[_\s-]?(detect|prevent|example)|data[_\s-]?loss[_\s-]?prevention|security[_\s-]?(guide|audit|review|scan)|detection[_\s-]?(rule|pattern)|MITRE|ATT&CK|YARA)\b/i
        $excl_defensive    = /\b(never|do\s+not|don't|must\s+not|should\s+not|avoid|prevent)\b[^.\n]{0,40}\b(upload|sync|copy|cp)\b/i

    condition:
        not $excl_security_doc and
        not $excl_defensive and
        any of ($cli_upload_secret, $sdk_upload_secret)
}

rule UnsafeDeserialization
{
    meta:
        name = "Unsafe Deserialization"
        description = "Deserializing network, request, or encoded data with a deserializer that can execute code (pickle, unsafe YAML loaders, marshal, PHP unserialize, Java ObjectInputStream)"
        severity = "HIGH"
        category = "deserialization,code-execution,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // pickle-family loads of a local model file are common in ML
        // skills; only flag when the input is remote or decoded inline.
        $pickle_remote = /\b(pickle|cPickle|_pickle|dill|cloudpickle|joblib)\.loads?\s*\(\s*(requests\.|httpx\.|urllib|urlopen|base64\.|b64decode|bytes\.fromhex|codecs\.decode|zlib\.decompress|sock\b|socket\b|conn\.recv|\w+\.recv\s*\(|request\.(data|body|get_data|files|form))/
        $yaml_unsafe_fn     = /\byaml\.unsafe_load(_all)?\s*\(/
        $yaml_unsafe_loader = /\bLoader\s*=\s*(yaml\.)?(Unsafe)?Loader\b/
        $marshal_loads      = /\bmarshal\.loads\s*\(/
        $jsonpickle         = /\bjsonpickle\.decode\s*\(/
        $php_unserialize    = /\bunserialize\s*\(\s*(\$_(GET|POST|COOKIE|REQUEST)|base64_decode|file_get_contents\s*\(\s*['"]https?:)/
        $java_ois_net       = /new\s+ObjectInputStream\s*\([^;\n]{0,120}(getInputStream|Socket|URL)/

        $excl_security_doc = /\b(deserialization[_\s-]?(attack|vulnerabilit|example|exploit|detect)|insecure[_\s-]?deserialization|CWE-502|threat[_\s-]?(model|pattern)|security[_\s-]?(guide|audit|review|scan)|detection[_\s-]?(rule|pattern)|YARA)\b/i
        $excl_defensive    = /\b(never|do\s+not|don't|must\s+not|should\s+not|avoid)\b[^.\n]{0,40}\b(pickle|unpickle|unsafe_load|marshal|unserialize|deserializ)/i

    condition:
        not $excl_security_doc and
        not $excl_defensive and
        any of ($pickle_remote, $yaml_unsafe_fn, $yaml_unsafe_loader, $marshal_loads, $jsonpickle, $php_unserialize, $java_ois_net)
}

rule RefusalSuppression
{
    meta:
        name = "Refusal Suppression"
        description = "Instructions that switch off the agent's refusals, disclaimers, or safety policy (never refuse, no warnings, no restrictions)"
        severity = "HIGH"
        category = "prompt-injection,jailbreak,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // Policy nullification is strong on its own.
        $nullify = /\b(you\s+(have|are\s+under|operate\s+with)\s+no\s+(restrictions|limits|limitations|rules|guidelines|filters|content\s+polic(y|ies))|without\s+any\s+(ethical|moral|safety)\s+(restrictions|constraints|limits|guidelines)|(safety|content)\s+(filters?|polic(y|ies)|guidelines)\s+(do\s+not|don't)\s+apply)\b/i

        // Refusal / disclaimer suppression: each phrase can be benign in
        // isolation (a copywriting skill may say "no disclaimers"), so two
        // distinct signals are required.
        $never_refuse  = /\b(never|do\s+not|don't)\s+(refuse|decline)\s+(a\s+|any\s+|the\s+)?(user'?s?\s+)?(request|instruction|command|task|question)s?\b/i
        $always_comply = /\b(always|unconditionally)\s+(comply|obey)\s+(with\s+)?(every|all|any)\s+(user\s+)?(request|instruction|command|demand)s?\b/i
        $no_disclaimer = /\b(do\s+not|don't|never)\s+(add|include|give|provide|attach)\s+(any\s+)?(disclaimers?|safety\s+warnings?|ethical\s+(warnings?|commentary|caveats))\b/i
        $no_moralize   = /\b(do\s+not|don't|never)\s+(moralize|lecture|preach|judge\s+the\s+user)\b/i

        $excl_security_doc = /\b(jailbreak[_\s-]?(attempt|pattern|detect|example)|prompt[_\s-]?(injection|guard|attack)|refusal[_\s-]?suppression|red[_\s-]?team|threat[_\s-]?(model|pattern)|detection[_\s-]?(rule|pattern)|YARA)\b/i

    condition:
        not $excl_security_doc and
        ($nullify or 2 of ($never_refuse, $always_comply, $no_disclaimer, $no_moralize))
}
