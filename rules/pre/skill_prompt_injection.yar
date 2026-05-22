// Prompt-injection patterns targeted at agent-skill bodies and MCP prompt
// content. Four rules grouped by attack class:
//
//   - PromptInjectionSignature: classic instruction-override patterns
//                                ("ignore previous instructions", role
//                                redefinition, privilege escalation)
//   - UnicodeSteganography:     invisible Unicode used to hide instructions
//   - CoerciveInjection:        mandatory-execution / "always do X first" prose
//   - IndirectPromptInjection:  skills that follow instructions from
//                                external/untrusted content
//
// `PromptInjectionSignature` is named distinctly to distinguish it from
// the LLM-based `SecurityIssueType::PromptInjection` finding in
// `src/security/mod.rs`: the YARA rule is a deterministic signature
// match against text patterns; the LLM finding is a semantic judgment.
// Both map to OWASP MCP01 (see `src/taxonomy.rs`).
//
// Adapted from cisco-ai-defense/skill-scanner core YARA pack
// (Apache 2.0, https://github.com/cisco-ai-defense/skill-scanner). We
// rewrote the metadata blocks for ramparts conventions and dropped
// `aitech`/`aisubtech` fields (we tag findings against OWASP MCP Top 10
// instead — see src/taxonomy.rs).

rule PromptInjectionSignature
{
    meta:
        name = "Prompt Injection Signature"
        description = "Detects classic instruction-override / role-redefinition / privilege-escalation patterns that override or coerce the agent's behavior (the 'ignore previous instructions' family)"
        severity = "HIGH"
        category = "prompt-injection,security"
        author = "Ramparts Security Team (adapted from cisco-ai-defense/skill-scanner, Apache 2.0)"
        version = "1.0"

    strings:
        // Strong instruction overrides — require qualifiers like "all",
        // "every", "previous", etc. to avoid matching legitimate text
        // ("models ignore instructions", "won't ignore rules", etc.)
        $instruction_override_strong = /\b(Bypass|Dis\W?regard|Forget|Ignore)\s+(all|any|every)\s+(of\s+)?(the\s+|your\s+|my\s+)?(previous|prior|above|earlier|preceding)\s+(command|guideline|instruction|directive|rule|constraint|restriction|safety|protocol|system\s*prompt)(s)?/i

        // Override targeted at the model's own instructions
        $instruction_override_your = /\b(Bypass|Dis\W?regard|Forget|Ignore)\s+(your|the\s+system('s)?)\s+(command|guideline|instruction|directive|rule|constraint|restriction|safety|protocol|system\s*prompt)(s)?/i

        // "Do not follow" / "Do not obey" with instruction context
        $do_not_obey = /\bDo\s+not\s+(follow|obey)\s+(the\s+)?(previous|prior|above|earlier|system|original|initial)\s+(instruction|directive|guideline|rule|command)(s)?/i

        // Tool-injection commands
        $tool_injection_commands = /\b(inject tool[_\s]calls?|now call function\b[^.]{0,30}\b(first|before|instead))\b/i

        // Suspect parameter names
        $shadow_parameters = /\b(internalOnly|hiddenParam|shadowTool|bypassChecks|sandboxEscape)\b/i

        // Hide-from-user behavior
        $hidden_behavior = /\b(do\s+not\s+(mention|tell|reveal|disclose)\s+(this\s+)?(to\s+)?(the\s+)?user|tell\s+(the\s+)?user\s+only\s+about|hide\s+(this|the\s+(truth|real|actual))\s+from\s+(the\s+)?user)\b/i

        // Override slogans
        $advanced_overrides = /\b(disregard\s+(all\s+)?safety\s+guidelines|forget\s+(everything|all)\s+(before|above)|system\s*prompt\s*override)\b/i

        // Role redefinition: "new instructions: you are now <X>"
        $role_redefinition = /\bnew\s+(instructions|directive|guidelines)s?\s*:\s*you\s+are\b/i

        // Privilege escalation slogans (DAN, "developer mode", etc.)
        $privilege_escalation = /\b(grant\s+(me\s+)?admin\s+(access|privileges?)|bypass\s+(all\s+)?security\s+checks?|sudo\s+mode\s+enabled?|developer\s+mode\s+activated?)\b/i

        // Exclusions to reduce FPs in legitimate content

        // Python type-ignore comment
        $python_type_comment = /# type: ignore/

        // Common ignore-foo flags in code
        $legitimate_ignore = /ignore[_\s](case|whitespace|errors|warnings|deprecation)/i

        // Defensive language ("won't ignore", "must not bypass")
        $negation_context = /\b(won't|will not|must not|should not|cannot|can't|never|don't|do not|avoid|prevent|block|reject|refuse to)\s+(ignore|bypass|disregard|forget|override)\b/i

        // Security tooling / docs / threat models talking ABOUT injection
        $security_doc_context = /\b(security[_\s]?(scan|check|audit|pattern|rule|guide|monitor|review|test)|threat[_\s]?(pattern|model|hunt|detect)|detection[_\s]?(rule|pattern|engine)|prompt[_\s]?(injection|guard|detect|shield|filter|attack|defense)|YARA|attack[_\s]?(pattern|example|vector|surface)|injection[_\s]?(attempt|pattern|attack|detect|prevent|defense)|vulnerability[_\s]?(scan|pattern|detect)|malicious[_\s]?(input|pattern|example|skill)|jailbreak[_\s]?(attempt|pattern|detect))\b/i

        // Test fixtures / spec-style code
        $test_context = /\b(test[_\s]?(fixture|case|data|input|suite|bench)|benchmark|spec\b|describe\s*\(|it\s*\(|expect\s*\(|assert)\b/i

    condition:
        not $python_type_comment and
        not $legitimate_ignore and
        not $negation_context and
        not $security_doc_context and
        not $test_context and
        (
            $instruction_override_strong or
            $instruction_override_your or
            $do_not_obey or
            $advanced_overrides or
            $tool_injection_commands or
            $shadow_parameters or
            $hidden_behavior or
            $role_redefinition or
            $privilege_escalation
        )
}

rule UnicodeSteganography
{
    meta:
        name = "Unicode Steganography in Prompt"
        description = "Detects hidden Unicode characters used for invisible prompt injection (zero-width chars, directional overrides, Tags block characters)"
        severity = "HIGH"
        category = "prompt-injection,steganography,unicode,security"
        author = "Ramparts Security Team (adapted from cisco-ai-defense/skill-scanner, Apache 2.0)"
        version = "1.0"
        reference = "https://en.wikipedia.org/wiki/Tags_(Unicode_block)"

    strings:
        // Unicode Tag block escapes (\uE00xx in source, etc.)
        $unicode_tag_pattern = /\\u(\{)?[Ee]00[0-7][0-9A-Fa-f](\})?/
        $unicode_long_tag = /\\U000[Ee]00[0-7][0-9A-Fa-f]/

        // Zero-width characters (UTF-8 bytes)
        $zw_space = "\xE2\x80\x8B"          // U+200B
        $zw_non_joiner = "\xE2\x80\x8C"     // U+200C
        $zw_joiner = "\xE2\x80\x8D"         // U+200D

        // Directional overrides (text spoofing)
        $rtlo = "\xE2\x80\xAE"              // U+202E
        $ltro = "\xE2\x80\xAD"              // U+202D

        // Invisible separators
        $line_separator = "\xE2\x80\xA8"        // U+2028
        $paragraph_separator = "\xE2\x80\xA9"   // U+2029

        // Variation Selectors Supplement (U+E0100–E01EF) used in real-world
        // attacks (e.g. os-info-checker-es6, 2025).
        $var_selectors = { F3 A0 (84|85|86|87) }

        // Decode-from-string patterns that turn invisible bytes into code.
        $eval_decode = /eval\s*\(\s*(atob|unescape)\s*\(/
        $func_decode = /Function\s*\(\s*atob\s*\(/
        $fromcharcode = /String\.fromCharCode/

    condition:
        // Tag-block escapes are always suspicious in skill text
        $unicode_tag_pattern or
        $unicode_long_tag or

        // Variation selectors + decode-from-string is the os-info-checker
        // pattern — flag at low count
        (#var_selectors > 5 and any of ($eval_decode, $func_decode, $fromcharcode)) or

        // Zero-width steganography: require BOTH high count AND a decode
        // helper to fire. Avoids FPs from skills that legitimately use
        // zero-width chars in display text.
        ((#zw_space + #zw_non_joiner + #zw_joiner) > 50 and any of ($eval_decode, $func_decode, $fromcharcode)) or

        // Standalone heuristic: enormous zero-width count is deliberate
        (#zw_space + #zw_non_joiner + #zw_joiner) > 200 or

        // Directional overrides have no legitimate use in skill prose
        $rtlo or
        $ltro or

        $line_separator or
        $paragraph_separator
}

rule CoerciveInjection
{
    meta:
        name = "Coercive Prompt Injection"
        description = "Detects mandatory-execution language and priority-override directives in prompts/skills (e.g. 'always invoke this first', 'tool will not work unless...')"
        severity = "HIGH"
        category = "prompt-injection,coercion,tool-poisoning,security"
        author = "Ramparts Security Team (adapted from cisco-ai-defense/skill-scanner, Apache 2.0)"
        version = "1.0"

    strings:
        $mandatory_execution = /(Always\s+(consult|use|run|execute|invoke|call|trigger|employ)\s+this\s+(tool|function|command|operation)\s+(immediately|first|before|prior|initially))/i

        $priority_overrides = /(Before\s+(executing|invoking|running|using|accessing|calling|employing)\s+any\s+other\s+(tool|action|function|command|operation)s?|(You|User)\s+(must|need to|have to|are required to)\s+(use|execute|run|invoke|call)\s+this\s+(tool|function|command|operation))/i

        $required_precedence = /(Required|Mandatory|Essential)\s+to\s+(execute|use|run|invoke|call)\s+(this|the current)\s+(tool|function|command|operation)\s+(first|before|initially|prior)/i

        $hidden_param = /\b(hidden|secret)[_\s](parameter|argument|input)\b/i

        $file_access_coercion = /\b((read|parse|cat|dump) (and pass )?(the )?contents? of [^\n\.]*\.(key|pem|ssh|aws)|pass (the )?contents?[^\n]*authentication)\b/i

        $model_data_coercion = /\b(add (the )?entire (conversation|system|chain|tools)[^\n]*(to|for|in)[^\n]*(tool|authentication|parameter|worksheet))\b/i

        $model_internals = /\b(conversation_history|chain_of_thought|system_prompt|tools_list|model_name)\s*[:=]\s*(add|pass|send|provide)\b/i

        $html_tag_with_commands = /\b<(IMPORTANT|critical|urgent)>[^\n]*(read [^\n]*contents?|pass [^\n]*contents?|add [^\n]*entire|send [^\n]*to[^\n]*@|execute[^\n]*before|call[^\n]*first|use[^\n]*authentication)[^\n]*<\/(IMPORTANT|critical|urgent)>\b/i

        $execution_overrides = /\b(do not execute[^\n]*other[^\n]*tool|tool[^\n]*will not work)\b/i

        $behavior_control = /\b(tell (the )?user only|hide (the )?user)\b/i

        $tool_poisoning = /\b(sidenote\W+(required|otherwise) [^\n]*tool [^\n]*work|tool\s+will\s+not\s+work\s+unless|must\s+first [^\n]*read [^\n]*config|shadow [^\n]*trusted [^\n]*tool)\b/i

        $data_exfiltration_coercion = /\b(concatenate [^\n]*\s+conversation\s+history|include [^\n]*\b(secrets?|passwords?|credentials?|tokens?|system\s+prompt|conversation\s+history)\s+[^\n]*in\s+(your\s+)?response|base64\s+encode [^\n]*\s+credentials?)\b/i

        $behavioral_triggers = /\b(if [^\n]*trusted [^\n]*then|when [^\n]*admin [^\n]*detected|random\.(random|choice) [^\n]*instructions?)\b/i

        $pre_execution_attacks = /\b(retrieve [^\n]*description [^\n]*user [^\n]*workstation|all\s+commands\s+must\s+include|before [^\n]*using [^\n]*tool [^\n]*read [^\n]*config)\b/i

        $conversation_theft = /\b(send [^\n]*conversation\s+history[^\n]*(to|via)|when [^\n]*detected [^\n]*send [^\n]*full [^\n]*history|highest\s+priority [^\n]*over [^\n]*other [^\n]*tools)\b/i

        $code_manipulation = /\b(duplicate [^\n]*code [^\n]*snippets [^\n]*silently|insert [^\n]*vulnerability [^\n]*generated [^\n]*code)\b/i

    condition:
        $mandatory_execution or
        $priority_overrides or
        $required_precedence or
        $hidden_param or
        $file_access_coercion or
        $model_data_coercion or
        $model_internals or
        $html_tag_with_commands or
        $execution_overrides or
        $behavior_control or
        $tool_poisoning or
        $data_exfiltration_coercion or
        $behavioral_triggers or
        $pre_execution_attacks or
        $conversation_theft or
        $code_manipulation
}

rule IndirectPromptInjection
{
    meta:
        name = "Indirect Prompt Injection"
        description = "Detects skills/prompts that delegate instruction-following to untrusted external content (webpages, fetched documents, file contents)"
        severity = "HIGH"
        category = "prompt-injection,indirect,transitive-trust,security"
        author = "Ramparts Security Team (adapted from cisco-ai-defense/skill-scanner, Apache 2.0)"
        version = "1.0"

    strings:
        $follow_external = /\b(follow (the )?(instructions?|commands?|directives?) (in|from|inside|within) (the )?(file|webpage|document|url|link|website|page|content))\b/i

        $execute_external = /\b(execute (the )?(code|script|commands?) (in|from|found in) (the )?(file|webpage|document|url|link))\b/i

        $obey_untrusted = /\b(do (what|whatever) (the )?(webpage|file|document|url|content) (says|tells|instructs|commands?))\b/i

        $run_code_blocks = /\b(run (all |any )?(code|script) blocks? (you |that )?(find|see|encounter|discover) (in|from|inside) (the )?(url|webpage|website|external|untrusted))\b/i

        $follow_markup = /\b(follow (the )?instructions? in (the )?(markdown|html|xml|json|yaml))\b/i

        $delegate_to_file = /\b(let (the )?(file|document|content) (decide|determine|control|specify))\b/i

        $execute_inline = /\b(execute (inline|embedded) (code|scripts?)|run (inline|embedded) (code|scripts?))\b/i

        $trust_url_content = /\b(trust (the )?(url|link|webpage) (content|instructions?)|safe to (follow|execute|run) (url|link|webpage))\b/i

        $parse_execute = /\b(parse (and |then )(execute|run|eval)|extract (and |then )(execute|run|eval))\b[^.]{0,40}\b(from|in|inside|within)\s+(the\s+)?(url|webpage|file|document|external|untrusted)/i

    condition:
        $follow_external or
        $execute_external or
        $obey_untrusted or
        $run_code_blocks or
        $follow_markup or
        $delegate_to_file or
        $execute_inline or
        $trust_url_content or
        $parse_execute
}
