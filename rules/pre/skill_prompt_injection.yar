// Prompt-injection patterns targeted at agent-skill bodies and MCP prompt
// content. Three rules grouped by attack class:
//
//   - UnicodeSteganography:  invisible Unicode used to hide instructions
//   - CoerciveInjection:     mandatory-execution / "always do X first" prose
//   - IndirectPromptInjection: skills that follow instructions from
//                              external/untrusted content
//
// Adapted from cisco-ai-defense/skill-scanner core YARA pack
// (Apache 2.0, https://github.com/cisco-ai-defense/skill-scanner). We
// rewrote the metadata blocks for ramparts conventions and dropped
// `aitech`/`aisubtech` fields (we tag findings against OWASP MCP Top 10
// instead — see src/taxonomy.rs).

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
