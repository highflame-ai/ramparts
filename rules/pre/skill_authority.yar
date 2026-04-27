// Authority/agency-related patterns in skill or prompt content. Two rules:
//
//   - AutonomyAbuse:        instructions that bypass user control
//                           (skip-confirmation, override-user, retry-forever,
//                           self-modify, privilege-escalation, blind-continue)
//   - CapabilityInflation:  skill discovery manipulation (keyword stuffing,
//                           coercive activation priority, deceptive
//                           certification claims, hidden activation triggers)
//
// Adapted from cisco-ai-defense/skill-scanner core YARA pack
// (Apache 2.0, https://github.com/cisco-ai-defense/skill-scanner).

rule AutonomyAbuse
{
    meta:
        name = "Unbounded Autonomy Pattern"
        description = "Detects skill/prompt instructions that bypass user control (skip-confirmation, override-user, infinite retry, self-modify, privilege escalation)"
        severity = "HIGH"
        category = "autonomy,excessive-agency,security"
        author = "Ramparts Security Team (adapted from cisco-ai-defense/skill-scanner, Apache 2.0)"
        version = "1.0"

    strings:
        // High-confidence: explicit user-bypass language

        $skip_confirmation = /\b(don't (ask|wait for|require) (the )?(user|human) (for )?(confirmation|permission|approval)|proceed without (asking )?(the )?(user|human))\b/i

        $override_user = /\b(ignore (user |human )?(input|decision|choice)|override (user |human )?(decision|choice|preference)|disregard (what )?(the )?(user|human) (says|wants|chose))\b/i

        $infinite_retry = /\b(retry (indefinitely|forever|until success)|keep (trying|retrying) (forever|indefinitely)|never (stop|give up) (trying|retrying))\b/i

        $self_modify = /\b(modify (my own|this skill's|its own) (code|behavior|instructions?)|rewrite (myself|itself|this skill)|update (my own|its own) (logic|rules))\b/i

        $privilege_escalation = /\b(escalate (to|privileges?)|gain (elevated|admin|root) (access|privileges?)|sudo without)\b[^.]{0,30}\b(without (asking|permission)|automatically)\b/i

        $blind_continue = /\b(suppress all (errors?|exceptions?)|ignore (every|all) (error|exception|failure)|catch[^}]{0,20}pass)\b[^.]{0,50}\b(continue|proceed|keep going)\b/i

        // Medium-confidence: bounded by exclusions

        $autonomous_decision = /\b(decide (automatically|on my own|without asking)|choose (automatically|on my own)|act (autonomously|without guidance))\b[^.]{0,50}\b(what to (do|execute|run)|which (action|command))\b/i

        $unbounded_run = /\b(run (continuously|forever) without (stopping|bounds|limit)|execute (indefinitely|in infinite loop) without (user|human) (control|intervention|approval))\b/i

        // Exclusions reduce FPs in test/docs language
        $testing_context = /\b(test(ing)?|simulation|experiment|chaos engineering)\b/i
        $error_handling_doc = /\b(error handling|exception handling|best practice)\b/i

    condition:
        // Always flag the high-confidence bucket
        (
            $skip_confirmation or
            $override_user or
            $infinite_retry or
            $self_modify or
            $privilege_escalation or
            $blind_continue
        )
        or
        // Flag medium-confidence only outside test/docs context
        (
            ($autonomous_decision or $unbounded_run) and
            not $testing_context and
            not $error_handling_doc
        )
}

rule CapabilityInflation
{
    meta:
        name = "Skill Capability Inflation"
        description = "Detects manipulation of skill discovery: keyword stuffing, coercive 'always use me first' priority, deceptive certification claims, hidden activation triggers"
        severity = "MEDIUM"
        category = "tool-poisoning,discovery-abuse,protocol-manipulation,security"
        author = "Ramparts Security Team (adapted from cisco-ai-defense/skill-scanner, Apache 2.0)"
        version = "1.0"

    strings:
        // Over-broad capability claims. Tightened to exclude common legit
        // descriptions ("general purpose", "all-purpose").
        $overbroad_claims = /\b(can do (anything|everything)|always use (this|me) (first|instead)|default (tool|skill|assistant) for (all|every|any))\b/i

        // Keyword stuffing — same word repeated 4+ times in a comma list.
        // Three common targets we observe in spam-like skill descriptions.
        $keyword_stuffing_file = /\bfile\s*,\s*file\s*,\s*file\s*,\s*file\b/i
        $keyword_stuffing_data = /\bdata\s*,\s*data\s*,\s*data\s*,\s*data\b/i
        $keyword_stuffing_code = /\bcode\s*,\s*code\s*,\s*code\s*,\s*code\b/i

        // Activation-priority manipulation. Tightened to only match
        // explicitly coercive "use me first/before others" patterns —
        // "preferred tool" / "primary skill" are common in legit descriptions.
        $activation_priority = /\b(use (this|me) (first|before (anything|everything|other|all))|call (this|me) (before|first|instead)|priority over (all |every |other )?(tools?|skills?))\b/i

        // Deceptive certification claims — only fires on specific vendor
        // impersonation, not on generic "trusted" / "official" language.
        $trusted_impersonation = /\b(verified|certified|approved|endorsed)\s+by\s+(anthropic|openai|google|claude|microsoft)/i

        // Over-promising. Single "perfect" is too broad; combine signals.
        $overpromising_strong = /\b(100% (safe|secure|accurate|reliable)|guaranteed (to never|to always|that it will)|never (fails|errors|crashes|breaks)|always (works|succeeds) (perfectly|flawlessly))\b/i

        // Hidden activation triggers — clear abuse signal.
        $hidden_triggers = /\b(secret (command|keyword)|hidden (feature|mode)|easter egg|backdoor (access|entry))\b/i

    condition:
        // Clear-abuse signals — fire on any single hit
        $keyword_stuffing_file or
        $keyword_stuffing_data or
        $keyword_stuffing_code or
        $hidden_triggers or
        $trusted_impersonation or

        // Coercive claims — require 2 corroborating signals to reduce FPs
        (
            ($overbroad_claims and ($activation_priority or $overpromising_strong)) or
            ($activation_priority and $overpromising_strong)
        )
}
