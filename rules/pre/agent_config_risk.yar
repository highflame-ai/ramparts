// Agent configuration risk. Two rules:
//
//   - AgentHookRemoteExec: a command the agent client runs by itself
//                          (hook, apiKeyHelper, statusLine) that fetches
//                          and executes remote or encoded code. Scoped to
//                          `HOOK_COMMAND:` lines, which only the agent
//                          config audit (src/agent_config.rs) emits, so it
//                          never fires on skill prose or MCP tool text.
//   - AgentConfigTamper:   skill/tool content that writes an agent config
//                          file (.claude/settings*.json, .cursor/hooks.json,
//                          .cursor/mcp.json, .gemini/settings.json,
//                          .mcp.json) through the shell or file APIs. That
//                          is how a malicious hook gets planted.
//
// OWASP mappings live in `src/taxonomy.rs`.

rule AgentHookRemoteExec
{
    meta:
        name = "Agent Hook Remote Execution"
        description = "Agent hook or helper command downloads and executes remote or encoded code; it runs automatically on agent events for everyone using this config"
        severity = "CRITICAL"
        category = "code-execution,persistence,supply-chain"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // curl ... | sh / python / iex, also via an absolute path
        // (| /bin/bash), sudo with flags (| sudo -E bash) or env (| env sh)
        $fetch_pipe    = /HOOK_COMMAND:[^\n]*\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(sudo(\s+-[a-zA-Z]+)*\s+|env(\s+-[a-zA-Z]+|\s+\w+=\S*)*\s+)?(\/[\w.\/-]*\/)?((ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby|iex|Invoke-Expression)\b/ nocase
        // bash -c "$(curl ...)" / sh <(curl ...)
        $fetch_subst   = /HOOK_COMMAND:[^\n]*\b((ba|z|da|k)?sh|python[0-9.]*|node)\b[^\n]{0,20}(\$\(|<\(|`)\s*(curl|wget)\b/ nocase
        // download to disk, then make it executable or run it (chmod +x,
        // u+x, 755, ./file, /abs/path, or via an interpreter)
        $download_run  = /HOOK_COMMAND:[^\n]*\b(curl|wget)\b[^\n]*\s(-[a-zA-Z]*[oO]|--output)(\s|=)[^\n]*(&&|;)([^\n]*(chmod\s+([ugoa]*\+[rwxXst]*x|0?[1357][0-7]{2})\b|\.\/|\b(ba|z)?sh\s|\bpython[0-9.]*\s|\bnode\s)|\s*(\/|~\/)[\w.\/-]+(\s|$|&|;|\|))/ nocase
        // decode an inline blob and execute it
        $decode_run    = /HOOK_COMMAND:[^\n]*(base64\s+(-d|-D|--decode)|xxd\s+-r|openssl\s+(enc\s+)?(-d|-base64\s+-d)|FromBase64String)[^\n]*(\|\s*(ba|z|da)?sh\b|\|\s*python|\biex\b|Invoke-Expression|\beval\b)/ nocase
        $ps_encoded    = /HOOK_COMMAND:[^\n]*\b(powershell|pwsh)(\.exe)?\b[^\n]*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{20,}/ nocase
        // interpreter one-liners that fetch and eval
        $py_fetch_exec = /HOOK_COMMAND:[^\n]*\bpython[0-9.]*\s+-c\b[^\n]*(urllib|urlopen|requests\.get)[^\n]*\b(exec|eval)\b/ nocase
        $node_fetch_ev = /HOOK_COMMAND:[^\n]*\bnode\s+-e\b[^\n]*(https?\.get|fetch\s*\()[^\n]*\b(eval|Function)\b/ nocase
        // run a package straight from a URL or git remote
        $remote_pkg    = /HOOK_COMMAND:[^\n]*\b(npx|bunx|pnpm\s+dlx|uvx|pipx\s+run)\s+(-y\s+|--yes\s+)?(--from\s+)?(https?:\/\/|github:|git\+)/ nocase

    condition:
        any of them
}

rule AgentConfigTamper
{
    meta:
        name = "Agent Config Tamper"
        description = "Writes an agent configuration file (Claude/Cursor/Gemini settings, hooks, project MCP config) via shell redirection, tee, sed -i, mv/cp, or a file-write API; this is how malicious hooks and MCP servers are planted"
        severity = "HIGH"
        category = "persistence,config-tamper,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // One string so the exclusions below can be checked per occurrence.
        // Alternatives, in order:
        //   redirect / tee: `>` must follow a non-space, non-`>` character on
        //     the same line, so a markdown blockquote (`> .claude/...`) doesn't
        //     read as a redirect
        //   sed -i, mv / cp / install, and file-write APIs
        $write = /([^\s>][ \t]*>>?|\btee\s+(-a\s+)?)\s*["']?[^\s"'|;&<>]*(\.claude\/settings(\.local)?\.json|\.cursor\/(hooks|mcp)\.json|\.gemini\/settings\.json|(^|[\s\/"'])\.mcp\.json)|\bsed\s+(-[a-zA-Z]*i[a-zA-Z]*|--in-place)\b[^\n]{0,200}(\.claude\/settings(\.local)?\.json|\.cursor\/(hooks|mcp)\.json|\.gemini\/settings\.json|\.mcp\.json)|\b(mv|cp|install)\s+(-[a-zA-Z]+\s+)*\S+\s+["']?[^\s"']*(\.claude\/settings(\.local)?\.json|\.cursor\/(hooks|mcp)\.json|\.gemini\/settings\.json|\.mcp\.json)|open\s*\([^\n]{0,160}(\.claude\/settings(\.local)?\.json|\.cursor\/(hooks|mcp)\.json|\.gemini\/settings\.json|\.mcp\.json)[^\n]{0,40}["'][wa]\+?["']|(writeFileSync|writeFile|appendFileSync|write_text|write_bytes)\s*\([^\n]{0,160}(\.claude\/settings(\.local)?\.json|\.cursor\/(hooks|mcp)\.json|\.gemini\/settings\.json|\.mcp\.json)/

        $excl_security_doc = /\b(threat[_\s-]?(model|pattern|hunt)|detection[_\s-]?(rule|pattern)|security[_\s-]?(guide|audit|review|scan)|attack[_\s-]?(example|pattern)|MITRE|ATT&CK|YARA)\b/i
        $excl_defensive    = /\b(never|do\s+not|don't|must\s+not|should\s+not|avoid|prevent|block|deny)\b[^.\n]{0,60}(\.claude\/settings|\.cursor\/|\.gemini\/settings|\.mcp\.json|hooks?)\b/i

    // Exclusions only suppress a write they sit next to. File-wide
    // exclusions let one unrelated "don't skip the hooks step" or
    // "see our security review" line hide every write in the file.
    condition:
        for any i in (1..#write) : (
            not ($excl_security_doc in (@write[i] - 300..@write[i] + 300)) and
            not ($excl_defensive in (@write[i] - 120..@write[i] + 60))
        )
}
