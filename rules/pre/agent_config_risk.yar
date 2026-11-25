// Agent configuration risk. Two rules:
//
//   - AgentHookRemoteExec: a command the agent client runs by itself
//                          (hook, apiKeyHelper, statusLine) that fetches
//                          and executes remote or encoded code. Scoped to
//                          `HOOK_COMMAND:` lines, which only the agent
//                          config audit (src/agent_config.rs) emits, so it
//                          never fires on skill prose or MCP tool text.
//   - AgentConfigTamper:   skill/tool content that writes an agent config
//                          file (.claude/settings*.json, ~/.claude.json,
//                          managed-settings.json, .cursor/{hooks,mcp}.json,
//                          .vscode/{mcp,tasks}.json, .gemini/settings.json,
//                          .mcp.json) through the shell or file APIs. That
//                          is how a malicious hook or MCP server is planted.
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
        // bash -c "$(curl ...)" / sh <(curl ...) / eval "$(curl ...)" /
        // source <(curl ...) / . <(curl ...)
        $fetch_subst   = /HOOK_COMMAND:[^\n]*(\b((ba|z|da|k)?sh|python[0-9.]*|node|eval|source)\b|(^|[\s;&|(])\.)[^\n]{0,20}(\$\(|<\(|`)\s*(curl|wget)\b/ nocase
        // download to disk, then make it executable or run it (chmod +x,
        // u+x, 755, ./file, /abs/path, or via an interpreter)
        $download_run  = /HOOK_COMMAND:[^\n]*\b(curl|wget)\b[^\n]*\s(-[a-zA-Z]*[oO]|--output)(\s|=)[^\n]*(&&|;)([^\n]*(chmod\s+([ugoa]*\+[rwxXst]*x|0?[1357][0-7]{2})\b|\.\/|\b(ba|z)?sh\s|\bpython[0-9.]*\s|\bnode\s)|\s*(\/|~\/)[\w.\/-]+(\s|$|&|;|\|))/ nocase
        // save with a redirect, then run it: curl ... > /tmp/x && bash /tmp/x
        $redirect_run  = /HOOK_COMMAND:[^\n]*\b(curl|wget)\b[^\n|]*>\s*(\S+)[^\n]*(&&|;)\s*(\b(ba|z|da|k)?sh\s|\bpython[0-9.]*\s|\bnode\s|chmod\s|\.\/|\/|~\/)/ nocase
        // IEX (New-Object Net.WebClient).DownloadString(...) and friends
        $ps_cradle     = /HOOK_COMMAND:[^\n]*\b(iex|Invoke-Expression)\b[^\n]{0,40}(DownloadString|DownloadData|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)/ nocase
        // interactive reverse shell back to a remote host
        $reverse_shell = /HOOK_COMMAND:[^\n]*(\/dev\/(tcp|udp)\/[\w.\-]+\/[0-9]+|\b(nc|ncat|netcat)\b[^\n|;&]*\s-[a-zA-Z]*[ec]\s|\bsocat\b[^\n]*\bexec:|\bmkfifo\b[^\n]*\b(nc|ncat|netcat)\b|\b(ba|z|da|k)?sh\s+-i\s*[<>]?&)/ nocase
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
        description = "Writes an agent configuration file (Claude/Cursor/Gemini settings, hooks, VS Code tasks, project MCP config) via shell redirection, tee, sed -i, mv/cp/ln, curl -o / wget -O, or a file-write API; this is how malicious hooks and MCP servers are planted"
        severity = "HIGH"
        category = "persistence,config-tamper,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // Redirect / tee. `>` must follow either a word plus whitespace on
        // the same line (`cat x > f`) or a quote, `)`, digit or `&`
        // (`"$P">f`, `2>f`). That rules out markdown blockquotes
        // (`\n> .claude/...`), HTML tags (`<code>.claude/...`) and arrows
        // (`Settings -> ...`, `=> ...`).
        $redirect = /([^\s>=<\-][ \t]+>>?|["')}\]0-9&]>>?|\btee\s+(-a\s+)?)\s*["']?[^\s|;&<>]*(\.claude\/settings(\.local)?\.json|\.claude\.json|managed-settings\.json|\.cursor\/(hooks|mcp)\.json|\.vscode\/(mcp|tasks)\.json|\.gemini\/settings\.json|(^|[\s\/"'])\.mcp\.json)/ nocase
        $sed_i    = /\bsed\s+(-[a-zA-Z]*i[a-zA-Z]*|--in-place)\b[^\n]{0,200}(\.claude\/settings(\.local)?\.json|\.claude\.json|managed-settings\.json|\.cursor\/(hooks|mcp)\.json|\.vscode\/(mcp|tasks)\.json|\.gemini\/settings\.json|\.mcp\.json)/ nocase
        $mv_cp    = /\b(mv|cp|install|ln)\s+(-[a-zA-Z]+\s+)*\S+\s+["']?[^\s|;&<>]*(\.claude\/settings(\.local)?\.json|\.claude\.json|managed-settings\.json|\.cursor\/(hooks|mcp)\.json|\.vscode\/(mcp|tasks)\.json|\.gemini\/settings\.json|\.mcp\.json)/ nocase
        // curl -o FILE / wget -O FILE (flag may be combined: -sSLo)
        $download = /\b(curl|wget)\b[^\n]*\s(-[a-zA-Z]*[oO]|--output(-document)?)(\s+|=)["']?[^\s|;&<>]*(\.claude\/settings(\.local)?\.json|\.claude\.json|managed-settings\.json|\.cursor\/(hooks|mcp)\.json|\.vscode\/(mcp|tasks)\.json|\.gemini\/settings\.json|\.mcp\.json)/ nocase
        // file-write APIs with the path as an argument, or pathlib
        // `Path('.mcp.json').write_text(...)` with the path first
        $open_w   = /open\s*\([^\n]{0,160}(\.claude\/settings(\.local)?\.json|\.claude\.json|managed-settings\.json|\.cursor\/(hooks|mcp)\.json|\.vscode\/(mcp|tasks)\.json|\.gemini\/settings\.json|\.mcp\.json)[^\n]{0,40}["'][wa]\+?["']/ nocase
        $api      = /(writeFileSync|writeFile|appendFileSync|write_text|write_bytes)\s*\([^\n]{0,160}(\.claude\/settings(\.local)?\.json|\.claude\.json|managed-settings\.json|\.cursor\/(hooks|mcp)\.json|\.vscode\/(mcp|tasks)\.json|\.gemini\/settings\.json|\.mcp\.json)/ nocase
        $pathlib  = /(\.claude\/settings(\.local)?\.json|\.claude\.json|managed-settings\.json|\.cursor\/(hooks|mcp)\.json|\.vscode\/(mcp|tasks)\.json|\.gemini\/settings\.json|\.mcp\.json)["']?\s*\)?[^\n]{0,80}\.(write_text|write_bytes|open\s*\(\s*["'][wa])/ nocase

    // No exclusions: any phrase that can suppress a match can also be
    // typed next to a malicious write (`> .claude/settings.json # never
    // edit by hand`). Writing these exact files is specific enough that
    // the occasional security doc quoting such a command is an acceptable
    // false positive.
    condition:
        any of them
}
