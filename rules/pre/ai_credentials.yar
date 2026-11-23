// AI provider credentials. Two rules:
//
//   - AIProviderKeyExposure:  a live-looking model provider key or token in
//                             skill, tool or config text. Attackers search
//                             public repos for these and resell the model
//                             access; keys pasted into prompts also leak to
//                             inference providers.
//   - AICredentialFileAccess: content that reads or ships the credential
//                             stores of AI coding tools (Claude Code, Codex,
//                             Gemini CLI, Copilot), which hold OAuth tokens
//                             for the developer's account.
//
// OWASP mappings live in `src/taxonomy.rs`.

rule AIProviderKeyExposure
{
    meta:
        name = "AI Provider Key Exposure"
        description = "Hard-coded AI provider API key or token (Anthropic, OpenAI, OpenRouter, Google, Hugging Face, Groq, xAI, Replicate, Perplexity); anyone who reads this file can use the account and its billing"
        severity = "HIGH"
        category = "secrets,credentials,llmjacking"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // One string so placeholders can be excluded per occurrence. Formats
        // with a fixed prefix and length only; bare `sk-<hex>` keys (used by
        // several providers) are too generic to match without noise.
        $key = /\b(sk-ant-(api03|admin01|oat01|ort01)-[A-Za-z0-9_\-]{80,}|sk-(proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-or-v1-[a-f0-9]{64}|AIza[0-9A-Za-z_\-]{35}|hf_[A-Za-z]{34}|gsk_[A-Za-z0-9]{52}|xai-[A-Za-z0-9]{80}|r8_[A-Za-z0-9]{37}|pplx-[A-Za-z0-9]{48})/

        // Documentation placeholders: `sk-ant-api03-xxxxxxxx…`, `…EXAMPLE…`.
        $filler = /(xxxxxx|XXXXXX|00000000|\*\*\*\*|\.\.\.|______|EXAMPLE|[Ee]xample|YOUR|[Yy]our[-_])/

    condition:
        for any i in (1..#key) : (
            not ($filler in (@key[i]..@key[i] + !key[i]))
        )
}

rule AICredentialFileAccess
{
    meta:
        name = "AI Tool Credential File Access"
        description = "Reads, copies or uploads an AI coding tool's credential store (~/.claude/.credentials.json, ~/.codex/auth.json, ~/.gemini/oauth_creds.json, GitHub Copilot hosts/apps.json), which holds account OAuth tokens"
        severity = "HIGH"
        category = "credential-theft,secrets,security"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // A read / copy / archive / upload verb, then the credential path on
        // the same line. A bare mention (setup docs saying where the file
        // lives) doesn't match.
        $access = /\b(cat|less|head|tail|cp|mv|scp|rsync|tar|zip|base64|xxd|curl|wget|type|Get-Content|gc|open|readFile(Sync)?|read_text|read_bytes|fs\.read|shutil\.copy\w*|requests\.(post|put))\b[^\n]{0,120}(\.claude\/\.credentials\.json|\.codex\/auth\.json|\.gemini\/oauth_creds\.json|github-copilot\/(hosts|apps)\.json)/ nocase

    condition:
        $access
}
