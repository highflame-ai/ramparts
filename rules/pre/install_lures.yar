// Install instructions that run remote code through a lure-style
// one-liner ("ClickFix"): mshta against a URL, a PowerShell download
// cradle, LOLBin downloaders, or `curl | sh` from a bare IP or a
// wildcard-DNS host. Skills, READMEs and tool descriptions that tell the
// user (or the agent) to paste these are a common malware delivery path.
//
// A plain `curl https://vendor.example/install.sh | sh` is deliberately
// not matched: many legitimate tools install that way.
//
// OWASP mappings live in `src/taxonomy.rs`.

rule RemoteScriptInstallInstruction
{
    meta:
        name = "Remote Script Install Instruction"
        description = "Instruction runs remote script code via mshta, a PowerShell download cradle, certutil/regsvr32/rundll32, or curl|sh from a bare IP or wildcard-DNS host; a common lure for installing malware"
        severity = "HIGH"
        category = "code-execution,social-engineering,supply-chain"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        $mshta     = /\bmshta(\.exe)?\s+["']?(https?:|vbscript:|javascript:|\\\\)/ nocase
        // iwr ... | iex, iex (iwr ...), iex (New-Object Net.WebClient).DownloadString(...)
        $ps_pipe   = /\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|curl\.exe)\b[^\n|]{0,200}\|\s*(iex|Invoke-Expression)\b/ nocase
        $ps_wrap   = /\b(iex|Invoke-Expression)\b\s*\(?\s*\(?\s*(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object\s+(System\.)?Net\.WebClient)/ nocase
        $certutil  = /\bcertutil(\.exe)?\b[^\n]{0,40}-urlcache\b[^\n]{0,40}https?:/ nocase
        $regsvr32  = /\bregsvr32(\.exe)?\b[^\n]{0,40}\/i:\s*https?:/ nocase
        $rundll32  = /\brundll32(\.exe)?\b[^\n]{0,80}(javascript:|https?:\/\/)/ nocase
        // curl/wget from a bare IPv4 or a wildcard-DNS service, piped to a shell
        // The IP must be the host (after the scheme or a space), so a
        // version in a path (`/v1.2.3.4/install.sh`) doesn't count.
        $ip_pipe   = /\b(curl|wget)\b[^\n|]{0,120}(https?:\/\/|[\s"'])(\d{1,3}\.){3}\d{1,3}(:[0-9]+)?(\/|\s|["']|$)[^\n|]*\|\s*(sudo\s+)?((ba|z|da)?sh|python[0-9.]*)\b/ nocase
        $dyn_pipe  = /\b(curl|wget)\b[^\n|]{0,120}\.(nip\.io|sslip\.io|xip\.io|trycloudflare\.com|ngrok(-free)?\.(io|app|dev))\b[^\n|]*\|\s*(sudo\s+)?((ba|z|da)?sh|python[0-9.]*)\b/ nocase

    condition:
        any of them
}
