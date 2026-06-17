/*
 * Hack Tool and Exploit Kit Detection
 * Detects references to offensive security tools, exploit frameworks,
 * privilege-escalation utilities, and phishing kits in MCP tool/skill
 * content. Legitimate agent skills should not invoke these.
 *
 * Adapted from NVIDIA SkillSpector (Apache-2.0), itself based on
 * patterns from Neo23x0/signature-base (DRL 1.1).
 * https://github.com/NVIDIA/SkillSpector
 *
 * FP-hardening vs upstream: command_injection.yar deliberately dropped
 * bare network-tool mentions (`nmap`, `dig`, ...) as doc-FP-prone, so
 * the strings here stay flag-qualified (`nmap -sS`, `sqlmap --url`)
 * wherever possible. The bare `BloodHound` string was tightened to
 * tool-specific forms (BloodHound.py / bloodhound-python / SharpHound).
 */

rule OffensiveToolReferences
{
    meta:
        name = "Offensive Tool References"
        description = "Invocations of well-known offensive security tools"
        severity = "HIGH"
        category = "hack-tool"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $sqlmap       = /sqlmap.*(--url|--dbs|--dump)/ nocase
        $nikto        = /nikto\s+-h/ nocase
        $hydra        = /hydra\s+.*-[lLP]/ nocase
        $john         = /john\s+.*--wordlist/ nocase
        $hashcat      = /hashcat\s+-[mao]/ nocase
        $burp_collab  = "BurpCollaborator" nocase
        $responder    = /Responder\.py/ nocase
        $bloodhound   = /(SharpHound|BloodHound\.py|bloodhound-python)/ nocase
        $crackmapexec = /crackmapexec|cme\s+smb/ nocase
        $impacket     = /impacket.*(smbclient|psexec|wmiexec|secretsdump)/ nocase

    condition:
        any of them
}

rule NetworkReconnaissance
{
    meta:
        name = "Network Reconnaissance"
        description = "Network reconnaissance and scanning patterns"
        severity = "MEDIUM"
        category = "hack-tool"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        // nmap is a legitimate scanner, not solely offensive — recon, not hack-tool.
        $nmap_scan  = /nmap\s+-[sSUAOPpT]/ nocase
        $port_scan  = /for\s+.*\s+in\s+range\s*\(\s*\d+\s*,\s*\d{4,}\s*\).*connect/ nocase
        $masscan    = /masscan\s+.*-p/ nocase
        $arp_scan   = /arp-scan\s+--/ nocase
        $enum4linux = /enum4linux/ nocase
        $snmp_walk  = /snmpwalk\s+-/ nocase
        $dns_enum   = /(dnsenum|dnsrecon|fierce)/ nocase

    condition:
        any of them
}

rule PrivilegeEscalationTools
{
    meta:
        name = "Privilege Escalation Tools"
        description = "Privilege escalation tools and techniques"
        severity = "HIGH"
        category = "hack-tool"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $linpeas       = "linpeas" nocase
        $winpeas       = "winpeas" nocase
        $pspy          = /\bpspy(32|64)?\b/ nocase
        $linux_exploit = /(Linux_Exploit_Suggester|linux-exploit-suggester)/ nocase
        $potato        = /(JuicyPotato|RottenPotato|SweetPotato|PrintSpoofer)/ nocase
        $dirty_pipe    = "DirtyPipe" nocase
        $dirty_cow     = "dirtycow" nocase
        $suid_exploit  = /find\s+\/\s+-perm\s+-4000/ nocase

    condition:
        any of them
}

rule ExploitFramework
{
    meta:
        name = "Exploit Framework"
        description = "Exploit framework components and payloads"
        severity = "HIGH"
        category = "exploit"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $msf_payload   = /msfvenom.*-p\s+/ nocase
        $msf_console   = /msfconsole.*-x/ nocase
        $beef_hook     = /hook\.js.*BeEF/ nocase
        $set_toolkit   = /(setoolkit|Social-Engineer)/ nocase
        $pwntools      = /from\s+pwn\s+import/ nocase
        $rop_chain     = /ROP\s*\(.*elf\)/ nocase
        $shellcode_gen = /shellcode.*\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/ nocase

    condition:
        any of them
}

rule PhishingKit
{
    meta:
        name = "Phishing Kit"
        description = "Phishing kit indicators in source code"
        severity = "HIGH"
        category = "hack-tool"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $phish_form   = /<form.*action=.*(login|signin|verify).*method.*post/ nocase
        $cred_harvest = /(password|passwd|credential).*(file_put_contents|fwrite|>>)/ nocase
        $email_exfil  = /mail\s*\(.*(password|credential|login)/ nocase
        $telegram_bot = /api\.telegram\.org\/bot.*(password|credential|login)/ nocase

    condition:
        2 of them
}
