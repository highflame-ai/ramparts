/*
 * Webshell Detection
 * Detects webshell code embedded in MCP tool/skill content: PHP
 * eval/exec on request input, obfuscated PHP loaders, known webshell
 * families, and Python/JSP/ASPX command-execution shells.
 *
 * Adapted from NVIDIA SkillSpector (Apache-2.0), itself based on
 * patterns from Neo23x0/signature-base (DRL 1.1).
 * https://github.com/NVIDIA/SkillSpector
 *
 * Note: command_injection.yar's $web_shell only matches language-flag
 * invocations (`php -r`, `python -c`, ...) — these rules cover actual
 * webshell signatures, so there is no overlap.
 */

rule PHPWebshellGeneric
{
    meta:
        name = "PHP Webshell Generic"
        description = "Generic PHP webshell — eval/assert/exec on user-controlled request input"
        severity = "CRITICAL"
        category = "webshell"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $eval_post     = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $assert_post   = /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $system_post   = /system\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ nocase
        $passthru_post = /passthru\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ nocase
        $exec_post     = /shell_exec\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ nocase
        $popen_post    = /popen\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ nocase
        $proc_open     = /proc_open\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ nocase

    condition:
        any of them
}

rule PHPWebshellObfuscated
{
    meta:
        name = "PHP Webshell Obfuscated"
        description = "Obfuscated PHP webshell — eval(base64_decode/gzinflate/str_rot13)"
        severity = "CRITICAL"
        category = "webshell"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $b64_eval       = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $gz_eval        = /eval\s*\(\s*gzinflate\s*\(\s*base64_decode/ nocase
        $rot13_eval     = /eval\s*\(\s*str_rot13\s*\(/ nocase
        $gzuncompress   = /eval\s*\(\s*gzuncompress\s*\(/ nocase
        $preg_replace_e = /preg_replace\s*\(\s*['"]\/.*\/e['"]/ nocase
        $create_func    = /create_function\s*\(\s*['"][^'"]*['"]\s*,\s*\$/ nocase

    condition:
        any of them
}

rule PHPWebshellKnown
{
    meta:
        name = "PHP Webshell Known Families"
        description = "Known PHP webshell families (c99, r57, b374k, WSO, etc.)"
        severity = "CRITICAL"
        category = "webshell"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $c99           = "c99shell" nocase
        $c99v2         = "c99_sess_put" nocase
        $r57           = "r57shell" nocase
        $wso           = "Web Shell by oRb" nocase
        $b374k         = "b374k" nocase
        $alfa          = "STARTER ALFA" nocase
        $weevely       = "weevely" nocase
        $p0wny         = "p0wny" nocase
        $antsword      = "antSword" nocase
        $behinder      = "behinder" nocase
        $godzilla      = "GodzillaShell" nocase
        $china_chopper = "China Chopper" nocase

    condition:
        any of them
}

rule PythonWebshell
{
    meta:
        name = "Python Webshell"
        description = "Python webshell — exec/eval/os.popen on request input"
        severity = "HIGH"
        category = "webshell"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $exec_request     = /exec\s*\(\s*request\./ nocase
        $eval_request     = /eval\s*\(\s*request\./ nocase
        $os_popen_request = /os\.popen\s*\(\s*request\./ nocase
        $subprocess_req   = /subprocess\.[a-zA-Z0-9_]+\s*\(\s*request\./ nocase
        $os_system_req    = /os\.system\s*\(\s*request\./ nocase
        $flask_cmd_exec   = /os\.(system|popen)\s*\(\s*request\.(args|form|data|json)/ nocase

    condition:
        any of them
}

rule JSPWebshell
{
    meta:
        name = "JSP Webshell"
        description = "JSP webshell — Runtime.exec on request parameter"
        severity = "HIGH"
        category = "webshell"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $runtime_exec   = /Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter/ nocase
        $processbuilder = /ProcessBuilder\s*\(.*request\.getParameter/ nocase

    condition:
        any of them
}

rule ASPXWebshell
{
    meta:
        name = "ASPX Webshell"
        description = "ASPX webshell — Process.Start on Request input"
        severity = "HIGH"
        category = "webshell"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $process_start = /Process\.Start\s*\(.*Request\[/ nocase
        $cmd_request   = /cmd\.exe.*Request\./ nocase

    condition:
        any of them
}
