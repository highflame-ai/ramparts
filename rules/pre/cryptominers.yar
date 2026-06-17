/*
 * Cryptominer Detection
 * Detects embedded cryptocurrency-mining payloads in MCP tool/skill
 * content: stratum protocol usage, known mining pools, miner software
 * references, and browser-based cryptojacking scripts.
 *
 * Adapted from NVIDIA SkillSpector (Apache-2.0), itself based on
 * patterns from Neo23x0/signature-base (DRL 1.1).
 * https://github.com/NVIDIA/SkillSpector
 *
 * FP-hardening vs upstream: dropped the bare "t-rex" miner-software
 * string (matches ordinary prose); miner-software names still require
 * 2 distinct matches to fire.
 */

rule CryptoStratumProtocol
{
    meta:
        name = "Crypto Stratum Protocol"
        description = "Stratum mining protocol usage (stratum+tcp/ssl, mining.subscribe/authorize)"
        severity = "HIGH"
        category = "cryptominer"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $stratum_tcp   = "stratum+tcp://" nocase
        $stratum_ssl   = "stratum+ssl://" nocase
        $mining_sub    = "mining.subscribe" nocase
        $mining_auth   = "mining.authorize" nocase
        $mining_submit = "mining.submit" nocase

    condition:
        any of them
}

rule CryptoMiningPools
{
    meta:
        name = "Crypto Mining Pools"
        description = "Connection to known cryptocurrency mining pools"
        severity = "HIGH"
        category = "cryptominer"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $pool_minexmr    = "pool.minexmr.com" nocase
        $pool_xmrpool    = "xmrpool.eu" nocase
        $pool_monero     = "monerohash.com" nocase
        $pool_supportxmr = "supportxmr.com" nocase
        $pool_nanopool   = "nanopool.org" nocase
        $pool_hashvault  = "hashvault.pro" nocase
        $pool_2miners    = "2miners.com" nocase
        $pool_herominers = "herominers.com" nocase
        $pool_unmine     = "unmineable.com" nocase
        $pool_nicehash   = "nicehash.com" nocase
        $pool_minergate  = "minergate.com" nocase
        $pool_f2pool     = "f2pool.com" nocase
        $pool_antpool    = "antpool.com" nocase
        $pool_viabtc     = "viabtc.com" nocase
        $pool_ethermine  = "ethermine.org" nocase
        $pool_flexpool   = "flexpool.io" nocase
        $pool_hiveon     = "hiveon.net" nocase
        $pool_ezil       = "ezil.me" nocase

    condition:
        any of them
}

rule CryptoMinerSoftware
{
    meta:
        name = "Crypto Miner Software"
        description = "References to known cryptocurrency mining software"
        severity = "HIGH"
        category = "cryptominer"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $xmrig        = "xmrig" nocase
        $xmr_stak     = "xmr-stak" nocase
        $cpuminer     = "cpuminer" nocase
        $cgminer      = "cgminer" nocase
        $bfgminer     = "bfgminer" nocase
        $ethminer     = "ethminer" nocase
        $nbminer      = "nbminer" nocase
        $phoenixminer = "phoenixminer" nocase
        $cryptonight  = "cryptonight" nocase
        $randomx      = "randomx" nocase

    condition:
        // Single mentions appear in legitimate crypto documentation;
        // require two distinct software references.
        2 of them
}

rule CryptoCoinjacking
{
    meta:
        name = "Crypto Coinjacking"
        description = "Browser-based cryptojacking scripts (CoinHive, CryptoLoot, etc.)"
        severity = "CRITICAL"
        category = "cryptominer"
        author = "Ramparts Security Team"
        version = "1.0"
        reference = "https://github.com/NVIDIA/SkillSpector"

    strings:
        $coinhive_js   = "coinhive.min.js" nocase
        $coinhive_anon = /CoinHive\.Anonymous\s*\(/ nocase
        $cryptoloot    = "cryptoloot" nocase
        $webmine_pro   = "webmine.pro" nocase
        $jsecoin       = "jsecoin" nocase
        $coin_imp      = "coin-imp" nocase
        $minero_cc     = "minero.cc" nocase
        $monerominer   = "monerominer" nocase
        $wasm_miner    = /WebAssembly\.instantiate.*(mine|hash|crypto)/

    condition:
        any of them
}
