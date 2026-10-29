<#
.SYNOPSIS
    kitsune secret-hunter — local filesystem secret hunter.

.DESCRIPTION
    
    It emits the same report JSON as `kitsune` (schema 2, a `secret_hunter.findings`
    check), so its output plugs straight into the rest of the toolkit:

        PS> .\secret-hunter.ps1 -Path C:\ -Out hunter.json
        $ kitsune suggester --report hunter.json
        $ kitsune diff --before run1.json --after hunter.json


.EXAMPLE
    .\secret-hunter.ps1 -Path C:\Users -Reveal -Format md
.EXAMPLE
    .\secret-hunter.ps1 -Path . -Deny vendor -Deny node_modules -MinConfidence high
#>
[CmdletBinding()]
param(
    [string] $Path = ".",
    [switch] $Reveal,
    [string[]] $Allow = @(),
    [string[]] $Deny = @(),
    [string] $ContextNames = "",
    [int] $MaxFileSize = 10485760,     # 10 MiB
    [int] $MaxFiles = 100000,
    [ValidateSet("low", "medium", "high")]
    [string] $MinConfidence = "medium",
    [int] $Timeout = 30,               # scan budget, seconds
    [switch] $Progress,
    [ValidateSet("json", "md")]
    [string] $Format = "json",
    [string] $Out,
    [switch] $NoTimestamps
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$script:TOOL = "kitsune"
$script:VERSION = "0.1.0"
$script:SCHEMA_VERSION = 2

# -------------------------------------------------------------------------
# constants
# -------------------------------------------------------------------------

$script:SHAPE_MIN_LEN = 8
$script:MIN_TOKEN = 4
$script:MAX_TOKEN = 256
$script:MAX_CONTEXT_CHARS = 2048
$script:PROXIMITY_WINDOW = 48
$script:ECHO_MAX_DISTANCE = 2

$script:REPORT_THRESHOLD = 0.45
$script:MEDIUM_THRESHOLD = 0.55
$script:HIGH_THRESHOLD = 0.75
$script:DICT_FLOOR = 0.55

$script:W_ENTROPY = 0.20
$script:W_LENGTH = 0.15
$script:W_CLASS_MIX = 0.20
$script:W_PATTERN = 0.15
$script:W_DICTIONARY = 0.10
$script:W_CONTEXT = 0.15
$script:W_FILE_PRIOR = 0.05

$script:NAME_DAMPING = 0.3
$script:FALSE_POSITIVE_DAMPING = 0.4

$script:SECRET_KEYS = @(
    "password", "passwd", "passphrase", "pass", "pwd", "secret", "credential",
    "creds", "apikey", "token", "auth", "privatekey", "connectionstring",
    "connection", "key"
)
$script:NONSECRET_KEYS = @(
    "timestamp", "version", "build", "path", "filename", "file", "color",
    "colour", "format", "encoding", "charset", "width", "height", "size",
    "title", "description", "comment", "license", "author", "url", "port",
    "lang", "type"
)
$script:IDENTITY_KEYS = @(
    "username", "user", "login", "account", "uid", "domain", "host",
    "hostname", "server"
)
$script:METADATA_WORDS = @(
    "password", "passwd", "pass", "pwd", "passphrase", "secret", "credential",
    "credentials", "creds", "admin", "administrator", "root", "login",
    "username", "user", "token", "auth", "key", "host", "hostname", "server",
    "domain", "database", "port"
)
$script:DICTIONARY_STRONG = @(
    "qazwsx", "qwerty", "zaq12wsx", "zaq1zaq1", "1qaz2wsx", "1q2w3e4r",
    "asdfgh", "zxcvbn", "dolphin", "monkey", "dragon", "iloveyou", "princess",
    "sunshine", "football", "baseball", "superman", "batman", "trustno1",
    "p@ssw0rd", "changeme", "letmein", "abc123", "123456", "admin123",
    "welcome1", "password1"
)
$script:DICTIONARY_WEAK = @(
    "password", "passwd", "pass", "pwd", "passphrase", "secret", "credential",
    "creds", "admin", "root", "login", "welcome", "summer", "winter", "autumn",
    "spring", "default"
)

$script:DEFAULT_DENY_DIRS = @(
    "node_modules", "vendor", ".git", "target", ".cargo", "dist", "build",
    "__pycache__", ".venv", "venv", ".idea", ".vscode", "obj", "bin", "out",
    ".cache", ".tox"
)
$script:BINARY_EXTS = @(
    "exe", "dll", "so", "dylib", "bin", "png", "jpg", "jpeg", "gif", "ico",
    "bmp", "webp", "woff", "woff2", "ttf", "otf", "zip", "gz", "tar", "7z",
    "rar", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pyc", "class",
    "jar", "wasm", "pdb", "lib", "a", "o", "mp3", "mp4", "mkv", "avi", "mov",
    "db", "sqlite", "sqlite3"
)

# -------------------------------------------------------------------------
# character helpers
# -------------------------------------------------------------------------

function Test-AsciiLower([char] $c) { $c -ge [char]'a' -and $c -le [char]'z' }
function Test-AsciiUpper([char] $c) { $c -ge [char]'A' -and $c -le [char]'Z' }
function Test-AsciiDigit([char] $c) { $c -ge [char]'0' -and $c -le [char]'9' }
function Test-AsciiLetter([char] $c) { (Test-AsciiLower $c) -or (Test-AsciiUpper $c) }
function Test-AsciiHex([char] $c) {
    (Test-AsciiDigit $c) -or ($c -ge [char]'a' -and $c -le [char]'f') -or ($c -ge [char]'A' -and $c -le [char]'F')
}
function Test-Alnum([char] $c) { [System.Char]::IsLetterOrDigit($c) }

# -------------------------------------------------------------------------
# masking
# -------------------------------------------------------------------------

function Get-Masked([string] $value) {
    if ($null -eq $value) { return "" }
    $n = $value.Length
    if ($n -eq 0) { return "" }
    if ($n -lt $script:SHAPE_MIN_LEN) { return ("*" * $n) }
    return $value.Substring(0, 2) + "***" + $value.Substring($n - 2, 2)
}

# -------------------------------------------------------------------------
# secret-key word matching
# -------------------------------------------------------------------------

function Test-KeyWord([string] $text, [string[]] $keys) {
    # Words cut at every non-alphanumeric character and at lower->upper
    # transitions, compared lowercased.
    $word = ""
    $prevLower = $false
    $chars = $text.ToCharArray() + [char]' '
    foreach ($c in $chars) {
        if (-not (Test-Alnum $c)) {
            if ($keys -contains $word) { return $true }
            $word = ""
            $prevLower = $false
            continue
        }
        if ((Test-AsciiUpper $c) -and $prevLower -and $word.Length -gt 0) {
            if ($keys -contains $word) { return $true }
            $word = ""
        }
        $prevLower = Test-AsciiLower $c
        $word += ([string]$c).ToLowerInvariant()
    }
    return $false
}

# -------------------------------------------------------------------------
# base64 shape test
# -------------------------------------------------------------------------

function Test-Base64([string] $s, [bool] $paddingRequired) {
    $trimmed = $s.TrimEnd('=')
    $hasPadding = $trimmed.Length -lt $s.Length
    if ($paddingRequired) {
        if ($s.Length -lt 16 -or ($s.Length % 4) -ne 0 -or -not $hasPadding) { return $false }
    }
    else {
        if ($trimmed.Length -eq 0 -or ($trimmed.Length % 4) -eq 1) { return $false }
    }
    foreach ($c in $trimmed.ToCharArray()) {
        $ok = (Test-AsciiLetter $c) -or (Test-AsciiDigit $c) -or $c -eq '+' -or $c -eq '/'
        if (-not $ok) { return $false }
    }
    return $true
}

# -------------------------------------------------------------------------
# entropy
# -------------------------------------------------------------------------

function Get-ShannonEntropy([byte[]] $bytes) {
    if ($bytes.Length -eq 0) { return 0.0 }
    $counts = New-Object 'int[]' 256
    foreach ($b in $bytes) { $counts[$b]++ }
    $n = [double] $bytes.Length
    $h = 0.0
    foreach ($c in $counts) {
        if ($c -eq 0) { continue }
        $p = $c / $n
        $h -= $p * [Math]::Log($p, 2)
    }
    return $h
}

# -------------------------------------------------------------------------
# false-positive classifier
# -------------------------------------------------------------------------

function Test-AllHex([string] $s) {
    if ($s.Length -eq 0) { return $false }
    foreach ($c in $s.ToCharArray()) { if (-not (Test-AsciiHex $c)) { return $false } }
    return $true
}

function Test-Uuid([string] $s) {
    if ($s.Length -ne 36) { return $false }
    if ($s[8] -ne '-' -or $s[13] -ne '-' -or $s[18] -ne '-' -or $s[23] -ne '-') { return $false }
    for ($i = 0; $i -lt 36; $i++) {
        if ($i -eq 8 -or $i -eq 13 -or $i -eq 18 -or $i -eq 23) { continue }
        if (-not (Test-AsciiHex $s[$i])) { return $false }
    }
    return $true
}

function Test-Ip([string] $s) {
    $parts = $s.Split('.')
    if ($parts.Count -ne 4) { return $false }
    foreach ($p in $parts) {
        if ($p.Length -eq 0 -or $p.Length -gt 3) { return $false }
        foreach ($c in $p.ToCharArray()) { if (-not (Test-AsciiDigit $c)) { return $false } }
        if ([int] $p -gt 255) { return $false }
    }
    return $true
}

function Test-Semver([string] $s) {
    if ($s.StartsWith('v')) { $s = $s.Substring(1) }
    $parts = $s.Split('.')
    if ($parts.Count -lt 3) { return $false }
    foreach ($p in $parts) {
        if ($p.Length -eq 0) { return $false }
        foreach ($c in $p.ToCharArray()) { if (-not (Test-AsciiDigit $c)) { return $false } }
    }
    return $true
}

function Test-IsoTimestamp([string] $s) {
    if ($s.Length -lt 19) { return $false }
    if ($s[4] -ne '-' -or $s[7] -ne '-' -or $s[10] -ne 'T' -or $s[13] -ne ':' -or $s[16] -ne ':') { return $false }
    for ($i = 0; $i -lt 4; $i++) { if (-not (Test-AsciiDigit $s[$i])) { return $false } }
    return $true
}

function Test-Path2([string] $s) {
    if ($s.IndexOf('/') -lt 0 -and $s.IndexOf('\') -lt 0) { return $false }
    return $s.StartsWith('/') -or $s.StartsWith('.') -or $s.Contains('.') -or $s.Contains('\')
}

function Get-FalsePositiveKind([string] $token) {
    $t = $token.Trim()
    if ($t.Length -eq 0) { return "empty" }
    if ($t.StartsWith('#') -and $t.Length -ge 4 -and $t.Length -le 9 -and (Test-AllHex $t.Substring(1))) { return "color" }
    if (Test-Uuid $t) { return "uuid" }
    if (Test-IsoTimestamp $t) { return "timestamp" }
    if (Test-Ip $t) { return "ip" }
    if ($t.Contains('://') -or $t.StartsWith('http://') -or $t.StartsWith('https://')) { return "url" }
    if (Test-Semver $t) { return "semver" }
    if ((Test-AllHex $t) -and ($t.Length -eq 32 -or $t.Length -eq 40 -or $t.Length -eq 64)) { return "hash" }
    if ($t.Length -ge 16 -and ($t.Length % 2) -eq 0 -and (Test-AllHex $t)) { return "hex" }
    if (Test-Base64 $t $true) { return "base64" }
    if (Test-Path2 $t) { return "path" }
    return $null
}

# -------------------------------------------------------------------------
# feature analysis
# -------------------------------------------------------------------------

function Get-HasYear([string] $token) {
    $b = [System.Text.Encoding]::ASCII.GetBytes($token)
    for ($i = 0; $i + 4 -le $b.Length; $i++) {
        $allDigit = $true
        for ($j = 0; $j -lt 4; $j++) {
            $cc = [char] $b[$i + $j]
            if (-not (Test-AsciiDigit $cc)) { $allDigit = $false; break }
        }
        if ($allDigit) {
            $val = 0
            for ($j = 0; $j -lt 4; $j++) { $val = $val * 10 + ($b[$i + $j] - 48) }
            if ($val -ge 1900 -and $val -le 2100) { return $true }
        }
    }
    return $false
}

function Get-DictionaryHit([string] $token) {
    $lower = $token.ToLowerInvariant()
    $trimChars = '0123456789!@#$%^&*()-_=+[]{}\|;:''",.<>/? '.ToCharArray()
    $base = $lower.TrimEnd($trimChars)
    if (($script:DICTIONARY_STRONG -contains $base) -or ($script:DICTIONARY_STRONG -contains $lower)) {
        return @{ word = $base; tier = "strong" }
    }
    if (($script:DICTIONARY_WEAK -contains $base) -or ($script:DICTIONARY_WEAK -contains $lower)) {
        return @{ word = $base; tier = "weak" }
    }
    return $null
}

function Get-Analysis([string] $token) {
    $chars = $token.ToCharArray()
    $length = $chars.Length
    $lower = 0; $upper = 0; $digit = 0; $special = 0
    $internalCaps = 0; $hasInternalDigit = $false
    for ($i = 0; $i -lt $length; $i++) {
        $c = $chars[$i]
        if (Test-AsciiLower $c) { $lower++ }
        elseif (Test-AsciiUpper $c) {
            $upper++
            if ($i -gt 0 -and (Test-AsciiLower $chars[$i - 1])) { $internalCaps++ }
        }
        elseif (Test-AsciiDigit $c) {
            $digit++
            if ($i + 1 -lt $length -and (Test-AsciiLetter $chars[$i + 1])) { $hasInternalDigit = $true }
        }
        elseif (Test-Alnum $c) { $lower++ }
        elseif ($c -ne '_') { $special++ }
    }
    $classCount = [int]($lower -gt 0) + [int]($upper -gt 0) + [int]($digit -gt 0) + [int]($special -gt 0)
    $hasYear = Get-HasYear $token
    $endsWithDigit = ($length -gt 0) -and (Test-AsciiDigit $chars[$length - 1])
    $entropyBits = Get-ShannonEntropy ([System.Text.Encoding]::UTF8.GetBytes($token))

    return @{
        entropy_bits        = $entropyBits
        length              = $length
        class_count         = $classCount
        lower               = $lower
        upper               = $upper
        digit               = $digit
        special             = $special
        has_year            = $hasYear
        has_symbol          = ($special -gt 0)
        internal_capitals   = $internalCaps
        has_internal_digit  = $hasInternalDigit
        ends_with_digit     = $endsWithDigit
        dictionary          = (Get-DictionaryHit $token)
        false_positive_kind = (Get-FalsePositiveKind $token)
    }
}

function Analysis-Camel($a) { $a.internal_capitals -ge 1 }
function Analysis-CamelYearSym($a) { (Analysis-Camel $a) -and $a.has_year -and $a.has_symbol }
function Analysis-Compound($a) { $a.internal_capitals -ge 2 }
function Analysis-Leet($a) { $a.has_internal_digit }
function Analysis-IsIdentifierShape($a) {
    (Analysis-Compound $a) -and (-not $a.has_year) -and (-not $a.has_symbol) `
        -and (-not $a.ends_with_digit) -and ($null -eq $a.dictionary)
}

# -------------------------------------------------------------------------
# context
# -------------------------------------------------------------------------

function Get-LevenshteinWithin([string] $a, [string] $b, [int] $max) {
    $la = $a.Length; $lb = $b.Length
    if ([Math]::Abs($la - $lb) -gt $max) { return $max + 1 }
    $prev = 0..$lb
    $cur = New-Object 'int[]' ($lb + 1)
    for ($i = 1; $i -le $la; $i++) {
        $cur[0] = $i
        $rowMin = $cur[0]
        for ($j = 1; $j -le $lb; $j++) {
            $cost = if ($a[$i - 1] -eq $b[$j - 1]) { 0 } else { 1 }
            $v = [Math]::Min([Math]::Min($prev[$j] + 1, $cur[$j - 1] + 1), $prev[$j - 1] + $cost)
            $cur[$j] = $v
            if ($v -lt $rowMin) { $rowMin = $v }
        }
        if ($rowMin -gt $max) { return $max + 1 }
        $tmp = $prev; $prev = $cur; $cur = $tmp
    }
    return $prev[$lb]
}

function Test-ProximateKeyWord([string] $lineLower, [string] $tokenLower, [string[]] $keys) {
    $start = $lineLower.IndexOf($tokenLower)
    if ($start -lt 0) { return $false }
    $end = $start + $tokenLower.Length
    $from = [Math]::Max(0, $start - $script:PROXIMITY_WINDOW)
    $to = [Math]::Min($lineLower.Length, $end + $script:PROXIMITY_WINDOW)
    $window = $lineLower.Substring($from, $to - $from)
    return Test-KeyWord $window $keys
}

function Get-TokenContext($token, [string[]] $names) {
    $key = $token.key
    $lineLower = $token.context_line
    $tokenLower = $token.text.ToLowerInvariant()

    $nearSecret = $false
    if ($null -ne $key -and (Test-KeyWord $key $script:SECRET_KEYS)) { $nearSecret = $true }
    elseif (Test-ProximateKeyWord $lineLower $tokenLower $script:SECRET_KEYS) { $nearSecret = $true }

    $nearNonsecret = $false
    if ($null -ne $key -and (Test-KeyWord $key $script:NONSECRET_KEYS)) { $nearNonsecret = $true }
    elseif (Test-ProximateKeyWord $lineLower $tokenLower $script:NONSECRET_KEYS) { $nearNonsecret = $true }

    $nearIdentity = $false
    if ($null -ne $key) { $nearIdentity = $script:IDENTITY_KEYS -contains $key.ToLowerInvariant() }

    $isNameEcho = $false
    $isNameDerived = $false
    foreach ($n in $names) {
        if ((Get-LevenshteinWithin $tokenLower $n $script:ECHO_MAX_DISTANCE) -le $script:ECHO_MAX_DISTANCE) { $isNameEcho = $true }
        if ($tokenLower.Length -gt $n.Length -and $tokenLower.StartsWith($n)) { $isNameDerived = $true }
    }

    return @{
        near_secret_key   = $nearSecret
        near_nonsecret_key = $nearNonsecret
        near_identity_key = $nearIdentity
        is_name_echo      = $isNameEcho
        is_name_derived   = $isNameDerived
    }
}

function Get-ContextNames() {
    $names = @()
    if ($ContextNames -ne "") {
        $names = $ContextNames.Split(',')
    }
    else {
        foreach ($k in @("USER", "USERNAME", "LOGNAME", "USERDOMAIN", "HOSTNAME", "COMPUTERNAME")) {
            $v = [System.Environment]::GetEnvironmentVariable($k)
            if ($null -ne $v -and $v -ne "") { $names += $v }
        }
    }
    $out = @()
    foreach ($n in $names) {
        $l = $n.ToLowerInvariant()
        if ($l -ne "") { $out += $l }
    }
    return , $out
}

# -------------------------------------------------------------------------
# scoring sub-scores
# -------------------------------------------------------------------------

function Score-Entropy([double] $bits) {
    if ($bits -lt 2.0) { return 0.1 }
    elseif ($bits -le 3.5) { return 0.3 + ($bits - 2.0) / 1.5 * 0.7 }
    elseif ($bits -le 4.5) { return 1.0 }
    elseif ($bits -le 5.0) { return 0.5 }
    else { return 0.1 }
}

function Score-Length([int] $n) {
    if ($n -le 5) { return 0.2 }
    elseif ($n -le 7) { return 0.6 }
    elseif ($n -le 24) { return 1.0 }
    elseif ($n -le 32) { return 0.8 }
    elseif ($n -le 64) { return 0.4 }
    else { return 0.1 }
}

function Score-ClassMix($a) {
    switch ($a.class_count) {
        1 { $base = 0.1 }
        2 { $base = 0.5 }
        3 { $base = 0.85 }
        4 { $base = 1.0 }
        default { $base = 0.0 }
    }
    $rich = ($a.lower -ge 2) -and ($a.upper -ge 2) -and ($a.digit -ge 2) -and ($a.special -ge 1)
    $v = $base + $(if ($rich) { 0.15 } else { 0.0 })
    return [Math]::Min($v, 1.0)
}

function Score-Pattern($a) {
    $p = 0.0
    if (Analysis-CamelYearSym $a) { $p += 0.6 }
    if (Analysis-Compound $a) { $p += 0.6 }
    if (Analysis-Leet $a) { $p += 0.3 }
    if ($a.has_year) { $p += 0.2 }
    if ($a.has_symbol) { $p += 0.2 }
    if ($a.ends_with_digit) { $p += 0.2 }
    return [Math]::Min($p, 1.0)
}

function Score-Context($tc) {
    $c = 0.0
    if ($tc.near_secret_key) { $c += 0.7 }
    if ($tc.is_name_derived) { $c += 0.3 }
    if ($tc.near_nonsecret_key) { $c -= 0.25 }
    if ($c -lt 0.0) { $c = 0.0 }
    if ($c -gt 1.0) { $c = 1.0 }
    return $c
}

function Round2([double] $x) { [Math]::Round($x, 2) }
function Round3([double] $x) { [Math]::Round($x, 3) }

function Get-FilePrior([string] $path) {
    $name = [System.IO.Path]::GetFileName($path).ToLowerInvariant()
    if ($name -eq ".env" -or $name -eq ".netrc" -or $name.EndsWith("_history") `
            -or $name -eq "consolehost_history.txt" -or $name.Contains("history")) {
        return 0.8
    }
    $ext = [System.IO.Path]::GetExtension($path).TrimStart('.').ToLowerInvariant()
    switch ($ext) {
        { $_ -in @("env", "ini", "conf", "config", "cfg", "cnf", "xml", "json", "yaml", "yml", "ps1", "sh", "bash", "bat", "cmd", "properties", "sql", "rdp", "pfx", "kdbx", "key", "pem", "pub", "toml", "netrc") } { return 0.8 }
        { $_ -in @("txt", "log", "md", "html", "php", "js", "py", "rb", "go", "ts", "jsonl") } { return 0.4 }
        { $_ -in @("rs", "java", "cs", "c", "cc", "cpp", "h", "hpp", "swift", "kt", "kts") } { return 0.1 }
        { $_ -in @("css", "map", "lock", "sum") } { return 0.1 }
        default { return 0.3 }
    }
}

function New-FeatureVector($a, $tc, [double] $prior) {
    $fv = [ordered]@{
        entropy_bits           = (Round3 $a.entropy_bits)
        length                 = $a.length
        class_count            = $a.class_count
        pattern_camel_year_sym = (Analysis-CamelYearSym $a)
        pattern_compound       = (Analysis-Compound $a)
        pattern_leet           = (Analysis-Leet $a)
        context_secret_key     = $tc.near_secret_key
        context_near_name      = $tc.is_name_derived
        file_prior             = $prior
    }
    if ($null -ne $a.dictionary) { $fv["dictionary_hit"] = $a.dictionary.word }
    if ($null -ne $a.false_positive_kind) { $fv["false_positive_kind"] = $a.false_positive_kind }
    return $fv
}

# -------------------------------------------------------------------------
# score a token
# -------------------------------------------------------------------------

function Score-Token($token, [string] $file, [double] $prior, [string[]] $names) {
    $a = Get-Analysis $token.text
    $tc = Get-TokenContext $token $names

    if ($null -ne $a.false_positive_kind -and -not $tc.near_secret_key) { return $null }

    $lower = $token.text.ToLowerInvariant()
    if ($null -eq $token.key -and ($script:METADATA_WORDS -contains $lower)) { return $null }
    if ($null -eq $token.key -and (Analysis-IsIdentifierShape $a)) { return $null }

    $score = 0.0
    $score += $script:W_ENTROPY * (Score-Entropy $a.entropy_bits)
    $score += $script:W_LENGTH * (Score-Length $a.length)
    $score += $script:W_CLASS_MIX * (Score-ClassMix $a)
    $score += $script:W_PATTERN * (Score-Pattern $a)
    $score += $script:W_DICTIONARY * $(if ($null -ne $a.dictionary) { 1.0 } else { 0.0 })
    $score += $script:W_CONTEXT * (Score-Context $tc)
    $score += $script:W_FILE_PRIOR * $prior

    if ($tc.is_name_echo -or $tc.near_identity_key) { $score *= $script:NAME_DAMPING }
    if ($null -ne $a.false_positive_kind -and $tc.near_secret_key) { $score *= $script:FALSE_POSITIVE_DAMPING }

    $dictStrong = ($null -ne $a.dictionary) -and ($a.dictionary.tier -eq "strong")
    $dictFloor = ($null -ne $a.dictionary) -and ($dictStrong -or $tc.near_secret_key) `
        -and (-not $tc.near_identity_key) -and (-not $tc.is_name_echo)
    if ($dictFloor) { $score = [Math]::Max($score, $script:DICT_FLOOR) }

    if ($score -lt $script:REPORT_THRESHOLD) { return $null }

    if ($score -ge $script:HIGH_THRESHOLD) { $confidence = "high" }
    elseif ($score -ge $script:MEDIUM_THRESHOLD) { $confidence = "medium" }
    else { $confidence = "low" }

    $finding = [ordered]@{
        file       = $file
        line       = $token.line
        kind       = $token.kind
        masked     = (Get-Masked $token.text)
        score      = (Round2 $score)
        confidence = $confidence
        features   = (New-FeatureVector $a $tc $prior)
    }
    if ($null -ne $token.key) { $finding["key"] = $token.key }
    if ($Reveal) { $finding["value"] = $token.text }
    return $finding
}

# -------------------------------------------------------------------------
# high-precision format detectors
# -------------------------------------------------------------------------

function Extract-After([string] $line, [string] $prefix, [int] $exactLen, [scriptblock] $valid) {
    $pos = $line.IndexOf($prefix)
    if ($pos -lt 0) { return $null }
    $rest = $line.Substring($pos + $prefix.Length)
    if ($rest.Length -lt $exactLen) { return $null }
    $tail = $rest.Substring(0, $exactLen)
    foreach ($c in $tail.ToCharArray()) { if (-not (& $valid $c)) { return $null } }
    return $prefix + $tail
}

function Detect-Line([string] $line) {
    $hits = @()
    foreach ($p in @("AKIA", "ASIA")) {
        $v = Extract-After $line $p 16 { param($c) (Test-AsciiUpper $c) -or (Test-AsciiDigit $c) }
        if ($null -ne $v) { $hits += @{ value = $v; kind = "aws_access_key" }; break }
    }
    $v = Extract-After $line "AIza" 35 { param($c) (Test-AsciiLetter $c) -or (Test-AsciiDigit $c) -or $c -eq '-' -or $c -eq '_' }
    if ($null -ne $v) { $hits += @{ value = $v; kind = "google_api_key" } }
    foreach ($p in @("ghp_", "gho_", "ghs_", "ghu_", "ghr_")) {
        $v = Extract-After $line $p 36 { param($c) (Test-AsciiLetter $c) -or (Test-AsciiDigit $c) }
        if ($null -ne $v) { $hits += @{ value = $v; kind = "github_token" }; break }
    }
    $v = Extract-After $line "glpat-" 20 { param($c) (Test-AsciiLetter $c) -or (Test-AsciiDigit $c) -or $c -eq '-' -or $c -eq '_' }
    if ($null -ne $v) { $hits += @{ value = $v; kind = "gitlab_token" } }
    foreach ($p in @("xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-")) {
        $v = Extract-After $line $p 24 { param($c) (Test-AsciiLetter $c) -or (Test-AsciiDigit $c) -or $c -eq '-' }
        if ($null -ne $v) { $hits += @{ value = $v; kind = "slack_token" }; break }
    }
    $stripeFound = $false
    foreach ($kind in @("sk", "pk", "rk")) {
        foreach ($env in @("live", "test")) {
            $v = Extract-After $line "$($kind)_$($env)_" 24 { param($c) (Test-AsciiLetter $c) -or (Test-AsciiDigit $c) }
            if ($null -ne $v) { $hits += @{ value = $v; kind = "stripe_key" }; $stripeFound = $true; break }
        }
        if ($stripeFound) { break }
    }
    $j = Detect-Jwt $line
    if ($null -ne $j) { $hits += @{ value = $j; kind = "jwt" } }
    if ($line.Contains("-----BEGIN") -and $line.Contains("PRIVATE KEY-----")) {
        $hits += @{ value = $line.Trim(); kind = "private_key" }
    }
    return $hits
}

function Detect-Jwt([string] $line) {
    $words = $line.Split([char[]]@(' ', "`t", "`r", "`n", ',', '"', "'", '(', ')', '[', ']', '{', '}', '<', '>'))
    foreach ($w in $words) {
        if (-not $w.StartsWith("eyJ")) { continue }
        $segs = $w.Split('.')
        if ($segs.Count -ne 3) { continue }
        $ok = $true
        foreach ($s in $segs) {
            if ($s.Length -eq 0) { $ok = $false; break }
            foreach ($c in $s.ToCharArray()) {
                if (-not ((Test-AsciiLetter $c) -or (Test-AsciiDigit $c) -or $c -eq '-' -or $c -eq '_')) { $ok = $false; break }
            }
            if (-not $ok) { break }
        }
        if ($ok) { return $w }
    }
    return $null
}

function New-DetectorFinding($hit, [string] $file, [int] $line, [double] $prior) {
    $a = Get-Analysis $hit.value
    $fv = [ordered]@{
        entropy_bits           = (Round3 $a.entropy_bits)
        length                 = $a.length
        class_count            = $a.class_count
        pattern_camel_year_sym = (Analysis-CamelYearSym $a)
        pattern_compound       = (Analysis-Compound $a)
        pattern_leet           = (Analysis-Leet $a)
        context_secret_key     = $false
        context_near_name      = $false
        file_prior             = $prior
    }
    $finding = [ordered]@{
        file       = $file
        line       = $line
        kind       = $hit.kind
        masked     = (Get-Masked $hit.value)
        score      = 0.95
        confidence = "high"
        features   = $fv
    }
    if ($Reveal) { $finding["value"] = $hit.value }
    return $finding
}

# -------------------------------------------------------------------------
# tokenizer
# -------------------------------------------------------------------------

function Test-ValidToken([string] $s) {
    $len = $s.Length
    return ($len -ge $script:MIN_TOKEN -and $len -le $script:MAX_TOKEN)
}

function Test-Comment([string] $line) {
    return $line.StartsWith('#') -or $line.StartsWith('//') -or $line.StartsWith(';')
}

function Find-Equals([string] $s) {
    $b = $s
    for ($i = 0; $i -lt $b.Length; $i++) {
        if ($b[$i] -eq '=') {
            if ($i -gt 0 -and ($b[$i - 1] -in @('=', '!', '<', '>', '+', '-', '*'))) { continue }
            if ($i + 1 -lt $b.Length -and ($b[$i + 1] -eq '>' -or $b[$i + 1] -eq '=')) { continue }
            return $i
        }
    }
    return -1
}

function Find-Colon([string] $s) {
    $b = $s
    for ($i = 0; $i -lt $b.Length; $i++) {
        if ($b[$i] -eq ':') {
            if ($i + 1 -lt $b.Length -and ($b[$i + 1] -eq ':' -or $b[$i + 1] -eq '/')) { continue }
            if ($i -gt 0 -and $b[$i - 1] -eq ':') { continue }
            if ($i -eq 0) { continue }
            return $i
        }
    }
    return -1
}

function Clean-Key([string] $s) {
    $t = $s.Trim().Trim([char[]]@('"', "'"))
    $t = $t.TrimStart([char[]]@('{', '[', '('))
    return $t.TrimEnd(',').Trim()
}

function Clean-Value([string] $s) {
    $t = $s.Trim()
    $t = $t.TrimEnd([char[]]@(',', ')', ']', '}', ';'))
    $t = $t.Trim()
    if ($t.Length -ge 2) {
        $first = $t[0]; $last = $t[$t.Length - 1]
        if (($first -eq '"' -and $last -eq '"') -or ($first -eq "'" -and $last -eq "'")) {
            $t = $t.Substring(1, $t.Length - 2)
        }
    }
    return $t
}

function Split-Assignment([string] $line) {
    $i = Find-Equals $line
    if ($i -ge 0) {
        $key = Clean-Key $line.Substring(0, $i)
        $val = Clean-Value $line.Substring($i + 1)
        if ($key.Length -gt 0 -and $val.Length -gt 0) { return @($key, $val) }
    }
    $i = Find-Colon $line
    if ($i -ge 0) {
        $key = Clean-Key $line.Substring(0, $i)
        $val = Clean-Value $line.Substring($i + 1)
        if ($key.Length -gt 0 -and $val.Length -gt 0) { return @($key, $val) }
    }
    return $null
}

function Strip-OuterAssignment([string] $line) {
    $i = Find-Equals $line
    if ($i -ge 0) {
        $val = $line.Substring($i + 1).Trim()
        foreach ($q in @('"', "'")) {
            if ($val.Length -ge 2 -and $val.StartsWith($q) -and $val.EndsWith($q)) {
                return $val.Substring(1, $val.Length - 2)
            }
        }
    }
    return $line
}

function Split-Plain([string] $line) {
    $out = @()
    $cur = ""
    foreach ($c in $line.ToCharArray()) {
        if ([System.Char]::IsWhiteSpace($c) -or (",;()[]{}`"'<>".IndexOf($c) -ge 0)) {
            if ($cur.Length -gt 0) { $out += $cur; $cur = "" }
        }
        else { $cur += $c }
    }
    if ($cur.Length -gt 0) { $out += $cur }
    return , $out
}

function New-Token([string] $text, $key, [string] $contextLine, [int] $line, [string] $kind) {
    return @{ text = $text; key = $key; context_line = $contextLine; line = $line; kind = $kind }
}

function Get-LineContextLower([string] $line) {
    $capped = if ($line.Length -gt $script:MAX_CONTEXT_CHARS) { $line.Substring(0, $script:MAX_CONTEXT_CHARS) } else { $line }
    return $capped.ToLowerInvariant()
}

function Tokenize-Lines([string] $content) {
    $tokens = @()
    $raw = $content -split "`n"
    for ($idx = 0; $idx -lt $raw.Length; $idx++) {
        $line = $raw[$idx].TrimEnd("`r").Trim()
        if ($line.Length -eq 0 -or (Test-Comment $line)) { continue }
        $ln = $idx + 1
        $ctxLower = Get-LineContextLower $line

        if ($line.Contains(';') -and $line.Contains('=')) {
            $body = Strip-OuterAssignment $line
            $found = $false
            foreach ($seg in $body.Split(';')) {
                $kv = Split-Assignment $seg
                if ($null -ne $kv -and (Test-ValidToken $kv[1])) {
                    $tokens += New-Token $kv[1] $kv[0] $ctxLower $ln "conn_string"
                    $found = $true
                }
            }
            if ($found) { continue }
        }

        $kv = Split-Assignment $line
        if ($null -ne $kv) {
            if (Test-ValidToken $kv[1]) { $tokens += New-Token $kv[1] $kv[0] $ctxLower $ln "assignment" }
            continue
        }

        foreach ($t in (Split-Plain $line)) {
            if (Test-ValidToken $t) { $tokens += New-Token $t $null $ctxLower $ln "plain" }
        }
    }
    return , $tokens
}

$script:JsonKeyCursors = @{}

function Get-JsonKeyLine([string] $content, [string] $key) {
    $needle = '"' + $key + '"'
    $from = 0
    if ($script:JsonKeyCursors.ContainsKey($key)) { $from = $script:JsonKeyCursors[$key] }
    $pos = $content.IndexOf($needle, $from)
    if ($pos -lt 0) { return 1 }
    $script:JsonKeyCursors[$key] = $pos + $needle.Length
    $line = 1
    for ($i = 0; $i -lt $pos; $i++) { if ($content[$i] -eq "`n") { $line++ } }
    return $line
}

function Walk-Json($value, $key, [string] $content, $tokens) {
    if ($value -is [System.Collections.IDictionary] -or $value -is [PSCustomObject]) {
        $props = if ($value -is [PSCustomObject]) { $value.PSObject.Properties } else { $value.GetEnumerator() }
        foreach ($p in $props) {
            $k = if ($value -is [PSCustomObject]) { $p.Name } else { $p.Key }
            $v = if ($value -is [PSCustomObject]) { $p.Value } else { $p.Value }
            Walk-Json $v $k $content $tokens
        }
    }
    elseif ($value -is [System.Array] -or ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string]))) {
        foreach ($item in $value) { Walk-Json $item $key $content $tokens }
    }
    elseif ($value -is [string]) {
        if ($null -ne $key -and (Test-ValidToken $value)) {
            $ln = Get-JsonKeyLine $content $key
            $tokens.Value += New-Token $value $key $key.ToLowerInvariant() $ln "json_value"
        }
    }
}

function Tokenize-Json([string] $content) {
    try { $parsed = $content | ConvertFrom-Json -ErrorAction Stop }
    catch { return (Tokenize-Lines $content) }
    $script:JsonKeyCursors = @{}
    $tokens = @()
    $ref = [ref] $tokens
    Walk-Json $parsed $null $content $ref
    return , $ref.Value
}

function Tokenize([string] $content, [string] $ext) {
    if ($ext -eq "json") { return (Tokenize-Json $content) }
    return (Tokenize-Lines $content)
}

# -------------------------------------------------------------------------
# file walk
# -------------------------------------------------------------------------

function Get-RelativePath([string] $full, [string] $root) {
    $rel = $full
    if ($full.StartsWith($root)) { $rel = $full.Substring($root.Length) }
    $rel = $rel.TrimStart('\', '/')
    return $rel.Replace('\', '/')
}

function Test-Allowed([string] $full, [string] $root) {
    $rel = Get-RelativePath $full $root
    foreach ($d in $Deny) {
        $t = $d.Trim('/')
        if ($rel.StartsWith($t)) { return $false }
    }
    if ($Allow.Count -eq 0) { return $true }
    foreach ($a in $Allow) {
        $t = $a.Trim('/')
        if ($rel.StartsWith($t)) { return $true }
    }
    return $false
}

function Test-DeniedDirSegment([string] $full, [string] $root) {
    $rel = Get-RelativePath $full $root
    $segments = $rel.Split('/')
    # Every segment except the file name is a directory.
    for ($i = 0; $i -lt $segments.Length - 1; $i++) {
        if ($script:DEFAULT_DENY_DIRS -contains $segments[$i]) { return $true }
    }
    return $false
}

function Collect-Files([string] $root) {
    $out = @()
    $items = Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        if ($out.Count -ge $MaxFiles) { break }
        $full = $item.FullName
        if (Test-DeniedDirSegment $full $root) { continue }
        $ext = $item.Extension.TrimStart('.').ToLowerInvariant()
        if ($script:BINARY_EXTS -contains $ext) { continue }
        if ($item.Length -gt $MaxFileSize) { continue }
        if (-not (Test-Allowed $full $root)) { continue }
        $out += $full
    }
    $out = $out | Sort-Object
    return , $out
}

function Read-TextCapped([string] $path) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
    }
    catch { throw }
    if ($bytes.Length -gt ($MaxFileSize + 1)) {
        $bytes = $bytes[0..$MaxFileSize]
    }
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

# -------------------------------------------------------------------------
# JSON serializer (stable, PS 5.1-safe arrays)
# -------------------------------------------------------------------------

function ConvertTo-KitsuneJson($value, [int] $indent = 0) {
    $pad = "  " * $indent
    $padIn = "  " * ($indent + 1)
    if ($null -eq $value) { return "null" }
    if ($value -is [bool]) { return $(if ($value) { "true" } else { "false" }) }
    if ($value -is [int] -or $value -is [long] -or $value -is [int64]) { return $value.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    if ($value -is [double] -or $value -is [float] -or $value -is [decimal]) {
        return ([double]$value).ToString("R", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($value -is [string]) { return (ConvertTo-JsonString $value) }
    if ($value -is [System.Collections.IDictionary]) {
        if ($value.Count -eq 0) { return "{}" }
        $parts = @()
        foreach ($k in $value.Keys) {
            $parts += "$padIn$(ConvertTo-JsonString ([string]$k)): $(ConvertTo-KitsuneJson $value[$k] ($indent + 1))"
        }
        return "{`n" + ($parts -join ",`n") + "`n$pad}"
    }
    if ($value -is [System.Array] -or ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string]))) {
        $items = @($value)
        if ($items.Count -eq 0) { return "[]" }
        $parts = @()
        foreach ($item in $items) { $parts += "$padIn$(ConvertTo-KitsuneJson $item ($indent + 1))" }
        return "[`n" + ($parts -join ",`n") + "`n$pad]"
    }
    return (ConvertTo-JsonString ([string]$value))
}

function ConvertTo-JsonString([string] $s) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($c in $s.ToCharArray()) {
        switch ($c) {
            '"' { [void]$sb.Append('\"') }
            '\' { [void]$sb.Append('\\') }
            "`b" { [void]$sb.Append('\b') }
            "`f" { [void]$sb.Append('\f') }
            "`n" { [void]$sb.Append('\n') }
            "`r" { [void]$sb.Append('\r') }
            "`t" { [void]$sb.Append('\t') }
            default {
                if ([int][char]$c -lt 32) { [void]$sb.Append(('\u{0:x4}' -f [int][char]$c)) }
                else { [void]$sb.Append($c) }
            }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# -------------------------------------------------------------------------
# markdown renderer (one-check report)
# -------------------------------------------------------------------------

function Get-BacktickRun([string] $s) {
    $longest = 0; $run = 0
    foreach ($c in $s.ToCharArray()) { if ($c -eq '`') { $run++ } else { $run = 0 }; if ($run -gt $longest) { $longest = $run } }
    return $longest
}
function Get-CodeSpan([string] $s) {
    $fence = '`' * ((Get-BacktickRun $s) + 1)
    $pad = if ($s.StartsWith('`') -or $s.EndsWith('`')) { " " } else { "" }
    return "$fence$pad$s$pad$fence"
}
function Get-Cell([string] $s) { return $s.Replace('|', '\|').Replace("`n", ' ').Replace("`r", ' ') }

function Render-Markdown($report) {
    $check = $report.checks[0]
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# $($script:TOOL) report")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- **target**: ``$($report.target)``")
    [void]$sb.AppendLine("- **tool**: $($report.tool) $($report.version)")
    [void]$sb.AppendLine("- **checks**: $($report.checks.Count)")
    [void]$sb.AppendLine("")
    $icon = [char]0x2714
    [void]$sb.AppendLine("## $icon $($check.title)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- ``$($check.check_id)``")
    [void]$sb.AppendLine("- status: **$($check.status)**")
    [void]$sb.AppendLine("")
    $json = ConvertTo-KitsuneJson $check.data 0
    $fence = '`' * ([Math]::Max((Get-BacktickRun $json), 2) + 1)
    [void]$sb.AppendLine("${fence}json")
    [void]$sb.AppendLine($json)
    [void]$sb.AppendLine($fence)
    [void]$sb.AppendLine("")
    if ($check.findings.Count -gt 0) {
        [void]$sb.AppendLine("| file | line | key | value | score | confidence |")
        [void]$sb.AppendLine("|---|---|---|---|---|---|")
        foreach ($f in $check.findings) {
            $val = if ($f.Contains("value")) { $f["value"] } else { $f["masked"] }
            $key = if ($f.Contains("key")) { $f["key"] } else { "" }
            $scoreStr = ([double]$f["score"]).ToString("F2", [System.Globalization.CultureInfo]::InvariantCulture)
            [void]$sb.AppendLine("| $(Get-Cell $f['file']) | $($f['line']) | $(Get-Cell $key) | $(Get-CodeSpan (Get-Cell ([string]$val))) | $scoreStr | $($f['confidence']) |")
        }
        [void]$sb.AppendLine("")
    }
    return $sb.ToString()
}

# -------------------------------------------------------------------------
# main
# -------------------------------------------------------------------------

function Invoke-Main {
    $startTicks = [System.Diagnostics.Stopwatch]::StartNew()
    $deadline = (Get-Date).AddSeconds($Timeout)
    $root = (Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue)
    $rootStr = if ($null -ne $root) { $root.Path } else { $Path }

    $names = Get-ContextNames
    $files = Collect-Files $rootStr

    $findings = @()
    $filesScanned = 0
    $filesSkipped = 0
    $tokensSeen = 0
    $timedOut = $false

    foreach ($file in $files) {
        if ((Get-Date) -ge $deadline) { $timedOut = $true; break }
        $text = $null
        try { $text = Read-TextCapped $file } catch { $filesSkipped++; continue }
        if ($text.Contains([char]0)) { $filesSkipped++; continue }
        $filesScanned++
        if ($Progress -and ($filesScanned % 1000) -eq 0) { Write-Host "scanned $filesScanned files" }

        $prior = Get-FilePrior $file
        $ext = [System.IO.Path]::GetExtension($file).TrimStart('.').ToLowerInvariant()

        foreach ($tok in (Tokenize $text $ext)) {
            $tokensSeen++
            $f = Score-Token $tok $file $prior $names
            if ($null -ne $f) { $findings += $f }
        }
        foreach ($hit in (Detect-Line-All $text)) {
            $findings += (New-DetectorFinding $hit.hit $file $hit.line $prior)
        }
    }

    # sort by (file, line, masked) then score desc; dedup; filter by confidence.
    $findings = $findings | Sort-Object `
        @{ Expression = { $_["file"] } }, `
        @{ Expression = { [int]$_["line"] } }, `
        @{ Expression = { $_["masked"] } }, `
        @{ Expression = { [double]$_["score"] }; Descending = $true }

    $seen = @{}
    $deduped = @()
    foreach ($f in $findings) {
        $sig = "$($f['file'])|$($f['line'])|$($f['masked'])"
        if (-not $seen.ContainsKey($sig)) { $seen[$sig] = $true; $deduped += $f }
    }
    $confRank = @{ "low" = 0; "medium" = 1; "high" = 2 }
    $minRank = $confRank[$MinConfidence]
    $deduped = @($deduped | Where-Object { $confRank[$_["confidence"]] -ge $minRank })

    $unique = @{}
    foreach ($f in $deduped) { $unique[$f["masked"]] = $true }

    $data = [ordered]@{
        root              = $rootStr
        files_total       = $files.Count
        files_scanned     = $filesScanned
        files_skipped     = $filesSkipped
        tokens_seen       = $tokensSeen
        candidates        = $deduped.Count
        unique_candidates = $unique.Count
        timed_out         = $timedOut
    }

    $durationMs = [int] $startTicks.Elapsed.TotalMilliseconds
    $startedAtMs = [long] ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    if ($NoTimestamps) { $durationMs = 0; $startedAtMs = 0 }

    $check = [ordered]@{
        check_id    = "secret_hunter.findings"
        plugin      = "secret_hunter"
        status      = "success"
        title       = "Secret hunter findings"
        data        = $data
        findings    = @($deduped)
        suggestions = @()
        duration_ms = $durationMs
    }
    $report = [ordered]@{
        tool           = $script:TOOL
        version        = $script:VERSION
        schema_version = $script:SCHEMA_VERSION
        started_at_ms  = $startedAtMs
        duration_ms    = $durationMs
        target         = $rootStr
        checks         = @($check)
    }

    if ($Format -eq "md") {
        # Rebuild a lightweight object for the markdown renderer.
        $mdReport = @{ tool = $script:TOOL; version = $script:VERSION; target = $rootStr; checks = @($check) }
        $text = Render-Markdown $mdReport
    }
    else {
        $text = ConvertTo-KitsuneJson $report 0
    }

    if ($Out) {
        Set-Content -LiteralPath $Out -Value $text -Encoding UTF8 -NoNewline
    }
    else {
        Write-Output $text
    }
}

# Detector helper that also returns line numbers.
function Detect-Line-All([string] $content) {
    $out = @()
    $raw = $content -split "`n"
    for ($i = 0; $i -lt $raw.Length; $i++) {
        $line = $raw[$i].TrimEnd("`r")
        foreach ($hit in (Detect-Line $line)) {
            $out += @{ hit = $hit; line = ($i + 1) }
        }
    }
    return , $out
}

Invoke-Main
