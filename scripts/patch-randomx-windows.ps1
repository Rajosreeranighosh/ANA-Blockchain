$ErrorActionPreference = "Stop"

# randomx-bindings-sys 0.1.5 emits its x86 configuration header through a
# PowerShell command containing shell-style redirection. CMake does not run
# COMMAND lines through a shell, so replace that one command with an explicit
# PowerShell pipeline that writes the generated assembly include.
cargo fetch
if ($LASTEXITCODE -ne 0) { throw "cargo fetch failed." }

$registry = Join-Path $env:USERPROFILE ".cargo\registry\src"
$matches = Get-ChildItem -Path $registry -Filter "CMakeLists.txt" -Recurse |
    Where-Object { $_.FullName -match "\\randomx-bindings-sys-0\.1\.5\\randomx\\CMakeLists\.txt$" }

if (-not $matches) {
    throw "randomx-bindings-sys 0.1.5 CMakeLists.txt was not found. Run cargo fetch first."
}

# Match the command semantically rather than comparing CMake's escaped path
# spelling byte-for-byte. Keep the replacement on one CMake COMMAND line.
$commandPattern = '(?im)^[ \t]*COMMAND\b[^\r\n]*h2inc\.ps1[^\r\n]*configuration\.asm[^\r\n]*$'
$replacement = '  COMMAND powershell -NoProfile -ExecutionPolicy Bypass -Command "& { ./h2inc.ps1 ../src/configuration.h | Out-File -Encoding ascii ../src/asm/configuration.asm }"'

foreach ($file in $matches) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    $updated = [regex]::Replace($content, $commandPattern, $replacement)

    if ($updated -ne $content) {
        Set-Content -LiteralPath $file.FullName -Value $updated -NoNewline
        Write-Host "Patched RandomX CMake assembly-generation command in $($file.FullName)"
    } elseif ($content -match '(?im)COMMAND\b[^\r\n]*Out-File[^\r\n]*configuration\.asm') {
        Write-Host "RandomX CMake assembly-generation command is already patched: $($file.FullName)"
    } else {
        $candidate = ($content -split [Environment]::NewLine | Where-Object { $_ -match 'h2inc|configuration\.asm' }) -join " | "
        throw "Could not identify the RandomX h2inc command in $($file.FullName). Relevant lines: $candidate"
    }
}
