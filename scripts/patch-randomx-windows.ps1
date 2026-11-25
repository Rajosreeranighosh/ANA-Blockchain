$ErrorActionPreference = "Stop"

# randomx-bindings-sys 0.1.5 ships a CMake custom command that uses shell
# redirection syntax inside add_custom_command(). CMake invokes commands
# directly, so the redirection is passed as arguments and configuration.asm
# is never created on MSVC/Windows.
# Ensure the pinned native dependency is present before locating its source.
cargo fetch
if ($LASTEXITCODE -ne 0) { throw "cargo fetch failed." }

$registry = Join-Path $env:USERPROFILE ".cargo\registry\src"
$matches = Get-ChildItem -Path $registry -Filter "CMakeLists.txt" -Recurse |
    Where-Object { $_.FullName -match "\\randomx-bindings-sys-0\.1\.5\\randomx\\CMakeLists\.txt$" }

if (-not $matches) {
    throw "randomx-bindings-sys 0.1.5 CMakeLists.txt was not found. Run cargo fetch first."
}

$old = 'COMMAND powershell -ExecutionPolicy Bypass -File h2inc.ps1 ..\src\configuration.h > ..\src\asm\configuration.asm SET ERRORLEVEL = 0'
$new = 'COMMAND powershell -NoProfile -ExecutionPolicy Bypass -Command "& { .\h2inc.ps1 ..\src\configuration.h | Out-File -Encoding ascii ..\src\asm\configuration.asm }"'

foreach ($file in $matches) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    if ($content.Contains($old)) {
        $content = $content.Replace($old, $new)
        Set-Content -LiteralPath $file.FullName -Value $content -NoNewline
        Write-Host "Patched $($file.FullName)"
    } elseif ($content.Contains($new)) {
        Write-Host "Already patched: $($file.FullName)"
    } else {
        throw "Unexpected RandomX CMake command in $($file.FullName); refusing an unsafe patch."
    }
}
