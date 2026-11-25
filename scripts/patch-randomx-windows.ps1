$ErrorActionPreference = "Stop"

# randomx-bindings-sys 0.1.5 uses a CMake custom command that relies on
# shell-style redirection and a relative working directory. MSBuild does not
# execute CMake COMMAND lines through a shell, so replace only that command
# with an explicit PowerShell invocation using absolute source paths.
cargo fetch
if ($LASTEXITCODE -ne 0) { throw "cargo fetch failed." }

$registry = Join-Path $env:USERPROFILE ".cargo\registry\src"
$matches = Get-ChildItem -Path $registry -Filter "CMakeLists.txt" -Recurse |
    Where-Object { $_.FullName -match "\\randomx-bindings-sys-0\.1\.5\\randomx\\CMakeLists\.txt$" }

if (-not $matches) {
    throw "randomx-bindings-sys 0.1.5 CMakeLists.txt was not found. Run cargo fetch first."
}

$commandPattern = '(?im)^[ \t]*COMMAND\b[^\r\n]*h2inc\.ps1[^\r\n]*configuration\.asm[^\r\n]*$'
$replacement = '  COMMAND powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Set-Location -LiteralPath ''${CMAKE_CURRENT_SOURCE_DIR}/vcxproj''; New-Item -ItemType Directory -Force -Path ''${CMAKE_CURRENT_SOURCE_DIR}/src/asm'' | Out-Null; & ''${CMAKE_CURRENT_SOURCE_DIR}/vcxproj/h2inc.ps1'' ''${CMAKE_CURRENT_SOURCE_DIR}/src/configuration.h'' | Set-Content -Encoding ascii ''${CMAKE_CURRENT_SOURCE_DIR}/src/asm/configuration.asm'' }"'

foreach ($file in $matches) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    $updated = [regex]::Replace($content, $commandPattern, $replacement)

    if ($updated -ne $content) {
        Set-Content -LiteralPath $file.FullName -Value $updated -NoNewline
        Write-Host "Patched RandomX assembly generation with absolute paths in $($file.FullName)"
    } elseif ($content -match '(?im)COMMAND\b[^\r\n]*Set-Content[^\r\n]*configuration\.asm') {
        Write-Host "RandomX CMake assembly-generation command is already patched: $($file.FullName)"
    } else {
        throw "Could not identify the RandomX h2inc command in $($file.FullName)."
    }
}
