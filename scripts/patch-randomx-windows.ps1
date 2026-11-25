$ErrorActionPreference = "Stop"

# The published randomx-bindings-sys 0.1.5 crate omits vcxproj/h2inc.ps1,
# but includes the generated src/asm/configuration.asm. Keep that packaged
# assembly and remove only the unavailable generation rule on Windows.
cargo fetch
if ($LASTEXITCODE -ne 0) { throw "cargo fetch failed." }

$registry = Join-Path $env:USERPROFILE ".cargo\registry\src"
$cmakeFiles = @(Get-ChildItem -Path $registry -Filter "CMakeLists.txt" -Recurse |
    Where-Object { $_.FullName -match "\\randomx-bindings-sys-0\.1\.5\\randomx\\CMakeLists\.txt$" })

if ($cmakeFiles.Count -eq 0) {
    throw "randomx-bindings-sys 0.1.5 CMakeLists.txt was not found. Run cargo fetch first."
}

foreach ($file in $cmakeFiles) {
    $randomxRoot = Split-Path -Parent $file.FullName
    $asmFile = Join-Path $randomxRoot "src\asm\configuration.asm"

    if (-not (Test-Path -LiteralPath $asmFile -PathType Leaf)) {
        throw "The packaged RandomX assembly file is missing: $asmFile"
    }
    if ((Get-Item -LiteralPath $asmFile).Length -eq 0) {
        throw "The packaged RandomX assembly file is empty: $asmFile"
    }

    $content = Get-Content -LiteralPath $file.FullName -Raw
    $rulePattern = '(?is)add_custom_command\s*\(\s*OUTPUT\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/src/asm/configuration\.asm.*?WORKING_DIRECTORY\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/vcxproj\s*\)'
    $updated = [regex]::Replace(
        $content,
        $rulePattern,
        '# Windows crate package already includes src/asm/configuration.asm; the generator script is not packaged.'
    )

    if ($updated -ne $content) {
        Set-Content -LiteralPath $file.FullName -Value $updated -NoNewline
        Write-Host "Disabled unavailable RandomX assembly-generation rule; using packaged assembly: $asmFile"
    } elseif ($content -match '(?i)generator script is not packaged') {
        Write-Host "RandomX assembly-generation rule is already disabled: $file"
    } else {
        throw "Could not safely locate the RandomX assembly-generation rule in $($file.FullName)."
    }

    Write-Host "Verified packaged assembly: $asmFile ($((Get-Item -LiteralPath $asmFile).Length) bytes)"
}
