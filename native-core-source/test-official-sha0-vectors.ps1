param([string]$NdkRoot = (Join-Path $PSScriptRoot '..\..\.tools\android-sdk\ndk\28.2.13676358'))
$ErrorActionPreference = 'Continue'
$llvm = Join-Path $NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$testRoot = Join-Path $PSScriptRoot 'tests'
$obj = Join-Path $testRoot 'official_sha0_host.obj'
$dll = Join-Path $testRoot 'official_sha0_host.dll'
& (Join-Path $llvm 'clang.exe') '--target=x86_64-pc-windows-msvc' '-ffreestanding' '-fno-builtin' '-fno-stack-protector' '-O2' '-c' (Join-Path $testRoot 'official_sha0_host.c') '-o' $obj
if ($LASTEXITCODE -ne 0) { throw 'Official SHA-0 host compilation failed.' }
& (Join-Path $llvm 'ld.lld.exe') '-flavor' 'link' '/machine:x64' '/dll' '/noentry' '/nodefaultlib' ("/out:" + $dll) $obj
if ($LASTEXITCODE -ne 0) { throw 'Official SHA-0 host linking failed.' }
$declaration = 'using System.Runtime.InteropServices; public static class OfficialSha0Regression { [DllImport(@"' + $dll.Replace('"','""') + '", CallingConvention=CallingConvention.Cdecl)] public static extern void probeHash(byte[] data,int len,byte[] digest); }'
Add-Type -TypeDefinition $declaration
$vectors = (Get-Content -LiteralPath (Join-Path $testRoot 'official-sha0-vectors.json') -Raw | ConvertFrom-Json).vectors
foreach ($vector in $vectors) {
    $value = if ($vector.PSObject.Properties.Name -contains 'ascii') { [string]$vector.ascii } else { ([string]$vector.repeatAscii) * [int]$vector.count }
    $bytes = [Text.Encoding]::ASCII.GetBytes($value)
    $hash = [byte[]]::new(20)
    [OfficialSha0Regression]::probeHash($bytes, $bytes.Length, $hash)
    $actual = [BitConverter]::ToString($hash).Replace('-','').ToLowerInvariant()
    if ($actual -ne $vector.sha0) { throw "Official SHA-0 vector failed at input length $($bytes.Length)" }
}
Write-Output "Official compiled C SHA-0: $($vectors.Count) independent vectors passed."

