param([string]$NdkRoot = (Join-Path $PSScriptRoot '..\..\.tools\android-sdk\ndk\28.2.13676358'))
$ErrorActionPreference = 'Continue'
$llvm = Join-Path $NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$testRoot = Join-Path $PSScriptRoot 'tests'
$obj = Join-Path $testRoot 'managed_tap_policy_test.obj'
$exe = Join-Path $testRoot 'managed_tap_policy_test.exe'
& (Join-Path $llvm 'clang.exe') '--target=x86_64-pc-windows-msvc' '-ffreestanding' '-fno-builtin' '-O2' '-c' (Join-Path $testRoot 'managed_tap_policy_test.c') ('-I' + (Join-Path $PSScriptRoot 'compat\include')) '-o' $obj
if ($LASTEXITCODE -ne 0) { throw 'Managed TAP policy host compilation failed.' }
& (Join-Path $llvm 'ld.lld.exe') '-flavor' 'link' '/machine:x64' '/entry:mainCRTStartup' '/subsystem:console' '/nodefaultlib' ("/out:" + $exe) $obj
if ($LASTEXITCODE -ne 0) { throw 'Managed TAP policy host linking failed.' }
& $exe
if ($LASTEXITCODE -ne 0) { throw "Managed TAP policy assertion failed: $LASTEXITCODE" }
Write-Output 'Managed TAP name/UUID validation boundary tests passed. Host policy only; no Android TAP or lock runtime claim.'
