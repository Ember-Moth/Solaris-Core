param(
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$RootDirectory = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RootDirectory "build-windows\install\x86_64"
}
$WorkDirectory = if ($env:SOLARIS_CORE_WINDOWS_WORK_DIR) {
    $env:SOLARIS_CORE_WINDOWS_WORK_DIR
} else {
    Join-Path $RootDirectory "build-windows\work\x86_64"
}
$BoringSslCommit = "922c15f36cc75db5af33c46f9ea8934553fb808e"
$BoringSslRepository = if ($env:BORINGSSL_REPOSITORY) {
    $env:BORINGSSL_REPOSITORY
} else {
    "https://boringssl.googlesource.com/boringssl"
}

function Require-Command([string]$Override, [string]$Name) {
    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        if (-not (Test-Path -LiteralPath $Override -PathType Leaf)) {
            throw "command is missing: $Override"
        }
        return (Resolve-Path -LiteralPath $Override).Path
    }
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) { throw "$Name was not found in PATH" }
    return $command.Source
}

function Assert-NativeSuccess([string]$Operation) {
    if ($LASTEXITCODE -ne 0) {
        throw "Solaris core Windows build: $Operation failed with exit code $LASTEXITCODE"
    }
}

$CMake = Require-Command $env:SOLARIS_CMAKE_BIN "cmake"
$Git = Require-Command $env:SOLARIS_GIT_BIN "git"
$Generator = if ($env:CMAKE_GENERATOR) { $env:CMAKE_GENERATOR } else { "Ninja" }
$BoringSource = Join-Path $WorkDirectory "boringssl-src"
$BoringBuild = Join-Path $WorkDirectory "boringssl-build"
$BoringInstall = Join-Path $WorkDirectory "boringssl-install"
$CoreBuild = Join-Path $WorkDirectory "aproxy-build"

New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $BoringSource ".git"))) {
    New-Item -ItemType Directory -Force -Path $BoringSource | Out-Null
    & $Git -C $BoringSource init
    Assert-NativeSuccess "BoringSSL repository initialization"
    & $Git -C $BoringSource remote add origin $BoringSslRepository
    Assert-NativeSuccess "BoringSSL remote configuration"
}
$currentCommit = (& $Git -C $BoringSource rev-parse HEAD 2>$null)
$patchPath = Join-Path $RootDirectory "third_party\boringssl-reality.patch"
& $Git -C $BoringSource apply --reverse --check $patchPath 2>$null
$patchAlreadyApplied = $LASTEXITCODE -eq 0
if ($currentCommit -ne $BoringSslCommit -or -not $patchAlreadyApplied) {
    & $Git -C $BoringSource fetch --depth 1 origin $BoringSslCommit
    Assert-NativeSuccess "BoringSSL pinned commit fetch"
    & $Git -C $BoringSource checkout --detach $BoringSslCommit
    Assert-NativeSuccess "BoringSSL pinned commit checkout"
    & $Git -C $BoringSource reset --hard $BoringSslCommit
    Assert-NativeSuccess "BoringSSL worktree reset"
    & $Git -C $BoringSource clean -fd
    Assert-NativeSuccess "BoringSSL generated file cleanup"
    & $Git -C $BoringSource apply $patchPath
    Assert-NativeSuccess "BoringSSL REALITY patch"
}

& $CMake -S $BoringSource -B $BoringBuild -G $Generator `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON `
    -DBUILD_SHARED_LIBS=OFF
Assert-NativeSuccess "BoringSSL configure"
& $CMake --build $BoringBuild --config Release --target crypto ssl
Assert-NativeSuccess "BoringSSL build"

if (Test-Path -LiteralPath $BoringInstall) {
    Remove-Item -LiteralPath $BoringInstall -Recurse -Force
}
New-Item -ItemType Directory -Force -Path `
    (Join-Path $BoringInstall "include"), (Join-Path $BoringInstall "lib") | Out-Null
Copy-Item -Path (Join-Path $BoringSource "include\*") `
    -Destination (Join-Path $BoringInstall "include") -Recurse
$CryptoLibrary = Get-ChildItem -LiteralPath $BoringBuild -Recurse -File `
    -Filter "crypto.lib" | Select-Object -First 1
$SslLibrary = Get-ChildItem -LiteralPath $BoringBuild -Recurse -File `
    -Filter "ssl.lib" | Select-Object -First 1
if ($null -eq $CryptoLibrary -or $null -eq $SslLibrary) {
    throw "BoringSSL did not produce crypto.lib and ssl.lib"
}
Copy-Item -LiteralPath $CryptoLibrary.FullName `
    -Destination (Join-Path $BoringInstall "lib\crypto.lib")
Copy-Item -LiteralPath $SslLibrary.FullName `
    -Destination (Join-Path $BoringInstall "lib\ssl.lib")

& $CMake -S $RootDirectory -B $CoreBuild -G $Generator `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_INSTALL_PREFIX=$OutputDirectory `
    -DAPROXY_BORINGSSL_ROOT=$BoringInstall `
    -DAPROXY_ENABLE_TUN=ON `
    -DAPROXY_FETCH_WINDOWS_DEPS=ON `
    -DFETCHCONTENT_UPDATES_DISCONNECTED=ON
Assert-NativeSuccess "Solaris core configure"
& $CMake --build $CoreBuild --config Release --target aproxy
Assert-NativeSuccess "Solaris core build"
& $CMake --install $CoreBuild --config Release
Assert-NativeSuccess "Solaris core install"

$CoreDll = Join-Path $OutputDirectory "bin\core.dll"
if (-not (Test-Path -LiteralPath $CoreDll -PathType Leaf)) {
    throw "Solaris core DLL is missing: $CoreDll"
}
Write-Host "Solaris core Windows artifacts: $OutputDirectory"
