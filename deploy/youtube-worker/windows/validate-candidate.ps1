[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$CandidateRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath($CandidateRoot)
$adapter = Join-Path $root 'runtime\scripts\youtube_global_windows_adapter.ps1'
$worker = Join-Path $root 'runtime\scripts\youtube_global_chunk_worker.py'
$wrapper = Join-Path $root 'windows\yt-dlp-anonymous.cmd'
foreach ($path in @($adapter,$worker,$wrapper)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'candidate source missing or unsafe' }
}
$tokens = $null; $errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($adapter,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) { throw 'native adapter parse failed' }
$adapterTestOutput = @(& (Join-Path $root 'windows\test-adapter-recovery.ps1') -CandidateRoot $root)
if (-not $?) { throw 'native adapter recovery regressions failed' }
$adapterTests = ([string]::Join("`n", [string[]]$adapterTestOutput)) | ConvertFrom-Json
if ($adapterTests.native_adapter_tests_passed -ne $true -or $adapterTests.provider_calls -ne 0 -or $adapterTests.checks -ne 5) { throw 'native adapter recovery receipt differs' }
$python = (Get-Command python.exe -ErrorAction Stop).Source
# Compile source bytes only; no candidate imports or provider requests.
& $python -m py_compile $worker
if ($LASTEXITCODE -ne 0) { throw 'native worker parse failed' }
& $python -m unittest discover -s (Join-Path $root 'tests') -p 'test_worker_recovery.py' -v
if ($LASTEXITCODE -ne 0) { throw 'native mocked worker regression failed' }
& $python -m unittest discover -s (Join-Path $root 'tests') -p 'test_worker_process_tree.py' -v
if ($LASTEXITCODE -ne 0) { throw 'native offline process-tree regression failed' }
$versions = @(& $wrapper --worker-preflight 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'actual-account offline wrapper preflight failed' }
$text = [string]::Join("`n",[string[]]$versions)
if ($text -notmatch '(?m)^node v(\d+)\.\d+\.\d+\s*$' -or [int]$Matches[1] -lt 22 -or $text -notmatch '(?m)^2026\.08\.19\s*$') { throw 'offline runtime versions differ from contract' }
$node = Join-Path $env:ProgramFiles 'nodejs\node.exe'
$extractor = Join-Path $env:USERPROFILE '.openclaw\youtube-transcript-tools\yt-dlp-2026.08.19\yt-dlp.exe'
$receipt = [ordered]@{
    schema = 'openclaw.youtube.windows-native-validation.v1'
    checked_at = [DateTimeOffset]::UtcNow.ToString('o')
    worker_account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    powershell_version = $PSVersionTable.PSVersion.ToString()
    adapter_parse_errors = @($errors).Count
    native_adapter_tests_passed = $true
    worker_parse_passed = $true
    native_worker_tests_passed = $true
    native_process_tree_tests_passed = $true
    provider_calls = 0
    offline_preflight_passed = $true
    runtime_versions = @($versions | ForEach-Object { [string]$_ })
    component_hashes = [ordered]@{}
    launcher_binaries = [ordered]@{}
}
foreach ($path in @($adapter,$worker,$wrapper)) { $receipt.component_hashes[(Split-Path -Leaf $path)] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
foreach ($path in @($python,$node,$extractor)) { $receipt.launcher_binaries[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
$receipt | ConvertTo-Json -Depth 8
