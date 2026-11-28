[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$CandidateRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$adapter = Join-Path $CandidateRoot 'runtime\scripts\youtube_global_windows_adapter.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($adapter,[ref]$tokens,[ref]$errors)
if (@($errors).Count) { throw 'adapter test parse failed' }
# Load definitions only, never the adapter's dispatch or production defaults.
foreach ($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]}, $false)) {
    if ($definition.Parent -is [Management.Automation.Language.NamedBlockAst]) {
        . ([scriptblock]::Create($definition.Extent.Text))
    }
}
$scratch = Join-Path $CandidateRoot ('.adapter-fixture-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$script:fixtureRoot = $scratch
$script:fixturePython = (Get-Command python.exe -ErrorAction Stop).Source
$ChunkId = 'fixture-atomic'
$LeaseId = '00000000-0000-4000-8000-000000000001'
$WorkerBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("# offline fixture`n"))
$WorkerGzipBase64 = ''
$UrlsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("fixture0001`thttps://www.youtube.com/watch?v=fixture0001`n"))
$StagingRoot = $scratch
function Get-SafeRoot { param([string]$RawRoot,[bool]$Create) return $script:fixtureRoot }
function Get-PythonPath { return $script:fixturePython }
function Get-ToolDeployment { return @{ compatibility = 'fixture'; fork_revision = ('2' * 40); archiver_revision = ('3' * 40); archiver_sha256 = ('4' * 64); wrapper_sha256 = ('5' * 64); worker_account = 'FIXTURE\fixture' } }
function Start-StagedWorker { param([string]$Base,[switch]$ResumeBlocked) throw 'fixture stop after publication' }
function Assert-Fixture([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
try {
    $writeDefinition = (Get-Item Function:\Write-AtomicBytes).ScriptBlock
    # A failure before publication leaves no authoritative chunk directory.
    function Write-AtomicBytes { param([string]$Path,[byte[]]$Bytes) throw 'fixture interrupted preparation' }
    try { Invoke-StageLaunch | Out-Null; throw 'preparation unexpectedly completed' } catch {
        if ($_.Exception.Message -cne 'fixture interrupted preparation') { throw }
    }
    $base = Join-Path $scratch ('chunk-' + $ChunkId)
    Assert-Fixture (-not (Test-Path -LiteralPath $base)) 'partial preparation published a chunk'
    Set-Item Function:\Write-AtomicBytes $writeDefinition
    # A stopped call after atomic publication has a checkpoint and free lock.
    try { Invoke-StageLaunch | Out-Null; throw 'fixture unexpectedly launched' } catch {
        if ($_.Exception.Message -cne 'fixture stop after publication') { throw }
    }
    $checkpoint = Read-JsonFile (Join-Path $base 'status.json')
    Assert-Fixture ($checkpoint.lease_id -ceq $LeaseId -and $checkpoint.items.fixture0001.attempts -eq 0) 'initial checkpoint binding or attempts invalid'
    Assert-Fixture ((Get-WorkerLockFree $base) -eq $true) 'published worker lock not free'
    # A retained PID belonging to this test process must not imply liveness.
    Write-AtomicBytes (Join-Path $base 'worker.pid') ([Text.Encoding]::UTF8.GetBytes([string]$PID))
    Assert-Fixture (-not (Get-WorkerAlive $base)) 'reused PID reported as worker'
    $lock = [IO.File]::Open((Join-Path $base 'worker.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
    try {
        $lock.Lock(0,1)
        Assert-Fixture (Get-WorkerAlive $base) 'held worker lock reported stopped'
    } finally { $lock.Unlock(0,1); $lock.Dispose() }
    $before = (Get-FileHash -LiteralPath (Join-Path $base 'status.json') -Algorithm SHA256).Hash
    try { Invoke-StageLaunch | Out-Null; throw 'duplicate staging unexpectedly accepted' } catch {
        if ($_.Exception.Message -cne 'remote chunk already exists') { throw }
    }
    Assert-Fixture ($before -ceq (Get-FileHash -LiteralPath (Join-Path $base 'status.json') -Algorithm SHA256).Hash) 'duplicate staging changed checkpoint'
    @{ native_adapter_tests_passed = $true; provider_calls = 0; checks = 5 } | ConvertTo-Json -Compress
} finally {
    # This is solely a newly created isolated test fixture, never a run tree.
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
