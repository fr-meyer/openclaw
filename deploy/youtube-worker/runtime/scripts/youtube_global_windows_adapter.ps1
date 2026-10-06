[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Probe', 'StageLaunch', 'Resume', 'Package', 'BundleInfo', 'ReadChunk')]
    [string]$Action = 'Validate',
    [string]$StagingRoot = "$env:USERPROFILE\.openclaw\youtube-transcript-staging\global",
    [string]$ChunkId,
    [string]$LeaseId,
    [string]$CheckpointSha256,
    [string]$WorkerBase64,
    [string]$WorkerGzipBase64,
    [string]$UrlsBase64,
    [string]$Archiver = "$env:USERPROFILE\Documents\GitHub\shared-agent-skills\skills\youtube-transcript-archive\scripts\archive_youtube_transcript.py",
    [string]$YtDlpWrapper = "$env:USERPROFILE\.openclaw\youtube-transcript-tools\yt-dlp-anonymous.cmd",
    [int]$MaxAttempts = 3,
    [int]$InterItemSleepSeconds = 10,
    [Int64]$Offset = 0,
    [int]$Count = 0,
    [Int64]$MinimumFreeBytes = 5368709120,
    [double]$MaximumCpuPercent = 85.0,
    [int]$MinimumBatteryPercent = 30
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$MediaExtensions = @('.mp4','.mkv','.webm','.mov','.avi','.m4v','.mp3','.m4a','.aac','.wav','.flac','.ogg','.opus')

function Write-Result([object]$Payload) {
    $Payload | ConvertTo-Json -Depth 12 -Compress
}

function Get-PythonPath {
    foreach ($candidate in @('python.exe', 'python3.exe')) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $command) { return $command.Source }
    }
    return $null
}

function Get-TarPath {
    $command = Get-Command tar.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) { return $command.Source }
    return $null
}

function Assert-ContainedPath([string]$Path, [string]$ContainmentRoot) {
    $root = [System.IO.Path]::GetFullPath($ContainmentRoot).TrimEnd('\')
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not ($full.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase))) {
        throw 'path escapes its containment root'
    }
    return $full
}

function Get-ExistingFilesystemItem([string]$Path) {
    try {
        return Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -match 'PathNotFound|ItemNotFound|DirectoryNotFound' -or $_.Exception.Message -like 'Cannot find path*') {
            return $null
        }
        throw
    }
}

function Assert-NoReparseAncestors([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $pathRoot = [System.IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($pathRoot)) { throw 'path root is unavailable' }
    $current = $pathRoot
    $relative = $full.Substring($pathRoot.Length).TrimStart('\')
    $components = @('')
    if (-not [string]::IsNullOrWhiteSpace($relative)) { $components += @($relative.Split('\')) }
    foreach ($part in $components) {
        if (-not [string]::IsNullOrEmpty($part)) { $current = Join-Path $current $part }
        $item = Get-ExistingFilesystemItem -Path $current
        if ($null -ne $item -and [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'reparse point refused in guarded path'
        }
    }
    return $full
}

function Assert-NoReparsePath([string]$Path, [string]$ContainmentRoot) {
    $root = [System.IO.Path]::GetFullPath($ContainmentRoot).TrimEnd('\')
    $full = Assert-ContainedPath -Path $Path -ContainmentRoot $root
    # Validate from the filesystem root, not only from ContainmentRoot, so a
    # USERPROFILE that itself sits under a junction is rejected before writes.
    [void](Assert-NoReparseAncestors -Path $full)
    return $full
}

function Assert-SafeTree([string]$Path, [string]$ContainmentRoot) {
    $full = Assert-NoReparsePath -Path $Path -ContainmentRoot $ContainmentRoot
    if (Test-Path -LiteralPath $full -PathType Container) {
        foreach ($item in @(Get-ChildItem -LiteralPath $full -Recurse -Force -ErrorAction Stop)) {
            [void](Assert-ContainedPath -Path $item.FullName -ContainmentRoot $full)
            if ([bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw 'reparse point refused in guarded tree'
            }
        }
    }
    return $full
}

function Get-SafeRoot([string]$RawRoot, [bool]$Create) {
    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) { throw 'USERPROFILE is unavailable' }
    $profile = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
    $full = [System.IO.Path]::GetFullPath($RawRoot).TrimEnd('\')
    if (-not $full.StartsWith($profile + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'staging root must stay under USERPROFILE'
    }
    $tempRoots = @($env:TEMP, $env:TMP) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
        [System.IO.Path]::GetFullPath($_).TrimEnd('\')
    }
    foreach ($temp in $tempRoots) {
        if ($full.Equals($temp, [System.StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($temp + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'temporary staging root refused'
        }
    }
    # Check every existing ancestor before creation.  Otherwise New-Item could
    # follow a junction below USERPROFILE and create the requested root outside
    # the guarded tree before the adapter gets a chance to reject it.
    [void](Assert-NoReparsePath -Path $full -ContainmentRoot $profile)
    if ($Create -and -not (Test-Path -LiteralPath $full -PathType Container)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
    }
    [void](Assert-NoReparsePath -Path $full -ContainmentRoot $profile)
    return (Assert-SafeTree -Path $full -ContainmentRoot $profile)
}

function Write-AtomicBytes([string]$Path, [byte[]]$Bytes) {
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporary = Join-Path $parent ('.' + [System.IO.Path]::GetFileName($Path) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Write-AtomicJson([string]$Path, [hashtable]$Payload) {
    $raw = [System.Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Depth 12 -Compress) + "`n")
    Write-AtomicBytes -Path $Path -Bytes $raw
}

function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Get-WorkerAlive([string]$Base) {
    # The worker retains its PID receipt after exit. Windows can reuse that
    # PID, but only a live worker holds this chunk's OS byte-range lock.
    # Missing/unknown locks remain ineligible for recovery and packaging.
    return (Get-WorkerLockFree $Base) -eq $false
}

function Get-WorkerLockFree([string]$Base) {
    # Inspect the existing OS byte-range lock; never replace/create its file.
    $path = Assert-NoReparsePath -Path (Join-Path $Base 'worker.lock') -ContainmentRoot $Base
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $stream = $null
    $locked = $false
    try {
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        $stream.Lock(0, 1)
        $locked = $true
        return $true
    } catch [IO.IOException] { return $false }
    finally {
        if ($null -ne $stream) {
            if ($locked) { $stream.Unlock(0, 1) }
            $stream.Dispose()
        }
    }
}

function Get-ToolDeployment {
    $path = Join-Path $env:USERPROFILE '.openclaw\youtube-transcript-tools\deployment.json'
    [void](Assert-NoReparseAncestors $path)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -gt 16384) { throw 'managed component receipt unavailable' }
    $record = Read-JsonFile $path
    if ($record.schema -cne 'openclaw.youtube.windows-assets.v1' -or $record.compatibility -cne 'windows-caption-worker-v2') { throw 'managed component contract invalid' }
    if ($record.fork_repository -cne 'fr-meyer/openclaw' -or $record.archiver_repository -cne 'fr-meyer/agent-toolkit' -or $record.archiver_source_path -cne 'skills/youtube-transcript-archive/scripts/archive_youtube_transcript.py') { throw 'managed source ownership invalid' }
    if ($record.fork_revision -notmatch '^[0-9a-f]{40}$' -or $record.archiver_revision -notmatch '^[0-9a-f]{40}$') { throw 'managed source revision invalid' }
    $account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($record.worker_account -cne $account) { throw 'managed worker account mismatch' }
    foreach ($key in @('archiver_sha256','wrapper_sha256')) {
        if ($record.$key -notmatch '^[0-9a-f]{64}$') { throw 'managed component hash invalid' }
    }
    [void](Assert-NoReparseAncestors $Archiver)
    [void](Assert-NoReparseAncestors $YtDlpWrapper)
    if ((Get-FileHash -LiteralPath $Archiver -Algorithm SHA256).Hash.ToLowerInvariant() -cne $record.archiver_sha256 -or (Get-FileHash -LiteralPath $YtDlpWrapper -Algorithm SHA256).Hash.ToLowerInvariant() -cne $record.wrapper_sha256) { throw 'managed component content drifted' }
    return [ordered]@{ compatibility = $record.compatibility; fork_revision = $record.fork_revision; archiver_revision = $record.archiver_revision; archiver_sha256 = $record.archiver_sha256; wrapper_sha256 = $record.wrapper_sha256; worker_account = $account }
}

function Test-Archive([string]$ArchiveRoot, [string]$Folder, [string]$VideoId) {
    $archiveRootFull = Assert-NoReparsePath -Path $ArchiveRoot -ContainmentRoot $ArchiveRoot
    $folderFull = Assert-SafeTree -Path $Folder -ContainmentRoot $archiveRootFull
    if (-not (Test-Path -LiteralPath $folderFull -PathType Container)) { throw "$VideoId archive directory missing" }
    $manifestPath = Join-Path $Folder 'manifest.json'
    $reportPath = Join-Path $Folder 'report.md'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw "$VideoId missing manifest or report"
    }
    $manifest = Read-JsonFile $manifestPath
    if ($manifest.video_id -ne $VideoId) { throw "$VideoId manifest identity mismatch" }
    $files = @($manifest.files)
    if ($files.Count -eq 0) { throw "$VideoId manifest files missing" }
    foreach ($raw in $files) {
        $relative = [string]$raw
        if ([System.IO.Path]::IsPathRooted($relative) -or $relative.Split(@('\','/')).Contains('..')) { throw "$VideoId unsafe manifest path" }
        $candidate = Assert-NoReparsePath -Path (Join-Path $folderFull $relative) -ContainmentRoot $folderFull
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "$VideoId listed file missing" }
    }
    $media = @(Get-ChildItem -LiteralPath $Folder -Recurse -File | Where-Object { $MediaExtensions -contains $_.Extension.ToLowerInvariant() })
    if ($media.Count -gt 0) { throw "$VideoId media file detected" }
}

function Invoke-Validation {
    $reasons = [System.Collections.Generic.List[string]]::new()
    $checks = [ordered]@{}
    function Add-Reason([string]$Reason) { if (-not $reasons.Contains($Reason)) { $reasons.Add($Reason) } }
    $checks.platform = [System.Environment]::OSVersion.Platform.ToString()
    if ($checks.platform -ne 'Win32NT') { Add-Reason 'platform_not_windows' }
    $python = Get-PythonPath
    $checks.python = $python
    if ([string]::IsNullOrWhiteSpace($python)) { Add-Reason 'python_missing' }
    $tar = Get-TarPath
    $checks.tar = $tar
    if ([string]::IsNullOrWhiteSpace($tar)) { Add-Reason 'tar_missing' }
    $checks.archiver = $Archiver
    $checks.archiverPresent = Test-Path -LiteralPath $Archiver -PathType Leaf
    if (-not $checks.archiverPresent) { Add-Reason 'archiver_missing' }
    $checks.ytDlpWrapper = $YtDlpWrapper
    $checks.ytDlpWrapperPresent = Test-Path -LiteralPath $YtDlpWrapper -PathType Leaf
    if (-not $checks.ytDlpWrapperPresent) { Add-Reason 'yt_dlp_wrapper_missing' }
    try { $checks.assets = Get-ToolDeployment } catch { $checks.assets = $null; Add-Reason 'managed_component_validation_failed' }
    try {
        $root = Get-SafeRoot -RawRoot $StagingRoot -Create $false
        $checks.stagingRoot = $root
        $checks.stagingRootPresent = Test-Path -LiteralPath $root -PathType Container
        if (-not $checks.stagingRootPresent) { Add-Reason 'staging_root_missing' }
    } catch {
        $checks.stagingRoot = $StagingRoot
        $checks.stagingRootPresent = $false
        Add-Reason 'staging_root_unsafe'
    }
    try {
        $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($StagingRoot)))
        $checks.freeBytes = $drive.AvailableFreeSpace
        if ($drive.AvailableFreeSpace -lt $MinimumFreeBytes) { Add-Reason 'free_space_low' }
    } catch { $checks.freeBytes = $null; Add-Reason 'free_space_unavailable' }
    try {
        $values = @(Get-CimInstance Win32_Processor | ForEach-Object { [double]$_.LoadPercentage })
        $cpu = if ($values.Count) { ($values | Measure-Object -Average).Average } else { $null }
        $checks.cpuPercent = $cpu
        if ($null -eq $cpu) { Add-Reason 'cpu_load_unavailable' } elseif ($cpu -gt $MaximumCpuPercent) { Add-Reason 'system_load_high' }
    } catch { $checks.cpuPercent = $null; Add-Reason 'cpu_load_unavailable' }
    try {
        $batteries = @(Get-CimInstance Win32_Battery -ErrorAction Stop)
        if ($batteries.Count) {
            $battery = ($batteries | Measure-Object EstimatedChargeRemaining -Minimum).Minimum
            $checks.batteryPercent = $battery
            if ($null -eq $battery -or [int]$battery -lt $MinimumBatteryPercent) { Add-Reason 'battery_low' }
        } else { $checks.batteryPercent = $null }
    } catch { $checks.batteryPercent = $null }
    $checks.transport = 'windows-powershell-v1'
    $checks.transportImplemented = $true
    return [ordered]@{
        schema = 'franck.youtube-global-pool.windows-adapter-validation.v1'
        checkedAt = [DateTimeOffset]::UtcNow.ToString('o')
        readOnly = $true
        eligible = ($reasons.Count -eq 0)
        reasons = @($reasons | Sort-Object -Unique)
        checks = $checks
        cookiesUsed = $false
        mediaFiles = 0
    }
}

function Require-Identifiers {
    if ([string]::IsNullOrWhiteSpace($ChunkId) -or $ChunkId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$') { throw 'invalid chunk id' }
    $parsed = [guid]::Empty
    if ([string]::IsNullOrWhiteSpace($LeaseId) -or -not [guid]::TryParse($LeaseId, [ref]$parsed)) { throw 'invalid lease id' }
}

function Get-ChunkBase([bool]$CreateRoot) {
    Require-Identifiers
    $root = Get-SafeRoot -RawRoot $StagingRoot -Create $CreateRoot
    return (Assert-NoReparsePath -Path (Join-Path $root ('chunk-' + $ChunkId)) -ContainmentRoot $root)
}

function Invoke-Probe {
    $base = Get-ChunkBase -CreateRoot $false
    $root = Get-SafeRoot -RawRoot $StagingRoot -Create $false
    if (Test-Path -LiteralPath $base) { [void](Assert-SafeTree -Path $base -ContainmentRoot $root) }
    $status = Read-JsonFile (Join-Path $base 'status.json')
    $staging = Read-JsonFile (Join-Path $base 'staging.json')
    if ($null -ne $staging -and $staging.lease_id -ne $LeaseId) { throw 'staging lease mismatch' }
    if ($null -ne $status -and $status.lease_id -ne $LeaseId) { throw 'status lease mismatch' }
    return [ordered]@{
        schema = 'franck.youtube-global-pool.windows-probe.v1'
        chunkId = $ChunkId
        leaseId = $LeaseId
        exists = Test-Path -LiteralPath $base -PathType Container
        workerAlive = Get-WorkerAlive $base
        workerLockFree = Get-WorkerLockFree $base
        statusSha256 = if (Test-Path -LiteralPath (Join-Path $base 'status.json') -PathType Leaf) { (Get-FileHash -LiteralPath (Join-Path $base 'status.json') -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        status = $status
        staging = $staging
        cookiesUsed = $false
        mediaFiles = 0
    }
}

function Start-StagedWorker([string]$Base, [switch]$ResumeBlocked) {
    $root = Get-SafeRoot -RawRoot $StagingRoot -Create $false
    $Base = Assert-SafeTree -Path $Base -ContainmentRoot $root
    $python = Get-PythonPath
    if ([string]::IsNullOrWhiteSpace($python)) { throw 'python missing' }
    $worker = Join-Path $Base 'worker.py'
    $urls = Join-Path $Base 'urls.tsv'
    [void](Assert-NoReparsePath -Path $worker -ContainmentRoot $Base)
    [void](Assert-NoReparsePath -Path $urls -ContainmentRoot $Base)
    [void](Assert-NoReparsePath -Path (Join-Path $Base 'staging.json') -ContainmentRoot $Base)
    $staging = Read-JsonFile (Join-Path $Base 'staging.json')
    if ($null -eq $staging -or $staging.lease_id -ne $LeaseId) { throw 'durable staging lease mismatch' }
    if ((Get-FileHash -LiteralPath $worker -Algorithm SHA256).Hash.ToLowerInvariant() -ne $staging.worker_sha256) { throw 'worker hash mismatch' }
    if ((Get-FileHash -LiteralPath $urls -Algorithm SHA256).Hash.ToLowerInvariant() -ne $staging.urls_sha256) { throw 'urls hash mismatch' }
    $assets = Get-ToolDeployment
    foreach ($key in @('compatibility','fork_revision','archiver_revision','archiver_sha256','wrapper_sha256','worker_account')) {
        if ($null -eq $staging.assets -or $staging.assets.$key -cne $assets[$key]) { throw 'staged component pins changed' }
    }
    if (Get-WorkerAlive $Base) { throw 'worker already active; recovery refused' }
    if ($ResumeBlocked) {
        if ((Get-WorkerLockFree $Base) -ne $true) { throw 'worker OS lock is not proven free' }
        if ($CheckpointSha256 -notmatch '^[0-9a-f]{64}$') { throw 'explicit recovery checkpoint digest required' }
        $statusPath = Join-Path $Base 'status.json'
        [void](Assert-NoReparsePath -Path $statusPath -ContainmentRoot $Base)
        if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf) -or (Get-FileHash -LiteralPath $statusPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $CheckpointSha256) { throw 'recovery checkpoint changed' }
    }
    $arguments = @(
        $worker, '--base', $Base, '--urls', $urls, '--archive-root', (Join-Path $Base 'archive'),
        '--python', $python, '--archiver', $Archiver, '--yt-dlp', $YtDlpWrapper,
        '--max-attempts', [string]$MaxAttempts, '--inter-item-sleep', [string]$InterItemSleepSeconds,
        '--lease-id', $LeaseId, '--wrapper-preflight'
    )
    if ($ResumeBlocked) { $arguments += @('--resume-blocked', '--checkpoint-sha256', $CheckpointSha256) }
    function Quote-ProcessArgument([string]$Value) { return '"' + $Value.Replace('"','\"') + '"' }
    $argumentLine = ($arguments | ForEach-Object { Quote-ProcessArgument ([string]$_) }) -join ' '
    # The shared archiver emits UTF-8 through yt-dlp.  Windows PowerShell and
    # Python otherwise default subprocess text decoding to the active ANSI
    # code page (commonly cp1252), which can corrupt or reject valid metadata.
    # Scope the override to the worker process tree and restore this adapter's
    # process environment immediately after Start-Process inherits it.
    $previousPythonUtf8 = [Environment]::GetEnvironmentVariable('PYTHONUTF8', 'Process')
    $previousPythonIoEncoding = [Environment]::GetEnvironmentVariable('PYTHONIOENCODING', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('PYTHONUTF8', '1', 'Process')
        [Environment]::SetEnvironmentVariable('PYTHONIOENCODING', 'utf-8', 'Process')
        $process = Start-Process -FilePath $python -ArgumentList $argumentLine -WorkingDirectory $Base -RedirectStandardOutput (Join-Path $Base 'worker.out') -RedirectStandardError (Join-Path $Base 'worker.err') -WindowStyle Hidden -PassThru
    } finally {
        [Environment]::SetEnvironmentVariable('PYTHONUTF8', $previousPythonUtf8, 'Process')
        [Environment]::SetEnvironmentVariable('PYTHONIOENCODING', $previousPythonIoEncoding, 'Process')
    }
    for ($attempt = 0; $attempt -lt 300; $attempt++) {
        Start-Sleep -Milliseconds 100
        if (Get-WorkerAlive $Base) { return Invoke-Probe }
        if ($process.HasExited) {
            $probe = Invoke-Probe
            if ($probe.status -and @('blocked_interrupted','blocked_configuration','complete','complete_with_blocked') -contains $probe.status.state) { return $probe }
            throw "worker exited before durable PID checkpoint (exit $($process.ExitCode))"
        }
    }
    try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch {}
    throw 'worker failed to acquire durable lock'
}

function Invoke-StageLaunch {
    Require-Identifiers
    $assets = Get-ToolDeployment
    $hasRawWorker = -not [string]::IsNullOrWhiteSpace($WorkerBase64)
    $hasGzipWorker = -not [string]::IsNullOrWhiteSpace($WorkerGzipBase64)
    if ($hasRawWorker -eq $hasGzipWorker -or [string]::IsNullOrWhiteSpace($UrlsBase64)) { throw 'exactly one worker payload and the URL payload are required' }
    # Validate in memory before creating a chunk. A private preparation tree
    # is published by one same-volume directory rename only after all pins,
    # the free lock and a recoverable initial checkpoint are durable.
    if (([string]$WorkerBase64).Length -gt 1398104 -or ([string]$WorkerGzipBase64).Length -gt 1398104 -or ([string]$UrlsBase64).Length -gt 8192) { throw 'staging payload exceeds budget' }
    if ($hasGzipWorker) {
        $compressed = [Convert]::FromBase64String($WorkerGzipBase64)
        $input = [IO.MemoryStream]::new($compressed, $false)
        $gzip = [IO.Compression.GZipStream]::new($input, [IO.Compression.CompressionMode]::Decompress)
        $output = [IO.MemoryStream]::new()
        try {
            $buffer = New-Object byte[] 65536
            while (($read = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {
                if ($output.Length + $read -gt 1048576) { throw 'worker expansion exceeds budget' }
                $output.Write($buffer, 0, $read)
            }
            $worker = $output.ToArray()
        } finally {
            $output.Dispose()
            $gzip.Dispose()
            $input.Dispose()
        }
    } else {
        $worker = [Convert]::FromBase64String($WorkerBase64)
    }
    if ($worker.Length -lt 1 -or $worker.Length -gt 1048576) { throw 'worker payload exceeds budget' }
    $urls = [Convert]::FromBase64String($UrlsBase64)
    $lines = @([System.Text.Encoding]::UTF8.GetString($urls).Split(@("`r`n","`n"), [System.StringSplitOptions]::RemoveEmptyEntries))
    if ($lines.Count -lt 1 -or $lines.Count -gt 25) { throw 'invalid URL count' }
    $ids = @()
    foreach ($line in $lines) {
        $parts = $line.Split("`t", 2)
        if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[A-Za-z0-9_-]{11}$' -or $parts[1] -cne ('https://www.youtube.com/watch?v=' + $parts[0])) { throw 'invalid URL row' }
        $ids += $parts[0]
    }
    if (@($ids | Sort-Object -Unique).Count -ne $ids.Count) { throw 'duplicate video IDs' }
    $python = Get-PythonPath
    if ([string]::IsNullOrWhiteSpace($python)) { throw 'python missing' }
    $root = Get-SafeRoot -RawRoot $StagingRoot -Create $true
    $base = Assert-NoReparsePath -Path (Join-Path $root ('chunk-' + $ChunkId)) -ContainmentRoot $root
    if (Test-Path -LiteralPath $base) { throw 'remote chunk already exists' }
    $preparation = Join-Path $root ('.stage-' + $ChunkId + '-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $preparation | Out-Null
    $preparation = Assert-SafeTree -Path $preparation -ContainmentRoot $root
    # Orphaned private preparation trees are preserved, never launched or
    # automatically cleaned. They cannot strand the authoritative chunk.
    $staging = [ordered]@{
        schema = 'franck.youtube-global-pool.windows-staging.v1'
        chunk_id = $ChunkId
        lease_id = $LeaseId
        storage_class = 'user_home_persistent'
        automatic_remote_cleanup = $false
        worker_sha256 = ''
        urls_sha256 = ''
        assets = $assets
        video_ids = $ids
        cookies_used = $false
        media_files = 0
        stage_publication = 'atomic_directory_v1'
    }
    Write-AtomicJson -Path (Join-Path $preparation 'stage-intent.json') -Payload @{ chunk_id = $ChunkId; lease_id = $LeaseId; state = 'preparing'; assets = $assets }
    Write-AtomicBytes -Path (Join-Path $preparation 'worker.py') -Bytes $worker
    Write-AtomicBytes -Path (Join-Path $preparation 'urls.tsv') -Bytes $urls
    $staging.worker_sha256 = (Get-FileHash -LiteralPath (Join-Path $preparation 'worker.py') -Algorithm SHA256).Hash.ToLowerInvariant()
    $staging.urls_sha256 = (Get-FileHash -LiteralPath (Join-Path $preparation 'urls.tsv') -Algorithm SHA256).Hash.ToLowerInvariant()
    & $python -m py_compile (Join-Path $preparation 'worker.py')
    if ($LASTEXITCODE -ne 0) { throw 'worker parser validation failed' }
    $items = [ordered]@{}
    foreach ($id in $ids) { $items[$id] = @{ video_id = $id; url = ('https://www.youtube.com/watch?v=' + $id); state = 'pending'; attempts = 0; failure_class = $null; error = $null; completed_at = $null } }
    Write-AtomicBytes -Path (Join-Path $preparation 'worker.lock') -Bytes ([byte[]]@(0))
    Write-AtomicJson -Path (Join-Path $preparation 'status.json') -Payload @{
        schema = 'franck.youtube-catalog-chunk-worker.v1'; state = 'running'; updated_at = [DateTimeOffset]::UtcNow.ToString('o')
        pid = $null; total = $ids.Count; counts = @{ pending = $ids.Count }; items = $items
        lease_id = $LeaseId; urls_sha256 = $staging.urls_sha256; cookies_used = $false; media_downloaded = $false; circuit_open = $false
        execution_lane = 'trusted-residential-anonymous'; stage_checkpoint = $true
    }
    Write-AtomicJson -Path (Join-Path $preparation 'staging.json') -Payload $staging
    Write-AtomicJson -Path (Join-Path $preparation 'stage-intent.json') -Payload @{ chunk_id = $ChunkId; lease_id = $LeaseId; state = 'committed'; worker_sha256 = $staging.worker_sha256; urls_sha256 = $staging.urls_sha256; assets = $assets }
    [void](Assert-SafeTree -Path $preparation -ContainmentRoot $root)
    # Directory.Move refuses an existing destination; concurrent or uncertain
    # launch never overwrites a published checkpoint, log, attempt or archive.
    [IO.Directory]::Move($preparation, $base)
    return Start-StagedWorker $base
}

function Invoke-Resume {
    $base = Get-ChunkBase -CreateRoot $false
    if (-not (Test-Path -LiteralPath $base -PathType Container)) { throw 'durable chunk staging missing' }
    [void](Assert-SafeTree -Path $base -ContainmentRoot (Get-SafeRoot -RawRoot $StagingRoot -Create $false))
    # Same-lease/hash fencing remains in Start-StagedWorker. Only the explicit
    # Resume action authorizes recovery of a blocked checkpoint.
    return Start-StagedWorker $base -ResumeBlocked
}

function Invoke-Package {
    $base = Get-ChunkBase -CreateRoot $false
    $root = Get-SafeRoot -RawRoot $StagingRoot -Create $false
    [void](Assert-SafeTree -Path $base -ContainmentRoot $root)
    if ((Get-WorkerLockFree $base) -ne $true) { throw 'worker OS lock is not proven free for packaging' }
    $status = Read-JsonFile (Join-Path $base 'status.json')
    if ($null -eq $status -or @('complete','complete_with_blocked') -notcontains $status.state) { throw 'chunk is not importable' }
    if ($status.lease_id -ne $LeaseId -or $status.cookies_used -ne $false -or $status.media_downloaded -ne $false) { throw 'unsafe or mismatched final status' }
    $rows = @(Get-Content -LiteralPath (Join-Path $base 'urls.tsv') -Encoding UTF8 | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $ids = @($rows | ForEach-Object {
        $parts = $_.Split("`t",2)
        if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[A-Za-z0-9_-]{11}$' -or $parts[1] -cne ('https://www.youtube.com/watch?v=' + $parts[0])) { throw 'invalid requested URL row' }
        $parts[0]
    })
    if ($ids.Count -lt 1 -or $ids.Count -gt 25 -or @($ids | Sort-Object -Unique).Count -ne $ids.Count) { throw 'invalid requested item set' }
    $statusIds = @($status.items.PSObject.Properties.Name)
    $requestedKey = [string]::Join("`n", [string[]]@($ids | Sort-Object))
    $statusKey = [string]::Join("`n", [string[]]@($statusIds | Sort-Object))
    if (-not [string]::Equals($requestedKey, $statusKey, [StringComparison]::Ordinal)) { throw 'status item set mismatch' }
    $archived = @($ids | Where-Object { $status.items.PSObject.Properties[$_].Value.state -eq 'archived' })
    $archiveRoot = Join-Path $base 'archive'
    if (Test-Path -LiteralPath $archiveRoot) { [void](Assert-SafeTree -Path $archiveRoot -ContainmentRoot $base) }
    $archiveDirs = if (Test-Path -LiteralPath $archiveRoot) { @(Get-ChildItem -LiteralPath $archiveRoot -Directory | ForEach-Object Name) } else { @() }
    # Compare canonical strings instead of piping empty arrays to
    # Compare-Object: PowerShell collapses an empty pipeline to $null and the
    # parameter binder rejects a legitimate zero-archive result (for example,
    # a chunk containing only skipped_private items).
    $archivedKey = [string]::Join("`n", [string[]]@($archived | Sort-Object))
    $archiveDirsKey = [string]::Join("`n", [string[]]@($archiveDirs | Sort-Object))
    if (-not [string]::Equals($archivedKey, $archiveDirsKey, [StringComparison]::Ordinal)) { throw 'archive/status set mismatch' }
    foreach ($videoId in $archived) { Test-Archive -ArchiveRoot $archiveRoot -Folder (Join-Path $archiveRoot $videoId) -VideoId $videoId }
    $exports = Join-Path $base 'exports'
    New-Item -ItemType Directory -Path $exports -Force | Out-Null
    [void](Assert-SafeTree -Path $exports -ContainmentRoot $base)
    $bundle = Join-Path $exports ("validated-archive-bundle-$LeaseId.tar.gz")
    $receipt = Join-Path $exports ("validated-archive-bundle-$LeaseId.json")
    if (Test-Path -LiteralPath $receipt -PathType Leaf) {
        $prior = Read-JsonFile $receipt
        if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) { throw 'bundle receipt exists but bundle is missing' }
        $digest = (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($prior.sha256 -ne $digest -or [Int64]$prior.size -ne (Get-Item -LiteralPath $bundle).Length) { throw 'existing bundle hash mismatch' }
        return $prior
    }
    $temporary = $bundle + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $tar = Get-TarPath
    if ([string]::IsNullOrWhiteSpace($tar)) { throw 'tar missing' }
    [void](Assert-SafeTree -Path $base -ContainmentRoot $root)
    Push-Location $base
    try {
        & $tar -czf $temporary archive status.json events.jsonl urls.tsv
        if ($LASTEXITCODE -ne 0) { throw 'tar packaging failed' }
    } finally { Pop-Location }
    Move-Item -LiteralPath $temporary -Destination $bundle
    $result = [ordered]@{
        schema = 'franck.youtube-global-pool.windows-bundle.v1'
        chunk_id = $ChunkId
        lease_id = $LeaseId
        state = $status.state
        requested_count = $ids.Count
        archived_count = $archived.Count
        incomplete_count = $ids.Count - $archived.Count
        created_at = [DateTimeOffset]::UtcNow.ToString('o')
        path = $bundle
        sha256 = (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $bundle).Length
        cookies_used = $false
        media_files = 0
    }
    Write-AtomicJson -Path $receipt -Payload $result
    return $result
}

function Get-ExpectedBundle {
    $base = Get-ChunkBase -CreateRoot $false
    $root = Get-SafeRoot -RawRoot $StagingRoot -Create $false
    [void](Assert-SafeTree -Path $base -ContainmentRoot $root)
    $bundle = Join-Path (Join-Path $base 'exports') ("validated-archive-bundle-$LeaseId.tar.gz")
    $bundle = Assert-NoReparsePath -Path $bundle -ContainmentRoot $base
    if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) { throw 'validated bundle is missing' }
    return $bundle
}

function Invoke-BundleInfo {
    $bundle = Get-ExpectedBundle
    $file = Get-Item -LiteralPath $bundle -Force
    return [ordered]@{
        schema = 'franck.youtube-global-pool.windows-bundle-info.v1'
        chunkId = $ChunkId
        leaseId = $LeaseId
        path = $file.FullName
        size = [Int64]$file.Length
        sha256 = (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant()
        cookiesUsed = $false
        mediaFiles = 0
    }
}

function Invoke-ReadChunk {
    if ($Offset -lt 0 -or $Count -lt 1 -or $Count -gt 32768) { throw 'invalid bounded bundle read' }
    $bundle = Get-ExpectedBundle
    $file = Get-Item -LiteralPath $bundle -Force
    if ($Offset -ge [Int64]$file.Length) { throw 'bundle offset is beyond the file' }
    $requested = [Math]::Min($Count, [int]([Int64]$file.Length - $Offset))
    $bytes = New-Object byte[] $requested
    $stream = [IO.File]::Open($bundle, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [void]$stream.Seek($Offset, [IO.SeekOrigin]::Begin)
        $read = $stream.Read($bytes, 0, $requested)
    } finally {
        $stream.Dispose()
    }
    if ($read -lt 1 -or $read -gt $requested) { throw 'bounded bundle read returned an invalid size' }
    return [ordered]@{
        schema = 'franck.youtube-global-pool.windows-bundle-chunk.v1'
        chunkId = $ChunkId
        leaseId = $LeaseId
        offset = $Offset
        count = $read
        data = [Convert]::ToBase64String($bytes, 0, $read)
        cookiesUsed = $false
        mediaFiles = 0
    }
}

switch ($Action) {
    'Validate' { Write-Result (Invoke-Validation); break }
    'Probe' { Write-Result (Invoke-Probe); break }
    'StageLaunch' { Write-Result (Invoke-StageLaunch); break }
    'Resume' { Write-Result (Invoke-Resume); break }
    'Package' { Write-Result (Invoke-Package); break }
    'BundleInfo' { Write-Result (Invoke-BundleInfo); break }
    'ReadChunk' { Write-Result (Invoke-ReadChunk); break }
}
