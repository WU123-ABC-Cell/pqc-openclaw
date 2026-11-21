#Requires -RunAsAdministrator
param(
  [Parameter(Mandatory)]
  [string] $Archive
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
  throw 'The temporary account check requires a GitHub-hosted runner.'
}

Write-Output "WINDOWS_JOB_OS_ARCHITECTURE=$env:RUNNER_ARCH"

$suffix = [Guid]::NewGuid().ToString('N')
$fixtureName = "pqc-windows-install-$suffix"
$stage = Join-Path $env:ProgramData "pqc-ci-owner-$suffix"
$password = ConvertTo-SecureString -String (
  'Aa1!' + [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
) -AsPlainText -Force
$owner = $null
try {
  $owner = New-LocalUser -Name ('pqc_own_' + $suffix.Substring(0, 12)) -Password $password -Description 'Temporary PQC CI package owner'
  $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
  if ($owner.SID -notin (Get-LocalGroupMember -SID $users).SID) {
    Add-LocalGroupMember -SID $users -Member $owner
  }

  New-Item -ItemType Directory -Path $stage | Out-Null
  $stageAcl = Get-Acl -LiteralPath $stage
  $stageAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $owner.SID, 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
  ))
  Set-Acl -LiteralPath $stage -AclObject $stageAcl
  $stagedArchive = Join-Path $stage 'openclaw-pqc.tgz'
  Copy-Item -LiteralPath $Archive -Destination $stagedArchive
  if ((Get-FileHash -LiteralPath $stagedArchive).Hash -ne (Get-FileHash -LiteralPath $Archive).Hash) {
    throw 'The standard-account staging copy differs from the verified archive.'
  }
  $child = 'pqc-windows-standard-owner-smoke.ps1'
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot $child) -Destination $stage
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'pqc-windows-installed-identity.mjs') -Destination $stage

  # With no explicit environment block, Windows supplies the new account's profile environment.
  $start = [Diagnostics.ProcessStartInfo]::new()
  $start.FileName = Join-Path $PSHOME 'pwsh.exe'
  $start.WorkingDirectory = $stage
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.UserName = $owner.Name
  $start.Domain = '.'
  $start.Password = $password
  $start.LoadUserProfile = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  foreach ($arg in @(
    '-NoProfile', '-NonInteractive', '-File', (Join-Path $stage $child),
    '-ExpectedSid', $owner.SID.Value, '-FixtureName', $fixtureName,
    '-NodeExe', (Get-Command node.exe -ErrorAction Stop).Source,
    '-SourceSha', $env:PQC_SOURCE_SHA
  )) {
    $start.ArgumentList.Add($arg)
  }

  $process = [Diagnostics.Process]::Start($start)
  try {
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (!$process.WaitForExit(1020000)) {
      $process.Kill($true)
      [void] $process.WaitForExit(10000)
      throw 'Standard-account package smoke timed out.'
    }
    Write-Output ($stdout.WaitAsync([TimeSpan]::FromSeconds(10)).GetAwaiter().GetResult().Trim())
    if ($process.ExitCode -ne 0) {
      throw ('Standard-account package smoke failed: ' + $stderr.WaitAsync([TimeSpan]::FromSeconds(10)).GetAwaiter().GetResult().Trim())
    }
  } finally {
    $process.Dispose()
  }

  $profileEntry = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $owner.SID.Value
  $ownerProfile = Get-ItemPropertyValue -LiteralPath $profileEntry -Name ProfileImagePath
  $fixture = Join-Path $ownerProfile $fixtureName
  $smoke = @(Get-ChildItem -LiteralPath $fixture -Directory -Filter 'identity-smoke-*')
  if ($smoke.Count -ne 1) { throw 'Expected a single product state fixture.' }
  $key = Join-Path $smoke[0].FullName 'state\wrap-key.b64'
  $keyOwner = (Get-Acl -LiteralPath $key).GetOwner([Security.Principal.SecurityIdentifier])
  if ($keyOwner -ne $owner.SID) { throw 'Expected the standard account to own the wrapping key.' }

  $hash = (Get-FileHash -LiteralPath $key).Hash
  & (Join-Path $PSScriptRoot 'pqc-windows-check-account-isolation.ps1') -WrapKey $key
  if ((Get-FileHash -LiteralPath $key).Hash -ne $hash) {
    throw 'The wrapping key changed during the cross-account access check.'
  }
} finally {
  try {
    if ($null -ne $owner) {
      Remove-LocalUser -SID $owner.SID
    }
  } finally {
    $password.Dispose()
  }
}
Write-Output 'INSTALLED_STANDARD_OWNER_AND_DISTINCT_STANDARD_READER_ISOLATION=PASS'
