param(
  [Parameter(Mandatory)]
  [string] $ExpectedSid,
  [Parameter(Mandatory)]
  [string] $FixtureName,
  [Parameter(Mandatory)]
  [string] $NodeExe,
  [Parameter(Mandatory)]
  [string] $SourceSha
)

$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
  $principal = [Security.Principal.WindowsPrincipal]::new($id)
  $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  if ($id.User.Value -cne $ExpectedSid -or $id.Groups.Contains($admins) -or
      !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::User)) {
    throw 'The installed package smoke must run as the new standard account.'
  }
} finally {
  $id.Dispose()
}

$ownerProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
if ([string]::IsNullOrWhiteSpace($ownerProfile)) { throw 'The standard-account profile is unavailable.' }
$fixture = Join-Path $ownerProfile $FixtureName
New-Item -ItemType Directory -Path $fixture | Out-Null
$archive = Join-Path $PSScriptRoot 'openclaw-pqc.tgz'
$npm = Join-Path (Split-Path -Parent $NodeExe) 'npm.cmd'
& $npm install --prefix $fixture --registry=https://registry.npmjs.org --no-fund $archive
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$env:PQC_SOURCE_SHA = $SourceSha
& $NodeExe (Join-Path $PSScriptRoot 'pqc-windows-installed-identity.mjs') $fixture $archive --node-host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output 'INSTALLED_PACKAGE_LIFECYCLE_AS_STANDARD_OWNER=PASS'
