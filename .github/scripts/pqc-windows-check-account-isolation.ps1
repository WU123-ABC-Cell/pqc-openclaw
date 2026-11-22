#Requires -RunAsAdministrator
param(
  [Parameter(Mandatory)]
  [string] $WrapKey
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
  throw 'The temporary account check requires a GitHub-hosted runner.'
}

Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public static class PqcWindowsAccountIsolation
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LogonUser(string user, string domain, string password,
        int logonType, int provider, out SafeAccessTokenHandle token);

    public static void Verify(string name, string password, string sid, string control, string key)
    {
        const int interactiveLogon = 2;
        const int defaultProvider = 0;
        const int accessDenied = unchecked((int)0x80070005);
        if (!LogonUser(name, ".", password, interactiveLogon, defaultProvider, out var token))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        using (token)
        {
            WindowsIdentity.RunImpersonated(token, () =>
            {
                using var who = WindowsIdentity.GetCurrent(true);
                var principal = new WindowsPrincipal(who);
                var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                if (who.User.Value != sid || who.Groups.Contains(administrators)
                    || !principal.IsInRole(WindowsBuiltInRole.User))
                    throw new InvalidOperationException("Expected a separate standard local account.");

                // Check the same parent path with a readable sibling before testing the key.
                using (var file = File.OpenRead(control))
                {
                    if (file.ReadByte() != 67)
                        throw new InvalidOperationException("The readable sibling did not match the fixture.");
                }

                try
                {
                    using var file = File.OpenRead(key);
                }
                catch (UnauthorizedAccessException error) when (error.HResult == accessDenied)
                {
                    return;
                }
                throw new InvalidOperationException("The standard account could open the wrapping key.");
            });
        }
    }
}
"@

$key = Get-Item -LiteralPath $WrapKey
if ($key.PSIsContainer -or $key.Name -cne 'wrap-key.b64') {
  throw 'Expected the wrapping-key file produced by the installation test.'
}

$suffix = [Guid]::NewGuid().ToString('N')
$name = 'pqc_acl_' + $suffix.Substring(0, 12)
$control = Join-Path $key.DirectoryName "acl-control-${suffix}.txt"
$secret = 'Aa1!' + [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$password = ConvertTo-SecureString -String $secret -AsPlainText -Force
$account = $null
$controlCreated = $false
try {
  $account = New-LocalUser -Name $name -Password $password -Description 'Temporary PQC CI ACL reader'
  $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
  if ($account.SID -notin (Get-LocalGroupMember -SID $users).SID) {
    Add-LocalGroupMember -SID $users -Member $account
  }

  $stream = [IO.File]::Open($control, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
  $controlCreated = $true
  try {
    $stream.WriteByte(67)
  } finally {
    $stream.Dispose()
  }
  $acl = Get-Acl -LiteralPath $control
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account.SID, 'Read', 'Allow'))
  Set-Acl -LiteralPath $control -AclObject $acl

  [PqcWindowsAccountIsolation]::Verify($account.Name, $secret, $account.SID.Value, $control, $key.FullName)
} finally {
  $password.Dispose()
  try {
    if ($controlCreated) {
      Remove-Item -LiteralPath $control
    }
  } finally {
    if ($null -ne $account) {
      Remove-LocalUser -SID $account.SID
    }
  }
}
Write-Output 'INSTALLED_STANDARD_ACCOUNT_CONTROL_READ_AND_WRAP_KEY_ACCESS_DENIED=PASS'
