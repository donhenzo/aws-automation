<#
.SYNOPSIS
  Creates the AWS IAM Identity Center lab groups and users in the CURRENT Entra tenant.
  Idempotent: safe to re-run (existing groups, users and memberships are left alone).

.DESCRIPTION
  4 security groups, each mapping 1:1 to one AWS permission set (ADR-010).
  10 mock users (Henz Industries IT). Initial passwords are random and written to
  ./output/lab-credentials.csv (git-ignored). Lab use only.

.EXAMPLE
  pwsh ./scripts/New-LabIdentities.ps1 -TenantId yourtenant.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutDir = (Join-Path $PSScriptRoot '..' 'output')
)

$ErrorActionPreference = 'Stop'

# ---------- Connect (delegated, interactive) ----------
$scopes = 'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Organization.Read.All'
$ctx = Get-MgContext
$missing = if ($ctx) { $scopes | Where-Object { $ctx.Scopes -notcontains $_ } } else { $scopes }
if (-not $ctx -or $ctx.AuthType -ne 'Delegated' -or $missing) {
    $connect = @{ Scopes = $scopes; NoWelcome = $true }
    if ($TenantId) { $connect.TenantId = $TenantId }
    Connect-MgGraph @connect
    $ctx = Get-MgContext
}

# ---------- Safety check: confirm the tenant before creating anything ----------
$org    = Get-MgOrganization | Select-Object -First 1
$domain = ($org.VerifiedDomains | Where-Object IsInitial).Name
Write-Host ""
Write-Host "Tenant     : $($org.DisplayName) [$($org.Id)]"
Write-Host "Domain     : $domain"
Write-Host "Signed in  : $($ctx.Account)"
if ((Read-Host "Create the lab groups and users in THIS tenant? Type YES to continue") -ne 'YES') {
    Write-Host "Cancelled."; return
}

# ---------- Lab data ----------
$groups = @(
    @{ Name = 'AWS-IT-Admins';     PermissionSet = 'AdministratorAccess' }
    @{ Name = 'AWS-IT-PowerUsers'; PermissionSet = 'PowerUserAccess' }
    @{ Name = 'AWS-IT-Security';   PermissionSet = 'SecurityAudit' }
    @{ Name = 'AWS-IT-ReadOnly';   PermissionSet = 'ReadOnlyAccess' }
)

# Group = $null means the user starts with no AWS access
$users = @(
    # Pilot users from the Henz IT design
    @{ First = 'Henry';     Last = 'Moore';    Id = 'H007'; Title = 'Systems Administrator';  Dept = 'IT';      Group = 'AWS-IT-Admins' }
    @{ First = 'Halima';    Last = 'Hamidu';   Id = 'H008'; Title = 'IAM Engineer';           Dept = 'IT';      Group = 'AWS-IT-PowerUsers' }
    @{ First = 'Moussa';    Last = 'Olatunji'; Id = 'H011'; Title = 'Cloud Engineer';         Dept = 'IT';      Group = 'AWS-IT-PowerUsers' }
    @{ First = 'Usman';     Last = 'Brown';    Id = 'H014'; Title = 'Security Analyst';       Dept = 'IT';      Group = 'AWS-IT-Security' }
    @{ First = 'Yemi';      Last = 'Toure';    Id = 'H019'; Title = 'DevOps Engineer';        Dept = 'IT';      Group = 'AWS-IT-PowerUsers' }
    @{ First = 'Oluwadare'; Last = 'Osei';     Id = 'H006'; Title = 'IT Support Specialist';  Dept = 'IT';      Group = 'AWS-IT-ReadOnly' }
    # Extras for the automation tests
    @{ First = 'Amara';     Last = 'Nwosu';    Id = 'H201'; Title = 'Junior Cloud Engineer';  Dept = 'IT';      Group = 'AWS-IT-ReadOnly' }    # mover test: ReadOnly -> PowerUsers
    @{ First = 'Tunde';     Last = 'Bello';    Id = 'H202'; Title = 'Cloud Engineer';         Dept = 'IT';      Group = $null }                 # joiner test: added to a group later
    @{ First = 'Ngozi';     Last = 'Adeyemi';  Id = 'H203'; Title = 'Contract DevOps';        Dept = 'IT';      Group = 'AWS-IT-PowerUsers' }   # leaver test: disable and confirm removal
    @{ First = 'Kwame';     Last = 'Mensah';   Id = 'H204'; Title = 'Finance Analyst';        Dept = 'Finance'; Group = $null }                 # control: must never reach AWS
)

# ---------- Helpers ----------
function New-LabPassword {
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; $lower = 'abcdefghijkmnopqrstuvwxyz'
    $digit = '23456789';                 $sym   = '!#$%*+-=?@'
    $all   = $upper + $lower + $digit + $sym
    $pick  = { param($s) $s[(Get-Random -Maximum $s.Length)] }
    $pw = @((& $pick $upper), (& $pick $lower), (& $pick $digit), (& $pick $sym)) + (1..16 | ForEach-Object { & $pick $all })
    -join ($pw | Get-Random -Count $pw.Count)
}

function Invoke-WithRetry {
    param([scriptblock]$Action, [int]$Tries = 5)
    for ($i = 1; $i -le $Tries; $i++) {
        try { & $Action; return }
        catch { if ($i -eq $Tries) { throw }; Start-Sleep -Seconds 4 }   # new objects can take a few seconds to replicate
    }
}

# ---------- Groups ----------
$groupId = @{}
foreach ($g in $groups) {
    $existing = Get-MgGroup -Filter "displayName eq '$($g.Name)'" | Select-Object -First 1
    if ($existing) {
        Write-Host "Group exists   : $($g.Name)"
    } else {
        $existing = New-MgGroup -DisplayName $g.Name -MailNickname $g.Name -MailEnabled:$false -SecurityEnabled:$true `
            -Description "Maps 1:1 to AWS permission set $($g.PermissionSet)"
        Write-Host "Group created  : $($g.Name)"
    }
    $groupId[$g.Name] = $existing.Id
}

# ---------- Users ----------
$newCreds = @()
$userId   = @{}
foreach ($u in $users) {
    $upn      = ('{0}.{1}@{2}' -f $u.First, $u.Last, $domain).ToLower()
    $nickname = ('{0}.{1}' -f $u.First, $u.Last).ToLower()
    $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" | Select-Object -First 1
    if ($existing) {
        Write-Host "User exists    : $upn"
    } else {
        $pw = New-LabPassword
        $existing = New-MgUser -AccountEnabled:$true -DisplayName "$($u.First) $($u.Last)" `
            -GivenName $u.First -Surname $u.Last -UserPrincipalName $upn -MailNickname $nickname `
            -JobTitle $u.Title -Department $u.Dept -EmployeeId $u.Id -UsageLocation 'NG' `
            -PasswordProfile @{ Password = $pw; ForceChangePasswordNextSignIn = $false }   # lab only
        $newCreds += [pscustomobject]@{ UserPrincipalName = $upn; InitialPassword = $pw }
        Write-Host "User created   : $upn"
    }
    $userId[$upn] = $existing.Id
    $u.Upn = $upn
}

# ---------- Memberships ----------
$members = @{}
foreach ($name in $groupId.Keys) {
    $members[$name] = @(Get-MgGroupMember -GroupId $groupId[$name] -All | ForEach-Object { $_.Id })
}
foreach ($u in $users) {
    if (-not $u.Group) { continue }
    $uid = $userId[$u.Upn]; $gid = $groupId[$u.Group]
    if ($members[$u.Group] -contains $uid) { continue }
    Invoke-WithRetry -Action {
        New-MgGroupMemberByRef -GroupId $gid -OdataId "https://graph.microsoft.com/v1.0/directoryObjects/$uid"
    }
    Write-Host "Added          : $($u.Upn) -> $($u.Group)"
}

# ---------- Credentials file (git-ignored) ----------
if ($newCreds.Count -gt 0) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    $credPath = Join-Path $OutDir 'lab-credentials.csv'
    $newCreds | Export-Csv -Path $credPath -Append -NoTypeInformation
    if (-not $IsWindows) { & chmod 600 $credPath }
    $gi = Join-Path $PSScriptRoot '..' '.gitignore'
    if (-not (Test-Path $gi) -or -not (Select-String -Path $gi -Pattern '^output/?$' -Quiet)) { Add-Content -Path $gi -Value 'output/' }
    Write-Host "`nInitial passwords written to $credPath (git-ignored)."
}

# ---------- Summary ----------
Write-Host "`n=== Summary ==="
foreach ($g in $groups) {
    $m = Get-MgGroupMember -GroupId $groupId[$g.Name] -All
    Write-Host ("{0,-20} -> {1,-20} {2} member(s)" -f $g.Name, $g.PermissionSet, @($m).Count)
}
Write-Host "Users with no group (joiner / control): $(@($users | Where-Object { -not $_.Group }).Count)"