# powerShell 7+ (cross-platform: macOS/Windows/Linux) + Microsoft.Graph + ExchangeOnlineManagement

<#
  OPTIONAL SWITCHES/FLAGS:
  `-ResetTenant` deletes all auto-generated (generic CDX) users and conf room mailboxes prior to creating users/rooms you've defined in this script. Preserves existing Admin users.

  `-UpdateExistingUsers` updates properties for existing users

  Run:
      - with reset → pwsh ./user-room-creation.ps1 -ResetTenant
      - without reset → pwsh ./user-room-creation.ps1
      - with update → pwsh ./user-room-creation.ps1 -UpdateExistingUsers
#>

param(
  [switch]$ResetTenant,
  [switch]$UpdateExistingUsers
)

# ----------- config ----------
$Domain = "M365x25843954.onmicrosoft.com"

# if you want a fixed password for all demo users and rooms set it here:
$DefaultPassword = "PolyDemo12!"
$DefaultRoomPassword = $DefaultPassword # if you want room password to differ from user password set $DefaultRoomPassword = "different-room-password"
$RoomPassword = ConvertTo-SecureString -String $DefaultRoomPassword -AsPlainText -Force

<#
  optional: folder for user photos (png/jpg/jpeg).
  photo naming convention: <alias>.png or <alias>.jpg (e.g., rey.png, chewie.jpg)
  set $PhotoFolder = "" to skip photos.
#>
$PhotoFolder = "photos"   # relative folder name
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PhotoFolderPath = if ($PhotoFolder) { Join-Path $ScriptDir $PhotoFolder } else { "" }

function Get-ValidatedAlias {
  param(
    [Parameter(Mandatory)] [string]$Value,
    [Parameter(Mandatory)] [string]$Label
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    throw "$Label is empty"
  }

  $alias = $Value.ToLower()

  if ($alias -notmatch '^[a-z0-9]+$') {
    throw "$Label '$Value' becomes '$alias' which has invalid characters. Use only letters/numbers (no spaces, hyphens, punctuation)"
  }
  return $alias
}
function Set-UserLicense {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$UserPrincipalNames,

    [Parameter(Mandatory)]
    [string[]]$SkuPartNumberPatterns,

    [Parameter(Mandatory)]
    [string]$LicenseType
  )

  try {
    $skusToAssign = @()
    $qty = @()
    $minAvail = [int]::MaxValue
    # $licensedUserCount = @()

    foreach ($pattern in $SkuPartNumberPatterns) {
      $sku = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -match $pattern } | Select-Object -First 1

      if (-not $sku) {
        Write-Warning "No $LicenseType license found matching: $pattern"
        return
      }
      $available = [int]$sku.PrepaidUnits.Enabled - [int]$sku.ConsumedUnits
      if ($available -lt $minAvail) { $minAvail = $available }

      $skusToAssign += $sku
      $qty += "$($sku.SkuPartNumber): $available available"
      # Write-Host "$($sku.SkuPartNumber): $available available"
    }

    if ($minAvail -le 0) {
      Write-Warning "`n  Not enough licenses available to license your $($LicenseType)s"
      return
    }

    Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
    Write-Host "LICENSING $($LicenseType.ToUpper())S" -ForegroundColor Yellow
    foreach ($q in $qty) {
      Write-Host "$($q)"
    }
    Write-Host ("=" * 60) -ForegroundColor DarkGray

    $licensedCount = 0
    $alreadyLicensedCount = 0
    $skippedUsers = @()

    foreach ($upn in $UserPrincipalNames) {
      try {
        $user = Get-MgUser -UserId $upn -Property "assignedLicenses" -ErrorAction Stop

        $hasAllLicenses = $true

        foreach ($sku in $skusToAssign) {
          if ($user.AssignedLicenses.SkuId -notcontains $sku.SkuId) {
            $hasAllLicenses = $false
            break
          }
        }

        if ($hasAllLicenses) {
          Write-Host "`n  $upn...⏭ Already Licensed" -ForegroundColor DarkGray
          $alreadyLicensedCount++
          continue
        }

        if ($licensedCount -ge $minAvail) {
          $skippedUsers += $upn
          continue
        }

        Write-Host "`n  $upn...✅"
        $licensesToAdd = $skusToAssign | ForEach-Object { @{ SkuId = $_.SkuId } }
        Set-MgUserLicense -UserId $upn -AddLicenses $licensesToAdd -RemoveLicenses @() | Out-Null
        $licensedCount++
      }
      catch {
        Write-Warning "`n Failed to process $upn : $($_.Exception.Message)"
      }
    }

    Write-Host ""
    if ($alreadyLicensedCount -gt 0) {
      Write-Host "Already licensed: $alreadyLicensedCount" -ForegroundColor DarkGray
    }
    Write-Host "Applied $licensedCount new licenses" -ForegroundColor Yellow

    if ($skippedUsers.Count -gt 0) {
      Write-Warning "Not enough licenses for all $($LicenseType)s. Unlicensed:"
      $skippedUsers | ForEach-Object { Write-Host "  - $($_)" }
    }
  }
  catch {
    Write-Warning "$LicenseType licensing failed: $($_.Exception.Message)"
  }
}

# ----------- user & room data ----------
<#
  leave as is or change to whatever you want...we're cool as long as you don't replace with star trek characters (just kidding you, i am)

  for User creation:
    - First, Last, and Alias are required
    - AccountEnabled will default to "true" if removed from the User object
    - JobTitle, Department, and OfficeLocation are optional

  Example minimum structure for user in $Users:
    @{ First = "admiral"; Last = "ackbar"; Alias = "ackbar" }
#>
$Rooms = @(
  "Endor101", "Endor201", "Endor301", "Bespin101", "Bespin201", "Bespin301",
  "Hoth101", "Hoth201", "Hoth301", "Dagobah101", "Dagobah201", "Dagobah301",
  "bobaMtroW"
)

$Users = @(
  @{ First = "admiral"; Last = "ackbar"; Alias = "ackbar"; JobTitle = "fleet commander"; Department = "fleet command"
    OfficeLocation = "star cruiser command"
    AccountEnabled = $true
  },
  @{ First = "boba"; Last = "fett"; Alias = "boba"; JobTitle = "daimyo"; Department = "mos espa operations"
    OfficeLocation = "jabba's palace"
    AccountEnabled = $true
  },
  @{ First = "c"; Last = "3pO"; Alias = "c3pO"; JobTitle = "protocol droid"; Department = "diplomatic services"
    OfficeLocation = "ak outpost"
    AccountEnabled = $true
  },
  @{ First = "chew"; Last = "bacca"; Alias = "chewie"; JobTitle = "co pilot"; Department = "transport services"
    OfficeLocation = "millennium falcon"
    AccountEnabled = $true
  },
  @{ First = "han"; Last = "solo"; Alias = "han"; JobTitle = "general"; Department = "fleet support"
    OfficeLocation = "millennium falcon"
    AccountEnabled = $true
  },
  @{ First = "jango"; Last = "fett"; Alias = "jango"; JobTitle = "bounty hunter"; Department = "contract operations"
    OfficeLocation = "tc complex"
    AccountEnabled = $true
  },
  @{ First = "lando"; Last = "calrissian"; Alias = "lando"; JobTitle = "general"; Department = "fleet coordination"
    OfficeLocation = "cloud city"
    AccountEnabled = $true
  },
  @{ First = "leia"; Last = "organo"; Alias = "leia"; JobTitle = "general"; Department = "resistance command"
    OfficeLocation = "ak outpost"
    AccountEnabled = $true
  },
  @{ First = "luke"; Last = "skywalker"; Alias = "luke"; JobTitle = "jedi master"; Department = "jedi order"
    OfficeLocation = "temple island"
    AccountEnabled = $true
  },
  @{ First = "obiwan"; Last = "kenobi"; Alias = "obiwan"; JobTitle = "jedi master"; Department = "jedi council"
    OfficeLocation = "galatic city"
    AccountEnabled = $true
  },
  @{ First = "poe"; Last = "dameron"; Alias = "poe"; JobTitle = "commander"; Department = "fleet operations"
    OfficeLocation = "ak outpost"
    AccountEnabled = $true
  },
  @{ First = "rey"; Last = "skywalker"; Alias = "rey"; JobTitle = "jedi knight"; Department = "jedi restoration"
    OfficeLocation = "ak outpost"
    AccountEnabled = $true
  },
  @{ First = "wicket"; Last = "warrick"; Alias = "wicket"; JobTitle = "scout"; Department = "forest reconnaissance"
    OfficeLocation = "happy grove"
    AccountEnabled = $true
  }
)

foreach ($u in $Users) {
  try {
    [void](Get-ValidatedAlias -Value $u.Alias -Label "User alias")
  }
  catch {
    throw "Invalid user entry '$($u.First) $($u.Last)' : $($_.Exception.Message) "
  }
}
foreach ($r in $Rooms) {
  try {
    [void](Get-ValidatedAlias -Value $r -Label "Room name/alias")
  }
  catch {
    throw "Invalid room entry '$r' : $($_.Exception.Message) "
  }
}

# ----------- check/install required modules ----------

Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
Write-Host "CHECKING REQUIRED POWERSHELL MODULES" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor DarkGray

$requiredModules = @(
  @{ Name = "Microsoft.Graph.Users"; MinVersion = "2.0.0" },
  @{ Name = "Microsoft.Graph.Identity.DirectoryManagement"; MinVersion = "2.0.0" },
  @{ Name = "ExchangeOnlineManagement"; MinVersion = "3.0.0" }
)

foreach ($module in $requiredModules) {
  $installed = Get-Module -ListAvailable -Name $module.Name | Where-Object { $_.Version -ge [version]$module.MinVersion }

  if (-not $installed) {
    Write-Host "  Installing $($module.Name)..." -NoNewline
    try {
      Install-Module -Name $module.Name -MinimumVersion $module.MinVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
      Write-Host " ✅"
    }
    catch {
      Write=Error "Failed to install $($module.Name): $($_.Exception.Message)"
      Write-Host "`nPlease install manually: Install-Module $($module.Name) -Scope CurrentUser"
      exit 1
    }
  }
  else {
    Write-Host "  $($module.Name)...✅"
  }
}
Write-Host ""

# ----------- modules/connections ----------
Import-Module Microsoft.Graph.Users -ErrorAction Stop
Import-Module ExchangeOnlineManagement -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

# Graph: create users + optional photos
Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Organization.Read.All", "RoleManagement.Read.Directory", "Directory.AccessAsUser.All" | Out-Null

# EXO: create room mailboxes
Connect-ExchangeOnline | Out-Null

# ----------- delete default non-admin users & conf rooms ----------
<#
  will run if `-ResetTenant` is true (passed as flag when running script)
  a room "resource account" is a normal Entra ID user object that has an Exchange mailbox type of "RoomMailbox" (and some additional exchange settings) + uses a Teams Rooms license
  Entra is directory of record and Exchange defines the "room mailbox" part

  to avoid msft soft-delete issues, we need to delete in this order:
    1. room mailboxes
    2. non-protected users (auto generated users including conf rooms)
#>

if ($ResetTenant) {

  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  Write-Host "-ResetTenant ENABLED" -ForegroundColor Yellow
  Write-Host ("=" * 60) -ForegroundColor DarkGray

  # delete conf room mailboxes + fallback in case EXO isn't avail
  try {
    $defaultRoomBox = Get-EXOMailbox -RecipientTypeDetails RoomMailbox -ResultSize Unlimited -ErrorAction Stop | Where-Object { $_.DisplayName -like "Conf Room *" }
  }
  catch {
    $defaultRoomBox = Get-Mailbox -RecipientTypeDetails RoomMailbox -ResultSize Unlimited | Where-Object { $_.DisplayName -like "Conf Room *" }
  }


  foreach ($box in $defaultRoomBox) {
    try {
      Write-Host "Removing default room mailbox: $($box.DisplayName) ($($box.UserPrincipalName))"
      Remove-Mailbox -Identity $box.UserPrincipalName -Confirm:$false -ErrorAction Stop

    }
    catch {
      Write-Warning "Couldn't remove room mailbox $($box.UserPrincipalName): $($_.Exception.Message)"
    }
  }

  # give exchange a small buffer
  Start-Sleep -Seconds 5

  # define default admin account, just in case
  $protectedUpns = @("admin@$Domain")

  # protect anyone in any directory role (admins, etc.)
  $protectedUsers = New-Object System.Collections.Generic.HashSet[string]

  $roles = Get-MgDirectoryRole -All
  foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    foreach ($mem in $members) {
      if ($mem.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.user") {
        [void]$protectedUsers.Add($mem.Id)
      }
    }
  }

  # protect default admin account
  foreach ($upn in $protectedUpns) {
    $user = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
    if ($user) { [void]$protectedUsers.Add($user.Id) }
    else { Write-Warning "Protected UPN not found: $upn" }
  }

  $allUsers = Get-MgUser -All -Property "id,displayName,userPrincipalName" | Select-Object Id, DisplayName, UserPrincipalName
  $toDelete = $allUsers | Where-Object { -not $protectedUsers.Contains($_.Id) }

  Write-Host "Total Users: $($allUsers.Count)"
  Write-Host "Protected (admins/keep): " -NoNewline
  Write-Host "$($protectedUsers.Count)" -ForegroundColor Green
  Write-Host "Will delete: " -NoNewline
  Write-Host "$($toDelete.Count)" -ForegroundColor Red
  Write-Host "`n***USERS TO DELETE***" -ForegroundColor Red
  $toDelete | Select-Object UserPrincipalName, DisplayName | Sort-Object UserPrincipalName | Format-Table -AutoSize

  Write-Host "`nUsers listed above will be deleted"
  Write-Host "Press Ctrl+C to cancel. Deletion will begin in: " -NoNewline
  for ($i = 10; $i -gt 0; $i--) {
    Write-Host "$i..." -NoNewline -ForegroundColor Yellow
    Start-Sleep -Seconds 1
  }
  Write-Host ""
  Write-Host "Starting deletion now!" -ForegroundColor Red
  Write-Host ""

  Write-Host "`nDeleting Users:"
  foreach ($user in $toDelete) {
    Write-Host "`n  $($user.UserPrincipalName)...🗑"  -ForegroundColor Red
    Write-Host "                      ******      " -ForegroundColor White
    Remove-MgUser -UserId $user.Id -ErrorAction stop
  }
  # give directory a buffer after deleting users
  Write-Host "`n ...Letting M365 services sync..." -ForegroundColor Magenta
  Start-Sleep -Seconds 10
}

# ----------- create new users ----------
Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
if ($UpdateExistingUsers) {
  Write-Host "UPDATING USER ACCOUNTS" -ForegroundColor Yellow
}
else {
  Write-Host "CREATING USER ACCOUNTS" -ForegroundColor Yellow
}
Write-Host ("=" * 60) -ForegroundColor DarkGray
Write-Host ""

# give directory a buffer
Start-Sleep -Seconds 5

foreach ($u in $Users) {

  $alias = Get-ValidatedAlias -Value $u.Alias -Label "User alias"

  $upn = "$alias@$Domain"
  $mailName = $alias

  $display = "$($u.First) $($u.Last)"
  $usageLocation = if ($u.UsageLocation) { $u.UsageLocation.ToUpper() } else { "US" }
  $accountEnabled = if ($null -ne $u.AccountEnabled) { $u.AccountEnabled } else { $true }
  $existing = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue

  $passwordProfile = @{
    Password                      = $DefaultPassword
    ForceChangePasswordNextSignIn = $false
  }

  try {
    $userParams = @{
      accountEnabled    = $accountEnabled
      givenName         = $u.First
      surname           = $u.Last
      displayName       = $display
      userPrincipalName = $upn
      mailNickname      = $mailName
      usageLocation     = $usageLocation
      passwordProfile   = $passwordProfile
    }

    # add optional fields if exists
    if ($u.JobTitle) { $userParams.jobTitle = $u.JobTitle }
    if ($u.Department) { $userParams.department = $u.Department }
    if ($u.OfficeLocation) { $userParams.officeLocation = $u.OfficeLocation }
    if ($u.CompanyName) { $userParams.companyName = $u.CompanyName }

    if ($null -ne $existing) {
      if (-not $UpdateExistingUsers) {
        Write-Warning "User already exists, skipping: $upn"
        continue
      }

      # remove fields that can't be updated
      $updateParams = $userParams.Clone()
      $updateParams.Remove('userPrincipalName')
      $updateParams.Remove('mailNickname')

      Update-MgUser -UserId $existing.Id -BodyParameter $updateParams
      Write-Host "  $display ($upn)...✅"
      Write-Host "                      ******      " -ForegroundColor Yellow
    }
    else {
      # create user
      Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
      Write-Host "CREATING USER ACCOUNTS" -ForegroundColor Yellow
      Write-Host ("=" * 60) -ForegroundColor DarkGray
      Write-Host ""

      New-MgUser @userParams | Out-Null

      Write-Host "  $display ($upn)...✅"
      Write-Host "                      ******      " -ForegroundColor Green
    }
  }
  catch {
    Write-Error "Failed creating/updating user $upn : $($_.Exception.Message)"
  }
}

if ($UpdateExistingUsers) {
  Write-Host "`n✅ User updates complete!`n" -ForegroundColor Green
  Disconnect-ExchangeOnline -Confirm:$false | Out-Null
  Disconnect-MgGraph | Out-Null
  return
}

# lil buffer to let users sync before updating user properties
Write-Host "`n ...Waiting for users to sync across M365 services..." -ForegroundColor Magenta
Start-Sleep -Seconds 15

# ----------- create rooms ----------
<#
  teams rooms resource account is hybrid object:
    → entra id for user/account (identity/licensing)
    → exchange room mailbox (calendar/booking rules, resource settings)
  have to use Exchange Online Powershell and Microsoft Graph for Teams Rooms automation,
  until Exchange Online Admin API is GA and all gaps are filled
#>
Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
Write-Host "CONFIGURING ROOM MAILBOXES AND CALENDARS" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor DarkGray

Start-Sleep -Seconds 3
foreach ($r in $Rooms) {

  $alias = Get-ValidatedAlias -Value $r -Label "Room name/alias"
  $upn = "$alias@$Domain"

  $roomNumber = [array]::IndexOf($Rooms, $r) + 1
  Write-Host "`n[$roomNumber/$($Rooms.Count)] Creating MSFT Teams Rooms → $r ($upn)"
  Write-Host "  Creating mailbox..." -NoNewline

  try {
    # skip if already exists
    $existing = Get-Recipient -Identity $alias -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
      Write-Warning "`n  Room/recipient already exists, skipping: $alias"
      continue
    }

    $roomParams = @{
      Room                      = $true
      Name                      = $r
      DisplayName               = $r
      Alias                     = $alias
      MicrosoftOnlineServicesID = $upn
      EnableRoomMailboxAccount  = $true
      RoomMailboxPassword       = $RoomPassword
    }
    New-Mailbox @roomParams | Out-Null
    Write-Host "✅"

    Write-Host "  Configuring calendar processing..." -NoNewline
    $calParams = @{
      Identity                            = $alias
      AutomateProcessing                  = "AutoAccept"
      AllowConflicts                      = $true
      AllowRecurringMeetings              = $true
      AddAdditionalResponse               = $false
      EnforceSchedulingHorizon            = $false
      BookingWindowInDays                 = 365
      ScheduleOnlyDuringWorkHours         = $false
      ConflictPercentageAllowed           = 100
      MaximumConflictInstances            = 100
      MaximumDurationInMinutes            = 1440
      ProcessExternalMeetingMessages      = $true
      AddOrganizerToSubject               = $true
      DeleteComments                      = $false
      DeleteSubject                       = $false
      RemovePrivateProperty               = $false
      RemoveForwardedMeetingNotifications = $false
    }
    Set-CalendarProcessing @calParams -WarningAction SilentlyContinue | Out-Null
    Write-Host "✅"
  }
  catch {
    Write-Error "`n  Failed creating room $r : $($_.Exception.Message)"
  }
}

# lil buffer to let rooms sync before updating room properties
Write-Host "`n ...Waiting for room accounts to sync across M365 services..." -ForegroundColor Magenta
Start-Sleep -Seconds 15

# ----------- upload user and rooms photos ----------

# upload user and rooms photos if folder is set + file exists
if (-not [string]::IsNullOrWhiteSpace($PhotoFolderPath) -and (Test-Path $PhotoFolderPath)) {
  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  Write-Host "UPLOADING USER PHOTOS" -ForegroundColor Yellow
  Write-Host ("=" * 60) -ForegroundColor DarkGray
  function Set-AccountPhoto {
    param (
      [string]$Alias,
      [string]$Domain,
      [string]$PhotoFolderPath,
      [string]$AccountType = "Account"
    )

    $upn = "$Alias@$Domain"

    $png = Join-Path $PhotoFolderPath "$Alias.png"
    $jpg = Join-Path $PhotoFolderPath "$Alias.jpg"
    $jpeg = Join-Path $PhotoFolderPath "$Alias.jpeg"

    $photoPath = $null
    if (Test-Path $png) { $photoPath = $png }
    elseif (Test-Path $jpg) { $photoPath = $jpg }
    elseif (Test-Path $jpeg) { $photoPath = $jpeg }

    if ($photoPath) {
      Write-Host "`n  $upn...✅"
      try {
        Set-MgUserPhotoContent -UserId $upn -InFile $photoPath | Out-Null
      }
      catch {
        Write-Warning "Photo upload failed for $Alias : $($_.Exception.Message)"
      }
    }
    else {
      Write-Host "`n  No photo found for $Alias → expected $Alias.png/.jpg/.jpeg)" -ForegroundColor Red
    }
  }

  foreach ($u in $Users) {
    $alias = Get-ValidatedAlias -Value $u.Alias -Label "User alias"
    Set-AccountPhoto -Alias $alias -Domain $Domain -PhotoFolderPath $PhotoFolderPath
  }
  foreach ($r in $Rooms) {
    $alias = Get-ValidatedAlias -Value $r -Label "Room alias"
    Set-AccountPhoto -Alias $alias -Domain $Domain -PhotoFolderPath $PhotoFolderPath
  }
}
else {
  Write-Host "`nSkipping photo uploads → no photo folder configured or folder not found"
}


# ----------- configure room (user) password policy ----------

# disable password expiration for room accounts

Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
Write-Host "SETTING ROOM POLICIES & LOCATION" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor DarkGray

foreach ($r in $Rooms) {
  $alias = Get-ValidatedAlias -Value $r -Label "Room name/alias"
  $roomUpn = "$alias@$Domain"
  try {
    $updateParams = @{
      UserId           = $roomUpn
      UsageLocation    = "US"
      PasswordPolicies = "DisablePasswordExpiration"
    }
    Update-MgUser @updateParams | Out-Null
    Write-Host "`n  $roomUpn...✅"
  }
  catch {
    Write-Warning "Room update failed for $roomUpn : $($_.Exception.Message)"

    # if error occurs, retry individually to pinpoint the failure
    try {
      Update-MgUser -UserId $roomUpn -UsageLocation "US" | Out-Null
    }
    catch {
      Write-Warning "  UsageLocation failed for $roomUpn : $($_.Exception.Message)"
    }

    try {
      Update-MgUser -UserId $roomUpn -PasswordPolicies "DisablePasswordExpiration" | Out-Null
    }
    catch {
      Write-Warning "  PasswordPolicies failed for $roomUpn : $($_.Exception.Message)"
    }
  }
}

Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
Write-Host "ASSIGNING USER & ROOM LICENSES" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor DarkGray

# -------license users with E5 + Teams-----
$userUpns = $Users | ForEach-Object {
  $alias = Get-ValidatedAlias -Value $_.Alias -Label "User alias"
  "$alias@$Domain"
}

$userLicenseParams = @{
  UserPrincipalNames    = $userUpns
  SkuPartNumberPatterns = @("E5.*no.*Teams", "Teams_Enterprise")
  LicenseType           = "User"
}
Set-UserLicense @userLicenseParams

# ------license rooms w/ Teams Rooms Pro------
$roomUpns = $Rooms | ForEach-Object {
  $alias = Get-ValidatedAlias -Value $_ -Label "Room alias"
  "$alias@$Domain"
}

$roomLicenseParams = @{
  UserPrincipalNames    = $roomUpns
  SkuPartNumberPatterns = @("Teams_Rooms_Pro_without")
  LicenseType           = "Room"
}
Set-UserLicense @roomLicenseParams

# ----------- disconnect modules/connections ----------
Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Disconnect-MgGraph | Out-Null

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor DarkGray
Write-Host "✅ Custom MSFT Demo tenant setup complete!"
Write-Host ("=" * 60) -ForegroundColor DarkGray
Write-Host "`nCreated & Licensed:"
Write-Host "  • $($Users.Count) users"
Write-Host "  • $($Rooms.Count) rooms"
Write-Host "`n You are a GO for demo 🚀`n"
