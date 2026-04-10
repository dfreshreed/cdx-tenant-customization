<#
  .SYNOPSIS
  Automates CDX demo tenant customization: users, rooms, groups, licensing, & CA policy

  .PARAMETER ResetTenant
  Delete all CDX auto-generated users/rooms before creating custom ones

  .PARAMETER SkipUsers
  Skip custom user creation

  .PARAMETER UpdateExistingUsers
  Update fields on existing users

  .PARAMETER SkipRooms
  Skip custom room creation

  .PARAMETER SkipGroups
  Skip custom group creation/user association with groups

  .PARAMETER SkipLicensing
  Skip assigning user and room licensing

  .PARAMETER SkipAosp
  Skip AOSP enrollment

  .EXAMPLE
  pwsh ./user-room-creation.ps1 -ResetTenant
#>

param(
  [switch]$ResetTenant, # delete all cdx users (except modAdmin)
  [switch]$UpdateExistingUsers, # update props for existing @Users
  [switch]$SkipUsers, # skip custom user creation
  [switch]$SkipRooms, # skip room creation/config
  [switch]$SkipGroups, # skip group creation + CA policy
  [switch]$SkipLicensing, # skip licensing
  [switch]$SkipAosp # skip AOSP profile creation
)

if ($ResetTenant -and $UpdateExistingUsers) {
  throw "Can't use -ResetTenant and -UpdateExistingUsers together"
}

# -- config
$Domain = "M365x12953264.onmicrosoft.com"

$DefaultPassword = "PolyDemo12!" # fixed pw for all demo users/rooms
$DefaultRoomPassword = $DefaultPassword # different pw for rooms. ex: $DefaultRoomPassword = "wutEvrUw@nt"
$RoomPassword = ConvertTo-SecureString -String $DefaultRoomPassword -AsPlainText -Force

<#
  optional folder for user photos (png/jpg/jpeg).
  expects filename like: <alias>.png or <alias>.jpg (i.e., rey.png, chewie.jpg)
  set $PhotoFolder = "" to skip photos.
#>
$PhotoFolder = "photos"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PhotoFolderPath = if ($PhotoFolder) { Join-Path $ScriptDir $PhotoFolder } else { "" }

<#
  leave as is or change to whatever you want...we're cool unless you replace with star trek characters (just kidding you, i am)

  for User creation:
    - First, Last, and Alias » REQUIRED
    - AccountEnabled defaults to "true" (if removed from User object)
    - JobTitle, Department, and OfficeLocation » OPTIONAL

  Example min structure for each user:
    @{ First = "admiral"; Last = "ackbar"; Alias = "ackbar" }
#>
$Rooms = @(
  "Endor101", "Endor201", "Endor301", "Bespin101", "Bespin201", "Bespin301",
  "Hoth101", "Hoth201", "Hoth301", "Dagobah101", "Dagobah201", "Dagobah301",
  "bobaMtroW"
)

$Users = @(
  @{
    First          = "admiral"
    Last           = "ackbar"
    Alias          = "ackbar"
    JobTitle       = "fleet commander"
    Department     = "fleet command"
    OfficeLocation = "star cruiser command"
    AccountEnabled = $true
  },
  @{
    First          = "boba"
    Last           = "fett"
    Alias          = "boba"
    JobTitle       = "daimyo"
    Department     = "mos espa operations"
    OfficeLocation = "jabba's palace"
    AccountEnabled = $true
  },
  @{
    First          = "c"
    Last           = "3pO"
    Alias          = "c3pO"
    JobTitle       = "protocol droid"
    Department     = "diplomatic services"
    OfficeLocation = "ak outpost"
    AccountEnabled = $true
  },
  @{
    First          = "chew"
    Last           = "bacca"
    Alias          = "chewie"
    JobTitle       = "co pilot"
    Department     = "transport services"
    OfficeLocation = "millennium falcon"
    AccountEnabled = $true
  },
  @{
    First          = "han"
    Last           = "solo"
    Alias          = "han"
    JobTitle       = "general"
    Department     = "fleet support"
    OfficeLocation = "millennium falcon"
    AccountEnabled = $true
  },
  @{
    First          = "jango"
    Last           = "fett"
    Alias          = "jango"
    JobTitle       = "bounty hunter"
    Department     = "contract operations"
    OfficeLocation = "tc complex"
    AccountEnabled = $true
  },
  @{
    First          = "lando"
    Last           = "calrissian"
    Alias          = "lando"
    JobTitle       = "general"
    Department     = "fleet coordination"
    OfficeLocation = "cloud city"
    AccountEnabled = $true
  },
  @{
    First          = "leia"
    Last           = "organo"
    Alias          = "leia"
    JobTitle       = "general"
    Department     = "resistance command"
    OfficeLocation = "ak outpost"
    AccountEnabled = $true
  },
  @{
    First          = "luke"
    Last           = "skywalker"
    Alias          = "luke"
    JobTitle       = "jedi master"
    Department     = "jedi order"
    OfficeLocation = "temple island"
    AccountEnabled = $true
  },
  @{
    First          = "obiwan"
    Last           = "kenobi"
    Alias          = "obiwan"
    JobTitle       = "jedi master"
    Department     = "jedi council"
    OfficeLocation = "galatic city"
    AccountEnabled = $true
  },
  @{
    First          = "poe"
    Last           = "dameron"
    Alias          = "poe"
    JobTitle       = "commander"
    Department     = "fleet operations"
    OfficeLocation = "ak outpost"
    AccountEnabled = $true
  },
  @{
    First          = "rey"
    Last           = "skywalker"
    Alias          = "rey"
    JobTitle       = "jedi knight"
    Department     = "jedi restoration"
    OfficeLocation = "ak outpost"
    AccountEnabled = $true
  },
  @{
    First          = "wicket"
    Last           = "warrick"
    Alias          = "wicket"
    JobTitle       = "scout"
    Department     = "forest reconnaissance"
    OfficeLocation = "happy grove"
    AccountEnabled = $true
  },
  @{
    First          = "daniel"
    Last           = "reed"
    Alias          = "dfr"
    JobTitle       = "dev"
    Department     = "droid operations"
    Roles          = @("Global Administrator")
    OfficeLocation = "happy grove"
    AccountEnabled = $true
  }
)

$Groups = @(
  @{
    DisplayName = "Dev Ops"
    Nickname    = "dev-ops"
    Type        = "Security"      # Security = access/policy only
    MfaExclude  = $true
    Members     = @("luke", "obiwan", "rey", "dfr")
  },
  @{
    DisplayName = "Product Management"
    Nickname    = "product"
    Type        = "M365"       # M365 = collaboration (Teams, SharePoint, shared mailbox)
    MfaExclude  = $false
    Members     = @("leia", "han", "lando", "poe")
  },
  @{
    DisplayName = "Teams Shared Device Accounts MFA Excluded"
    Nickname    = "teams-shared-device-mfa-excluded"
    Type        = "Security"
    MfaExclude  = $true
    Members     = @("Endor101", "Endor201", "Endor301", "Bespin101", "Bespin201", "Bespin301",
      "Hoth101", "Hoth201", "Hoth301", "Dagobah101", "Dagobah201", "Dagobah301",
      "bobaMtroW")
  }
)

$AospProfiles = @(
  @{
    displayName          = "MTR Devices"
    description          = "All Android Teams Rooms, Phones, Panels"
    enrollmentMode       = "corporateOwnedAOSPUserAssociatedDevice"
    enrollmentTokenType  = "default"
    isTeamsDeviceProfile = $true
    configureWifi        = $false
  }
)

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

    foreach ($pattern in $SkuPartNumberPatterns) {
      $sku = Get-MgSubscribedSku -ErrorAction Stop | Where-Object { $_.SkuPartNumber -match $pattern } | Select-Object -First 1

      if (-not $sku) {
        Write-Warning "No $LicenseType license found matching » $pattern"
        return
      }
      $available = [int]$sku.PrepaidUnits.Enabled - [int]$sku.ConsumedUnits
      if ($available -lt $minAvail) { $minAvail = $available }

      $skusToAssign += $sku
      $qty += "$($sku.SkuPartNumber): $available available"
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
          Write-Host "`n  $upn...» Already Licensed" -ForegroundColor DarkGray
          $alreadyLicensedCount++
          continue
        }

        if ($licensedCount -ge $minAvail) {
          $skippedUsers += $upn
          continue
        }

        Write-Host "`n  $upn...✅"
        $licensesToAdd = $skusToAssign | ForEach-Object { @{ SkuId = $_.SkuId } }
        Set-MgUserLicense -UserId $upn -AddLicenses $licensesToAdd -RemoveLicenses @() -ErrorAction Stop | Out-Null
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
    Write-Host "`n $licensedCount new licenses" -ForegroundColor Yellow

    if ($skippedUsers.Count -gt 0) {
      Write-Warning "Not enough licenses for all $($LicenseType)s. Unlicensed:"
      $skippedUsers | ForEach-Object { Write-Host "  - $($_)" }
    }
  }
  catch {
    Write-Warning "$LicenseType licensing failed » $($_.Exception.Message)"
  }
}
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
      Set-MgUserPhotoContent -UserId $upn -InFile $photoPath -ErrorAction Stop | Out-Null
    }
    catch {
      Write-Warning "Photo upload failed for $Alias » $($_.Exception.Message)"
    }
  }
  else {
    Write-Host "`n  No photo found for $Alias → expected $Alias.png/.jpg/.jpeg" -ForegroundColor Red
  }
}

foreach ($u in $Users) {
  try {
    Get-ValidatedAlias -Value $u.Alias -Label "User alias" | Out-Null
  }
  catch {
    throw "Invalid user entry '$($u.First) $($u.Last)' : $($_.Exception.Message) "
  }
}
foreach ($r in $Rooms) {
  try {
    Get-ValidatedAlias -Value $r -Label "Room name/alias" | Out-Null
  }
  catch {
    throw "Invalid room entry '$r' : $($_.Exception.Message) "
  }
}

# -- required modules
Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
Write-Host "CHECKING REQUIRED POWERSHELL MODULES" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor DarkGray

$requiredModules = @(
  @{ Name = "Microsoft.Graph.Users"; MinVersion = "2.0.0" },
  @{ Name = "Microsoft.Graph.Identity.DirectoryManagement"; MinVersion = "2.0.0" },
  @{ Name = "ExchangeOnlineManagement"; MinVersion = "3.0.0" },
  @{ Name = "Microsoft.Graph.Identity.Governance"; MinVersion = "2.0.0" },
  @{ Name = "Microsoft.Graph.Groups"; MinVersion = "2.0.0" },
  @{ Name = "Microsoft.Graph.Identity.SignIns"; MinVersion = "2.0.0" }
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
      Write-Error "Failed to install $($module.Name): $($_.Exception.Message)"
      Write-Host "`nPlease install manually: Install-Module $($module.Name) -Scope CurrentUser"
      exit 1
    }
  }
  else {
    Write-Host "  $($module.Name)...✅"
  }
}
Write-Host ""

# -- modules/connections
Import-Module Microsoft.Graph.Users -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
Import-Module Microsoft.Graph.Groups -ErrorAction Stop
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# -- connect graph
try {
  $graphScopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Organization.Read.All",
    "RoleManagement.ReadWrite.Directory",
    "Directory.AccessAsUser.All",
    "Group.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "DeviceManagementConfiguration.ReadWrite.All"
  )
  Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop | Out-Null
}
catch {
  throw "Graph connection failed with error: $($_.Exception.Message)"
}

# -- connect EXO
try {
  Connect-ExchangeOnline -ErrorAction Stop | Out-Null
}
catch {
  throw "Exchange connection failed with error: $($_.Exception.Message)"
}

# -- delete default users & conf rooms
if ($ResetTenant) {
  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  Write-Host "-ResetTenant ENABLED" -ForegroundColor Yellow
  Write-Host ("=" * 60) -ForegroundColor DarkGray

  $prevDeleted = Get-MgDirectoryDeletedItemAsUser -All -ErrorAction SilentlyContinue
  if ($prevDeleted) {
    $cnfDeleted = $prevDeleted | Where-Object { $_.UserPrincipalName -match 'ACNF:' }
    $legitDeleted = $prevDeleted | Where-Object { $_.UserPrincipalName -notmatch 'ACNF:' }

    if ($legitDeleted) {
      Write-Host "  Restoring $($legitDeleted.Count) soft-deleted user(s) to avoid CNF conflict state"
      foreach ($u in $legitDeleted) {
        try {
          Restore-MgDirectoryDeletedItem -DirectoryObjectId $u.id -ErrorAction Stop
        }
        catch {
          Write-Warning "Failed to restore $($u.UserPrincipalName)"
        }
      }
    }
    if ($cnfDeleted) {
      Write-Host " Wiping $($cnfDeleted.Count) CNF conflict object(s) - AKA mangled/broken dups - from deleted items" -ForegroundColor DarkYellow
      foreach ($u in $cnfDeleted) {
        Remove-MgDirectoryDeletedItem -DirectoryObjectId $u.id -Confirm:$false -ErrorAction SilentlyContinue
      }
    }
    Start-Sleep -Seconds 15
  }
  $defaultRoomBox = @()
  # delete conf room mailboxes and EXO fallback
  try {
    $defaultRoomBox = Get-EXOMailbox -RecipientTypeDetails RoomMailbox -ResultSize Unlimited -ErrorAction Stop
  }
  catch {
    Write-Warning "Couldn't delete room mailbox » $($_.Exception.Message)"
  }

  # give exchange small buffer
  Start-Sleep -Seconds 5

  Write-Host "DELETING ROOM MAILBOXES » `n"
  foreach ($box in $defaultRoomBox) {
    try {
      Write-Host "  $($box.DisplayName) ($($box.UserPrincipalName))" -ForegroundColor Red
      Write-Host "                   ******      " -ForegroundColor White
      if ($box.UserPrincipalName -match "ACNF:") {
        $cnfId = $box.ExternalDirectoryObjectId
        if ($cnfId) {
          try {
            Remove-MgUser -UserId $cnfId -Confirm:$false -ErrorAction Stop
            Remove-MgDirectoryDeletedItem -DirectoryObjectId $cnfId -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "  [CNF conflict object hard-deleted via Graph]" -ForegroundColor DarkYellow
          }
          catch {
            Remove-Mailbox -Identity $box.UserPrincipalName -Confirm:$false -ErrorAction Stop
            Write-Host " [CNF orphan removed via Exchange UPN fallback]" -ForegroundColor Yellow
          }
        }
        else {
          Write-Warning "CNF object has no ExternalDirectoryObjectId, skipping: $($box.UserPrincipalName)"
        }
      }
      else {
        Remove-Mailbox -Identity $box.ExternalDirectoryObjectId -Confirm:$false -ErrorAction Stop
      }
    }
    catch {
      Write-Warning "Couldn't remove room mailbox $($box.UserPrincipalName) » $($_.Exception.Message)"
    }
  }

  # give exchange small buffer
  Start-Sleep -Seconds 5

  $protectedUsers = New-Object System.Collections.Generic.HashSet[string]

  # protect mod admin account
  $modAdmin = Get-MgUser -UserId "admin@$Domain" -ErrorAction SilentlyContinue
  if ($modAdmin) { [void]$protectedUsers.Add($modAdmin.Id) }
  else { Write-Warning "Default admin account not found » admin@$Domain" }

  $allUsers = Get-MgUser -All -Property "id,displayName,userPrincipalName" -ErrorAction Stop | Select-Object Id, DisplayName, UserPrincipalName
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

  Write-Host "DELETING USERS » `n"
  foreach ($user in $toDelete) {
    try {
      Write-Host "   $($user.UserPrincipalName)...🗑"  -ForegroundColor Red
      Write-Host "               ******      " -ForegroundColor White
      Remove-MgUser -UserId $user.Id -ErrorAction stop | Out-Null
    }
    catch {
      Write-Warning "Deleting user $($user.UserPrincipalName) failed » $($_.Exception.Message)"
    }
  }
  # dir buffer post users wipe
  Write-Host "`n ...letting M365 services sync..." -ForegroundColor Magenta
  Start-Sleep -Seconds 10
}

# -- create or update users
$createdUsers = @()
$updatedUsers = @()
if (-not $SkipUsers) {
  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  if ($UpdateExistingUsers) {
    Write-Host "UPDATING USER ACCOUNTS" -ForegroundColor Yellow
  }
  else {
    Write-Host "CREATING USER ACCOUNTS" -ForegroundColor Yellow
  }
  Write-Host ("=" * 60) -ForegroundColor DarkGray
  Write-Host ""

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
          Write-Warning "User already exists, skipping » $upn"
          continue
        }

        # remove fields that can't be updated
        $updateParams = $userParams.Clone()
        $updateParams.Remove('userPrincipalName')
        $updateParams.Remove('mailNickname')

        Update-MgUser -UserId $existing.Id -BodyParameter $updateParams -ErrorAction Stop | Out-Null
        $updatedUsers += $u
        Write-Host "  $display ($upn)...✅"
        Write-Host "                      ******      " -ForegroundColor Yellow
      }
      else {
        New-MgUser @userParams -ErrorAction Stop | Out-Null
        $createdUsers += $u
        Write-Host "  $display ($upn)...✅"
        Write-Host "                      ******      " -ForegroundColor Green
      }
    }
    catch {
      Write-Error "Failed creating/updating user $upn : $($_.Exception.Message)"
    }
  }

  # -- assign user roles
  $usersNeedingRoles = $Users | Where-Object { $_.Roles -and $_.Roles.Count -gt 0 -and $createdUsers.Alias -contains $_.Alias }

  if ($usersNeedingRoles.Count -gt 0) {
    if (-not $UpdateExistingUsers) {
      Write-Host "`n...Waiting for users to sync before assigning roles..." -ForegroundColor Magenta
      Start-Sleep -Seconds 10
    }

    Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
    Write-Host "ASSIGNING USER ROLES" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor DarkGray

    foreach ($u in $usersNeedingRoles) {
      $upn = "$($u.Alias)@$Domain"
      foreach ($roleName in $u.Roles) {
        try {
          $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$roleName'" -ErrorAction Stop
          if (-not $roleDef) {
            Write-Warning "Role not found » $roleName"
            continue
          }
          $userId = (Get-MgUser -UserId $upn -ErrorAction SilentlyContinue).Id
          if (-not $userId) {
            Write-Warning "No user found for role assignment » $upn"
            continue
          }
          $userRole = @{
            principalId      = $userId
            roleDefinitionId = $roleDef.Id
            directoryScopeId = "/"
          }
          New-MgRoleManagementDirectoryRoleAssignment @userRole -ErrorAction Stop | Out-Null
          Write-Host "  $upn → $roleName...✅"
        }
        catch {
          Write-Warning "Role assignment failed for $upn ($roleName) » $($_.Exception.Message)"
        }
      }
    }
  }
}

# -- create rooms
<#
  teams rooms resource account is hybrid object:
    → entra id for user/account (identity/licensing)
    → exchange room mailbox (calendar/booking rules, resource settings)
  using Exchange Online Powershell and Microsoft Graph for Teams Rooms automation,
  until Exchange Online Admin API is GA
#>
$createdRooms = @()
if (-not $SkipRooms) {
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


    # skip if exists
    $existing = Get-Recipient -Identity $alias -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
      if ($existing.PrimarySmtpAddress -match "ACNF:") {
        Write-Warning "`n CNF conflict object blocking creation of $alias. Manual cleanup in admin portal required"
      }
      else {
        Write-Warning "`n  Room/recipient already exists, skipping » $alias"
      }
      continue
    }

    try {
      $roomParams = @{
        Room                      = $true
        Name                      = $r
        DisplayName               = $r
        Alias                     = $alias
        MicrosoftOnlineServicesID = $upn
        EnableRoomMailboxAccount  = $true
        RoomMailboxPassword       = $RoomPassword
      }
      New-Mailbox @roomParams -ErrorAction Stop | Out-Null
      $createdRooms += $r
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
      Set-CalendarProcessing @calParams -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
      Write-Host "✅"
    }
    catch {
      Write-Error "`n  Failed creating room $r : $($_.Exception.Message)"
    }
  }

  # rooms sync buffer pre prop update
  Write-Host "`n ...Waiting for room accounts to sync across M365 services..." -ForegroundColor Magenta
  Start-Sleep -Seconds 15

  # -- room (user) pw policy
  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  Write-Host "SETTING ROOM POLICIES & LOCATION" -ForegroundColor Yellow
  Write-Host ("=" * 60) -ForegroundColor DarkGray

  # disable room pw expiration
  foreach ($r in $Rooms) {
    $alias = Get-ValidatedAlias -Value $r -Label "Room name/alias"
    $roomUpn = "$alias@$Domain"
    try {
      $updateParams = @{
        UserId           = $roomUpn
        UsageLocation    = "US"
        PasswordPolicies = "DisablePasswordExpiration"
      }
      Update-MgUser @updateParams -ErrorAction Stop | Out-Null
      Write-Host "`n  $roomUpn...✅"
    }
    catch {
      Write-Warning "Room update failed for $roomUpn » $($_.Exception.Message)"

      # if error occurs, retry individually to pinpoint the failure
      try {
        Update-MgUser -UserId $roomUpn -UsageLocation "US" -ErrorAction Stop | Out-Null
      }
      catch {
        Write-Warning "  UsageLocation failed for $roomUpn » $($_.Exception.Message)"
      }

      try {
        Update-MgUser -UserId $roomUpn -PasswordPolicies "DisablePasswordExpiration" -ErrorAction Stop | Out-Null
      }
      catch {
        Write-Warning "  PasswordPolicies failed for $roomUpn » $($_.Exception.Message)"
      }
    }
  }
}

# -- create groups/assign users
$createdGroups = @()
if (-not $SkipGroups) {
  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  Write-Host "CREATING GROUPS & ADDING USERS" -ForegroundColor Yellow
  Write-Host ("=" * 60) -ForegroundColor DarkGray

  $mfaExcludeGroup = @()

  foreach ($g in $Groups) {
    $ism365 = $g.Type -eq "M365"

    $groupParams = @{
      displayName     = $g.DisplayName
      mailNickname    = $g.Nickname
      securityEnabled = $true
      mailEnabled     = $ism365
      groupTypes      = if ($ism365) { @("Unified") } else { @() }
    }

    try {
      $existing = Get-MgGroup -Filter "mailNickname eq '$($g.Nickname)'" -ErrorAction SilentlyContinue
      if ($existing) {
        $group = $existing
      }
      else {
        $group = New-MgGroup @groupParams -ErrorAction Stop
        $createdGroups += $g
      }
      if ($g.MfaExclude) { $mfaExcludeGroup += $group }

      foreach ($alias in $g.Members) {
        try {
          $userId = (Get-MgUser -UserId "$alias@$Domain" -ErrorAction SilentlyContinue)?.Id
          if (-not $userId) {
            Write-Warning "User not found » $alias"
            continue
          }

          $alreadyMember = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $userId }

          if (-not $alreadyMember) {
            New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $userId -ErrorAction Stop | Out-Null
            Write-Host "  Added $alias to $($g.DisplayName)...✅"
          }
        }
        catch {
          Write-Warning "  Failed to add member '$alias' to '$($g.DisplayName)' » $($_.Exception.Message)"
        }
      }
    }
    catch {
      Write-Warning "Failed to create group '$($g.DisplayName)' » $($_.Exception.Message)"
      continue
    }
  }

  # -- assign groups mfa policy
  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  Write-Host "ADDING GROUPS TO MFA EXCLUDE POLICY" -ForegroundColor Yellow
  Write-Host ("=" * 60) -ForegroundColor DarkGray

  try {
    $mfaPolicy = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.DisplayName -like "*Multifactor authentication*partners*vendors*" }

    if ($mfaPolicy) {
      $currentExclusions = @($mfaPolicy.Conditions.Users.ExcludeGroups)
      $groupIdsToAdd = $mfaExcludeGroup.Id | Where-Object { $currentExclusions -notcontains $_ }

      if ($groupIdsToAdd.Count -gt 0) {
        $updatedExclusions = $currentExclusions + $groupIdsToAdd
        $params = @{
          conditions = @{
            users = @{excludeGroups = $updatedExclusions }
          }
          state      = "enabled"
        }
        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $mfaPolicy.Id -BodyParameter $params -ErrorAction Stop | Out-Null
        Write-Host "  Updated existing MFA policy with exclusion group $($mfaExcludeGroup.DisplayName -join ',')...✅"
      }
      else {
        Write-Host "  Group already excluded from MFA policy...skipping" -ForegroundColor DarkGray
      }
    }
    else {
      Write-Warning "CDX MFA policy not found - creating new policy"
      $newPolicy = @{
        displayName   = "Require MFA - All Users"
        state         = "enabled"
        conditions    = @{
          applications = @{includeApplications = @("All") }
          users        = @{
            includeUsers  = @("All")
            excludeGroups = @($mfaExcludeGroup.Id)
          }
        }
        grantControls = @{
          operator        = "OR"
          builtInControls = @("mfa")
        }
      }
      New-MgIdentityConditionalAccessPolicy -BodyParameter $newPolicy -ErrorAction Stop | Out-Null
      Write-Host "  Created new MFA policy with exclusion group"
    }
  }
  catch {
    Write-Warning "MFA policy update failed » $($_.Exception.Message)"
  }
}

# -- license users with E5 + Teams
if (-not $SkipLicensing) {
  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  Write-Host "ASSIGNING USER LICENSES" -ForegroundColor Yellow
  Write-Host ("=" * 60) -ForegroundColor DarkGray
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
}

if ($UpdateExistingUsers) {
  Write-Host "`n✅ User updates complete!`n" -ForegroundColor Green
  Disconnect-ExchangeOnline -Confirm:$false | Out-Null
  Disconnect-MgGraph | Out-Null
  return
}

if (-not $SkipUsers -and -not $SkipRooms) {
  # lil buffer to let users sync before updating user properties
  Write-Host "`n ...Waiting for users to sync across M365 services..." -ForegroundColor Magenta
  Start-Sleep -Seconds 15
}

# -- upload user/room photos
if (-not $SkipUsers -or -not $SkipRooms) {
  if (-not [string]::IsNullOrWhiteSpace($PhotoFolderPath) -and (Test-Path $PhotoFolderPath)) {
    Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
    Write-Host "UPLOADING USER PHOTOS" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor DarkGray

    if (-not $SkipUsers) {
      foreach ($u in $Users) {
        $alias = Get-ValidatedAlias -Value $u.Alias -Label "User alias"
        Set-AccountPhoto -Alias $alias -Domain $Domain -PhotoFolderPath $PhotoFolderPath
      }
    }

    if (-not $SkipRooms) {
      foreach ($r in $Rooms) {
        $alias = Get-ValidatedAlias -Value $r -Label "Room alias"
        Set-AccountPhoto -Alias $alias -Domain $Domain -PhotoFolderPath $PhotoFolderPath
      }
    }
  }
  else {
    Write-Host "`nSkipping photo uploads → no photo folder configured or folder not found"
  }
}

# -- license rooms w/ Teams Rooms Pro
if (-not $SkipLicensing -and -not $SkipRooms) {
  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  Write-Host "ASSIGNING ROOM LICENSES" -ForegroundColor Yellow
  Write-Host ("=" * 60) -ForegroundColor DarkGray

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
}

# -- create AOSP profile
if (-not $SkipAosp) {
  Write-Host ("`n" + "=" * 60) -ForegroundColor DarkGray
  Write-Host "CREATING AOSP PROFILE" -ForegroundColor Yellow
  Write-Host ("=" * 60) -ForegroundColor DarkGray

  foreach ($p in $AospProfiles) {
    try {
      $response = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles" `
        -ErrorAction Stop

      $existingByMode = $response.value | Where-Object { $_.enrollmentMode -ieq $p.enrollmentMode }

      if ($existingByMode) {
        Write-Host "`n AOSP profile already exists ('$($existingByMode.displayName)')...⏭ skipping" -ForegroundColor DarkGray
        continue
      }
      $tokenExpiration = (Get-Date).AddYears(65).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

      $body = @{
        displayName             = $p.displayName
        description             = $p.description
        isTeamsDeviceProfile    = $p.isTeamsDeviceProfile
        enrollmentTokenType     = $p.enrollmentTokenType
        tokenExpirationDateTime = $tokenExpiration
        configureWifi           = $p.configureWifi
        enrollmentMode          = $p.enrollmentMode
      }

      Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles" `
        -Body ($body | ConvertTo-Json) `
        -ContentType "application/json" `
        -ErrorAction Stop | Out-Null

      Write-Host "`n  '$($p.displayName)'...✅"
    }
    catch {
      Write-Warning "Failed to create AOSP profile '$($p.displayName)' » $($_.Exception.Message)"
      Write-Warning "API detail » $($_.ErrorDetails.Message)"
    }
  }
}

if (-not $SkipUsers -or -not $SkipRooms) {
  $allAffectedUsers = @(
    ($createdUsers | ForEach-Object { @{User = $_; Status = "Created"; Type = "User" } })
    ($updatedUsers | ForEach-Object { @{User = $_; Status = "Updated"; Type = "User" } })
    ($createdRooms | ForEach-Object { @{User = $_; Status = "Created"; Type = "Room" } })
  )
  $createdOrUpdated = $allAffectedUsers | ForEach-Object {
    $u = $_.User
    $type = $_.Type
    $status = $_.Status

    if ($type -eq "Room") {
      $alias = $u
      $upn = "$alias@$Domain"
      $mgUser = Get-MgUser -UserId $upn -Property "assignedLicenses" -ErrorAction SilentlyContinue
      [PSCustomObject]@{
        Type     = $type
        Status   = $status
        Name     = $u
        UPN      = $upn
        Password = $DefaultRoomPassword
        Licensed = ($mgUser.AssignedLicenses.Count -gt 0)
      }
    }
    else {
      $upn = "$($u.Alias)@$Domain"
      $mgUser = Get-MgUser -UserId $upn -Property "assignedLicenses" -ErrorAction SilentlyContinue
      [PSCustomObject]@{
        Type       = $type
        Status     = $status
        Name       = "$($u.First) $($u.Last)"
        UPN        = $upn
        Password   = $DefaultPassword
        Roles      = if ($u.Roles) { $u.Roles -join ", " } else { "-" }
        Title      = $u.JobTitle
        Department = $u.Department
        Licensed   = ($mgUser.AssignedLicenses.Count -gt 0)
      }
    }
  }
}

# -- disconnect modules/connections
Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Disconnect-MgGraph | Out-Null

$summary = @()
if (-not $SkipUsers) { $summary += "  • $($createdUsers.Count) users" }
if (-not $SkipRooms) { $summary += "  • $($createdRooms.Count) rooms" }
if (-not $SkipGroups) { $summary += "  • $($createdGroups.Count) groups" }
if (-not $SkipLicensing) { $summary += "  • Licensing applied" }

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor DarkGray
Write-Host "✅ Custom CDX Demo tenant setup complete!"
Write-Host ("=" * 60) -ForegroundColor DarkGray
if ($summary) { $summary | ForEach-Object { Write-Host $_ } }

if ($createdOrUpdated.Count -gt 0) {
  Write-Host "`nUSERS" -ForegroundColor Yellow
  $createdOrUpdated | Format-Table -AutoSize
}
# if ($createdRooms.Count -gt 0) {
#   Write-Host "ROOMS" -ForegroundColor Yellow
#   $createdRooms | ForEach-Object {
#     [PSCustomObject]@{
#       Room     = $_
#       UPN      = "$($_.ToLower())@$Domain"
#       Password = $DefaultRoomPassword
#     }
#   } | Format-Table -AutoSize
# }

Write-Host "`n You are a GO for demo 🚀`n"
