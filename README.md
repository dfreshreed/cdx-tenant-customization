# CDX Demo Tenant Customization Script

Automate the setup of your Microsoft CDX demo tenant with custom users and Teams Rooms. If you like having a customized tenant, but don't have the sanity (or time) to redo it manually every 90 days, this script is for you!

## What It Does

Empowers you to customize your CDX tenant by:

- **Removing** default CDX users and rooms (optional with `-ResetTenant` flag)
- **Creating** custom-themed users and Microsoft Teams Rooms
- **Configuring** permissive room calendars for demos (auto-accept, unlimited conflicts, 24/7)
- **Personalizing** profile photos for users and rooms
- **Assigning** teams Rooms and enterprise user licenses automatically
- **Updating** user properties (optional with `-UpdateExistingUsers` flag)

## Run What You Want

| Scenario                                   | Flags                                           |
| ------------------------------------------ | ----------------------------------------------- |
| Full run with your changes, keep CDX users | no flags                                        |
| Full run with user removal first           | -ResetTenant                                    |
| Update user props only + re-run licensing  | -UpdateExistingUsers                            |
| Update user props only                     | -UpdateExistingUsers -SkipGroups -SkipLicensing |
| Re-run groups + CA policy only             | -SkipUsers -SkipRooms -SkipLicensing            |
| Re-run licensing only                      | -SkipUsers -SkipRooms -SkipGroups               |

> **💡 Pro-Tip**
>
> Licensing always targets accounts defined in `$Users` and `$Rooms`. To license different accounts, update those arrays before running.
>
> Add `-SkipAosp` to any scenario to skip AOSP enrollment profile creation

## Requirements

- **PowerShell 7+** (cross-platform: macOS/Windows/Linux)
- **Permissions:** Global Administrator in your CDX tenant
- **Modules:** Auto-installed on first run:
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Identity.DirectoryManagement`
  - `Microsoft.Graph.Identity.Governance`
  - `Microsoft.Graph.Identity.SignIns`
  - `Microsoft.Graph.Groups`
  - `ExchangeOnlineManagement`

## Quick Start

1. **Install PowerShell 7+** (if needed)
2. **Edit the script** - Update `$Domain`, `$Password`, customize `$Users/$Rooms/$Groups`, and add profile photos (optional)
3. **Run it:**

   ```powershell
   # first run (keep existing CDX accounts)
   pwsh ./user-room-creation.ps1

   # or reset tenant first (⚠️ KEEPS MOD ADMIN ONLY)
   pwsh ./user-room-creation.ps1 -ResetTenant

   # or update properties on existing users
   pwsh ./user-room-creation.ps1 -UpdateExistingUsers
   ```

---

## Configuration Options

### 1. Set Your Domain

```powershell
$Domain = "M365x12345678.onmicrosoft.com"  # change to your CDX tenant
```

### 2. Set Password

```powershell
$DefaultPassword = "YourDemoPassword123!" # used for all user and room accounts
```

To use a different password for rooms: `$DefaultRoomPassword = "differentpassword"`

### 3. Customize Users

```powershell
$Users = @(
  @{ First = "admiral"; Last = "ackbar"; Alias = "ackbar"; JobTitle = "fleet commander"; Department = "fleet command"
    OfficeLocation = "star cruiser command"
    AccountEnabled = $true },
  @{ First = "boba"; Last = "fett"; Alias = "boba"; JobTitle = "daimyo"; Department = "mos espa operations"
    OfficeLocation = "jabba's palace"
    AccountEnabled = $true }
  # add/remove/modify as needed
)
```

Creates UPN as: `alias@domain` (e.g., `ackbar@M365x12345678.onmicrosoft.com`)

### 4. Customize Rooms

```powershell
$Rooms = @(
  "Endor101", "Endor201", "Hoth101", "Hoth201"
  # add/remove/modify as needed
)
```

### 5. Customize Groups

```powershell
$Groups = @(
  @{
    DisplayName = "Dev Ops"
    Nickname    = "dev-ops"
    Type        = "Security"   # "Security" or "M365"
    MfaExclude  = $true        # adds group to MFA Conditional Access exclusion policy
    Members     = @("ackbar", "boba")
  }
)
```

- **`Type`**
  - `Security` for identity/access control/CA policy
  - `M365` for Microsoft 365 "collaboration" groups (shared mailbox, sharepoint, Teams)
- **`MfaExclude`**
  - when `$true`, the group is added to the CDX MFA Conditional Access policy exclusion list
  - use for shared device accounts or demo accounts that shouldn't be prompted for MFA
- **`Members`**
  - use the alias of users or rooms defined in `$Users` / `$Rooms`

### 6. Configure AOSP Enrollment Profile

```powershell
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
```

### 7. Add Photos (Optional)

1. Add user photos to the `photos` folder (same directory as script)
2. Image names accepted: `alias.png`, `alias.jpg`, or `alias.jpeg`
   - Example: `rey.png`, `endor101.jpg`
3. **Recommended MSFT specs:** 648×648px (square), PNG/JPG, <500KB
4. Skip photos: Set `$PhotoFolder = ""`

> **Note:** Room photos appear in Teams booking interface

---

## First Run Authentication

The script opens your browser for authentication:

1. **Sign in** with CDX admin account (`admin@tenant.onmicrosoft.com`)
2. **Accept permissions** when prompted
3. **Token storage:**
   - **macOS:** Stored in Keychain - Click "Always Allow" to avoid re-auth (if running script multiple times in a row)
   - **Windows:** Stored in Credential Manager. No prompt needed

## What Happens During Execution

**Validation** → Checks alias names (alphanumeric only)

**Connection** → Authenticates to Graph and Exchange Online

**Reset (if `-ResetTenant` used):**

- Deletes default CDX rooms and all users (except Mod Admin)

**User Creation:**

- Entra ID accounts with the user details you added
- Password set (no forced change on login)
- UsageLocation: "US"
- Microsoft Teams Enterprise and Microsoft 365 E5 license assigned

**Groups & CA Policy:**

- Creates Security and M365 groups with defined members
- Adds MFA-excluded groups to the CDX Conditional Access policy exclusion list (creates a new policy if one isn't found)

**Teams Rooms Creation:**

- Exchange mailboxes with calendar auto-processing
- Wide-open settings for demo flexibility: auto-accept, unlimited conflicts, 24/7, 365-day booking
- No password expiration
- Teams Rooms Pro without Audio Conferencing license assigned (if you completed the free trial step of CDX tenant creation)

**Photo Upload:**

- Uploads photos for users and rooms if found in the photos folder
- Warns and skips if a photo file isn't found (doesn't bork execution)

**Cleanup** → Disconnects services

---

## Alias Rules

✅ **Valid:** Letters and numbers only (a-z, 0-9) -`hansolo`, `c3p0`, `rey`
❌ **Invalid:** Spaces, hyphens, special characters -`han-solo`, `c-3p0`, `rey skywalker`

---

## Troubleshooting

### **"User/room already exists"**

- Normal → script skips existing accounts. Run with `-ResetTenant` to start fresh

### **Photo uploads fail**

- Check: filename matches alias, 648×648px recommended, PNG/JPG/JPEG format
- Photos may fail if M365 services are slow.
- re-run with `-SkipUsers -SkipRooms -SkipGroups -SkipLicensing` to retry just photos

### **"Sync to Places failed" warnings**

- Safe to ignore. Non-critical Microsoft Places sync
- Rooms are created successfully (look for ✅)

### **Room creation slow (20-30 sec each)**

- Normal Exchange Online behavior
- Progress indicators show: `[1/13]`, `[2/13]`, etc.

### **Keychain prompts (macOS)**

- Click "Always Allow" to avoid re-authentication on each run

### **Module errors**

- Ensure PowerShell 7+ (`$PSVersionTable` to check)
- Manually install if auto-install fails:

```powershell
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Important Notes

💡 **INTENDED FOR DEMO CDX TENANTS** - Simple passwords for convenience, not intended for production use. Use freely for demo/training purposes.

---
