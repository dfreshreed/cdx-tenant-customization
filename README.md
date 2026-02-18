# CDX Demo Tenant Customization Script

Automate the setup of your Microsoft CDX demo tenant with custom users and Teams Rooms. If you like having a customized tenant, but don't have the sanity (or time) to redo it manually every 90 days, this script is for you!

## What It Does

Transforms your CDX tenant by:

- **Removing** default CDX users and rooms (optional with `-ResetTenant` flag)
- **Creating** custom-themed users and Microsoft Teams Rooms
- **Configuring** permissive room calendars for demos (auto-accept, unlimited conflicts, 24/7)
- **Personalizing** profile photos for users and rooms
- **Assigning** teams Rooms and enterprise user licenses automatically
- **Updating** user properties (optional with `-UpdateExistingUsers` flag)

## Requirements

- **PowerShell 7+** (cross-platform: macOS/Windows/Linux)
- **Permissions:** Global Administrator in your CDX tenant
- **Modules:** Auto-installed on first run:
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Identity.DirectoryManagement`
  - `ExchangeOnlineManagement`

## Quick Start

1. **Install PowerShell 7+** (if needed)
2. **Edit the script** - Update domain, password, customize users/rooms, and add profile photos (if you want to)
3. **Run it:**

   ```powershell
   # first run (keep existing CDX accounts)
   pwsh ./user-room-creation.ps1

   # or reset tenant first (⚠️ DELETES ALL NON-ADMIN USERS)
   pwsh ./user-room-creation.ps1 -ResetTenant

   # or update properties on existing users
   pwsh ./user-room-creation.ps1 -UpdateExistingUsers
   ```

## Configuration

### 1. Set Your Domain

```powershell
$Domain = "M365x12345678.onmicrosoft.com"  # change to your CDX tenant
```

### 2. Set Password

```powershell
$DefaultPassword = "YourDemoPassword123!" # used for "regular" user accounts
```

Used for all demo users and rooms. To use different password for rooms: `$DefaultRoomPassword = "differentpassword"`

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

### 5. Add Photos (Optional)

1. Add user photos to the `photos` folder (same directory as script)
2. Image names accepted: `alias.png`, `alias.jpg`, or `alias.jpeg`
   - Example: `rey.png`, `endor101.jpg`
3. **Recommended MSFT specs:** 648×648px (square), PNG/JPG, <500KB
4. Skip photos: Set `$PhotoFolder = ""`

**Note:** Room photos appear in Teams booking interface

## First Run Authentication

The script opens your browser for authentication:

1. **Sign in** with CDX admin account (`admin@[tenant].onmicrosoft.com`)
2. **Accept permissions** when prompted:
   - Read/write users and directory
   - Read organization and roles
3. **Token storage:**
   - **macOS:** Stored in Keychain - Click "Always Allow" to avoid re-auth (if running script multiple times in a row)
   - **Windows:** Stored in Credential Manager - No prompt needed

## What Happens During Execution

**Validation** → Checks alias names (alphanumeric only)

**Connection** → Authenticates to Graph and Exchange Online

**Reset (if `-ResetTenant` used):**

- Deletes default CDX rooms and non-admin users
- Protects Global Admins and role members

**User Creation:**

- Entra ID accounts with the user details you added
- Password set (no forced change on login)
- UsageLocation: "US"
- Microsoft Teams Enterprise and Microsoft 365 E5 license assigned

**Teams Rooms Creation:**

- Exchange mailboxes with calendar auto-processing
- Permissive settings: auto-accept, unlimited conflicts, 24/7, 365-day booking
- No password expiration
- Teams Rooms Pro without Audio Conferencing license assigned (if you completed the free trial step of CDX tenant creation)

**Photo Upload:**

- Both users and rooms
- Auto-retry with propagation delays

**Cleanup** → Disconnects services

## Alias Rules

✅ **Valid:** Letters and numbers only (a-z, 0-9)
❌ **Invalid:** Spaces, hyphens, special characters

Examples:

- ❌ `han-solo`, `c-3p0`, `rey skywalker`
- ✅ `hansolo`, `c3p0`, `rey`

## Troubleshooting

### **"User/room already exists"**

- Normal → script skips existing accounts. Run with `-ResetTenant` to start fresh

### **Photo uploads fail**

- Check: filename matches alias, 648×648px recommended, PNG/JPG/JPEG format
- Photos may fail if services are slow. Script includes automatic delays to **try to** mitigate

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
 Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Important Notes

💡 **INTENDED FOR DEMO CDX TENANTS** - Simple passwords for convenience, not intended for production use. Use freely for demo/training purposes.

---
