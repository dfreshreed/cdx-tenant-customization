# Changelog

All notable changes to this project will be documented here.

## [0.3.0] - 2026-04-10

### Added

- Add Switches for granular partial runs » `-SkipUsers`, `-SkipRooms`, `-SkipGroups`, `-SkipLicensing`, `-SkipAosp`
- Add Mutual exclusion guard » `-ResetTenant` and `-UpdateExistingUsers` now throw if used together
- Create Security/M365 Groups » uses the `$Groups` array to define `Type` (Security or M365), `Members`, and `MFAExclude`
- Add MFA-excluded groups to CDX policy exclusion list; create a new policy if none is found
- Create AOSP MTR Devices profile
- Add `Roles` field on user objects; assign the Entra directory role (e.g., `Global Administrator`) to users after creation
- Prevent CNF conflict objects when using `-ResetTenant` flag
  - restore soft-deleted users
  - delete CNF conflict objects from the recycle bin
- Add CNF conflict detection during room mailbox creation and deletion
- Show created/updated users with license status in summary table
- Show counts of users/rooms/groups created and licensing applied in summary stats table
- Add Required Modules: `Microsoft.Graph.Identity.Governance`, `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Groups`
- Add Graph scopes: `Group.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `DeviceManagementConfiguration.ReadWrite.All`

### Changed

- Convert script header to PowerShell doc block format
- Move `Set-AccountPhoto` from inline-defined to top-level function (defined before first use)
- Wrap Graph and Exchange `Connect-*` calls in try/catch with descriptive errors
- `-ResetTenant` protects/retains mod admin only (removes all other default CDX users)
- `$UpdateExistingUsers` early return now fires after licensing runs (previously before)
- Photo upload now respects `-SkipUsers` and `-SkipRooms` flags
- `-ErrorAction Stop` added to key Graph/Exchange calls improving error handling
- User data reformatted to multi-line aligned hashtable style for improved readability
- Module list expanded and reordered in both `$requiredModules` and `Import-Module` calls
- README: "Run What You Want" example table, `---` dividers, blockquote-style notes, inline alias rule examples
- README: "Add Photos" renumbered from section 5 → 7 to accommodate new Groups and AOSP sections
- README: troubleshooting tip updated with skip-flag combo for photo-only retry
- `.gitignore` comment cleanup

### Fixed

- `Write=Error` typo in module installation block → `Write-Error`

---

## [0.2.0] - 2026-04-10

### Added

- `-UpdateExistingUsers` switch — updates properties on existing users instead of skipping them; exits early before room/group/licensing steps
- Optional user object fields: `JobTitle`, `Department`, `OfficeLocation`, `AccountEnabled`, `UsageLocation`, `CompanyName`
- `Directory.AccessAsUser.All` scope added to `Connect-MgGraph` call
- Per-user error handling in `Set-UserLicense` (try/catch per user instead of bulk)
- Already-licensed detection in `Set-UserLicense` — skips users who already have all required SKUs and reports count

### Changed

- `Set-UserLicense` now tracks `$licensedCount` and `$alreadyLicensedCount` separately with clearer output
- License shortage warning deferred until after processing all users
- User creation block now builds a `$userParams` hashtable and conditionally appends optional fields
- `AccountEnabled` defaults to `true` if omitted from user object; `UsageLocation` defaults to `"US"`
- Missing photo warning now styled red with leading newline
- Updated README with `-UpdateExistingUsers` usage, updated user object examples with full field set

### Fixed

- Unused `$licensedUserCount` array replaced with scalar `$licensedCount`

---

## [0.1.0] - 2026-03-01

### Added

- Initial release: automated CDX demo tenant setup
- Creates custom Entra ID users with passwords and profile photos
- Creates Teams Rooms resource accounts with Exchange mailbox configuration (auto-accept, unlimited conflicts, 24/7 availability)
- Assigns Teams Rooms Pro and Enterprise user licenses via Microsoft Graph
- `-ResetTenant` switch to delete all non-admin CDX users and room mailboxes before provisioning
- Conditional Access policy, security group, and AOSP enrollment profile creation
- Cross-platform support (macOS/Windows/Linux) via PowerShell 7+
