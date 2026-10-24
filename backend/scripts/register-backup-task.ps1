<#
.SYNOPSIS
  Registers a Scheduled Task that runs SSO's new `npm run db:backup:prod`
  (scripts/db-backup.ts) nightly. SSO previously had zero backup automation  - 
  PLATFORM_ARCHITECTURE.md Section 16 documented this as "a documentation fix only."
  SSO is the identity provider every other system depends on to log anyone
  in, which makes idpprod the single highest-impact backup gap on the
  platform. RUN THIS ON THE LIVE SERVER.
#>

param(
  # Default corrected 2026-09-09 (was B:\Company_Systems, two roots out
  # of date -- running this unedited registered a task against a stale checkout).
  [string]$BackendPath = "B:\COMPANY_SYSTEMS\SSO\backend",
  [string]$TaskName = "ExampleCorp-SSO-DB-Backup",
  # Offset from DMS (02:00) and GMS (02:20) so three pg_dump processes aren't
  # fighting for disk I/O at once. GMS was also on 02:00 until 2026-09-09, so
  # this comment's premise was only half true when it was written.
  [string]$At = "02:40"
)

if (-not (Test-Path (Join-Path $BackendPath "package.json"))) {
  Write-Error "SSO backend not found at $BackendPath  -  pass -BackendPath to point at the real location on this box."
  exit 1
}

$npmCmd = (Get-Command npm.cmd -ErrorAction SilentlyContinue)
if (-not $npmCmd) {
  Write-Error "npm.cmd not found on PATH for this session  -  specify the full path if npm isn't globally on PATH for the account this task will run as."
  exit 1
}

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "A task named '$TaskName' already exists (State: $($existing.State))."
  Write-Host "Unregister it first if you want to re-register: Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
  exit 0
}

$action  = New-ScheduledTaskAction -Execute $npmCmd.Source -Argument "run db:backup:prod" -WorkingDirectory $BackendPath
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
  -Description "Nightly idpprod backup via scripts/db-backup.ts. See DEPLOY-WINDOWS-MANUAL.md section 7." `
  -RunLevel Highest

Write-Host "Registered '$TaskName' (daily at $At). Verify with:"
Write-Host "  Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
Write-Host ""
Write-Host "Test immediately: Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Then check SSO\backups\ for a new .dump file."
