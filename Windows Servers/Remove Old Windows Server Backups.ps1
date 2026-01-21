$upperBackupThresholdDays = 30

$oldBackups = Get-WBBackupSet | Where-Object { $_.BackupTime -lt (Get-Date).AddDays("$(-$upperBackupThresholdDays)") }

foreach ($oldBackup in $oldBackups) {
    wbadmin DELETE BACKUP -version:$($oldBackup.VersionId) -quiet
}