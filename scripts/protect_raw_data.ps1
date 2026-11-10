# protect_raw_data.ps1 - Make downloaded raw files read-only so they cannot be edited by accident.
# Raw data is the evidence locker: it must never change after download.
#
#   .\scripts\protect_raw_data.ps1              set read-only on every raw file
#   .\scripts\protect_raw_data.ps1 -Unprotect   remove read-only again (for example before deleting a bad download)
#   .\scripts\protect_raw_data.ps1 -WhatIf      only show what would change
#
# manifest.jsonl is NOT protected: the NVD and advisories collectors append to it.
# New downloads are still possible (new files are created, existing ones are never rewritten).
param([switch]$Unprotect, [switch]$WhatIf)
Set-Location (Split-Path -Parent $PSScriptRoot)

$skipNames = @("manifest.jsonl", ".gitkeep")
$files = Get-ChildItem -Path "data\raw" -Recurse -File | Where-Object { $skipNames -notcontains $_.Name }
$changed = 0
foreach ($f in $files) {
    $wantReadOnly = -not $Unprotect
    if ($f.IsReadOnly -ne $wantReadOnly) {
        if ($WhatIf) { Write-Host ("would set read-only={0}: {1}" -f $wantReadOnly, $f.FullName) }
        else { $f.IsReadOnly = $wantReadOnly }
        $changed++
    }
}
$mode = if ($Unprotect) { "writable" } else { "read-only" }
if ($WhatIf) { Write-Host "$changed file(s) would become $mode (of $($files.Count))" }
else { Write-Host "$changed file(s) changed to $mode (of $($files.Count) raw files)" -ForegroundColor Green }
