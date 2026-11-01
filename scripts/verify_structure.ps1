# verify_structure.ps1 - Check that every expected folder and root file exists.
# Run from the project root:   .\scripts\verify_structure.ps1
Set-Location (Split-Path -Parent $PSScriptRoot)

$leafDirs = @(
  "backend\api\routes","backend\api\dependencies","backend\schemas","backend\services","backend\middleware","backend\core",
  "config",
  "ingestion\collectors\nvd","ingestion\collectors\cisa_kev","ingestion\collectors\mitre_attack","ingestion\collectors\cwe","ingestion\collectors\advisories",
  "ingestion\document_processing","ingestion\chunking","ingestion\normalization","ingestion\validation",
  "canonical\schemas","canonical\entities","canonical\relationships","canonical\provenance",
  "graphrag_engine\indexing","graphrag_engine\retrieval","graphrag_engine\export","graphrag_engine\synchronization",
  "neo4j_engine\connection","neo4j_engine\schema","neo4j_engine\queries","neo4j_engine\repositories",
  "database\mongodb","database\repositories",
  "agent\graph","agent\nodes","agent\tools","agent\prompts","agent\state",
  "evaluation\datasets","evaluation\metrics","evaluation\experiments","evaluation\reports",
  "data\raw\nvd","data\raw\cisa_kev","data\raw\mitre_attack","data\raw\cwe","data\raw\advisories",
  "data\processed","data\documents","data\chunks","data\graphrag_outputs",
  "outputs\reports","outputs\exports","outputs\analytics",
  "tests\unit","tests\integration","tests\evaluation",
  "logs","frontend","scripts",
  "docs\architecture","docs\data_dictionary","docs\pipeline","docs\decisions"
)
$rootFiles = @(".env.example",".gitignore","requirements.txt","README.md","CHANGELOG.md","PROJECT_STATUS.md")

$missing = 0
foreach ($d in $leafDirs)   { if (-not (Test-Path $d -PathType Container)) { Write-Host "MISSING folder: $d" -ForegroundColor Red; $missing++ } }
foreach ($f in $rootFiles)  { if (-not (Test-Path $f -PathType Leaf))      { Write-Host "MISSING file:   $f" -ForegroundColor Red; $missing++ } }

Write-Host ("Checked {0} folders and {1} root files." -f $leafDirs.Count, $rootFiles.Count)
if ($missing -eq 0) { Write-Host "STRUCTURE OK" -ForegroundColor Green } else { Write-Host "$missing item(s) missing" -ForegroundColor Red; exit 1 }
