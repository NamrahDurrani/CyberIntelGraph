# GitHub Guide - make this folder a GitHub repository

Analogy: **Git** is a time machine on your PC (every commit is a save point). **GitHub** is the
cloud copy of that time machine, so you can recover or continue on another PC.

## 1. One-time Git identity
```powershell
git config --global user.name  "Your Name"
git config --global user.email "you@example.com"
```

## 2. Local repository + first commit
Easiest: use the helper script.
```powershell
cd C:\CyberIntelGraph
.\scripts\git_init.ps1
```
Manual equivalent:
```powershell
git init -b main
git add .
git status --short      # CHECK: .venv and .env must NOT appear
git commit -m "Milestone 1: project structure, docs and helper scripts"
git log --oneline
```

## 3. Create the GitHub repository
**Option A - website**
1. github.com -> **New repository** -> name `CyberIntelGraph`.
2. Choose **Private**. Do NOT tick "Add README" or ".gitignore" (you already have them).
3. Copy the URL, then:
```powershell
git remote add origin https://github.com/YOUR-USER/CyberIntelGraph.git
git push -u origin main
```
A browser window asks you to sign in the first time.

**Option B - GitHub CLI**
```powershell
winget install --id GitHub.cli -e
gh auth login
gh repo create CyberIntelGraph --private --source=. --remote=origin --push
```

**Or let the script do it after the repo exists:**
```powershell
.\scripts\git_init.ps1 -RemoteUrl https://github.com/YOUR-USER/CyberIntelGraph.git
```

## 4. Prove it worked (clone test)
```powershell
git clone https://github.com/YOUR-USER/CyberIntelGraph.git C:\clone_test
Get-ChildItem C:\clone_test -Name
Remove-Item C:\clone_test -Recurse -Force
```
Expected: the listing shows `README.md`, `docs`, `scripts`, ...

## 5. Daily workflow (after every finished, tested step)
```powershell
git status
git add .
git commit -m "Milestone 3: CISA KEV collector with validation"
git push
```
Commit message pattern: `Milestone N: what you did`.

## 6. Safety rules
- `.env`, `.venv`, `data/**`, `outputs/**`, `logs/**` are ignored by `.gitignore`.
- If you ever commit a secret by mistake: **revoke the key immediately** (deleting the commit is not enough).
- To share a small dataset on purpose: `git add -f data/processed/some_small_file.json`.
- Document large datasets in `docs/data_dictionary/` instead of committing them.

## 7. Restoring on another PC
```powershell
git clone https://github.com/YOUR-USER/CyberIntelGraph.git C:\CyberIntelGraph
cd C:\CyberIntelGraph
.\scripts\setup_env.ps1
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```
Then re-run the collectors to rebuild `data/` (raw data is not stored in Git).
