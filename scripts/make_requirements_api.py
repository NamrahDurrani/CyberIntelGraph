r"""Build requirements-api.txt for the Docker image from what your API code really imports.

Run from the project root with the venv you run uvicorn in (.venv-graphrag):
    python scripts\make_requirements_api.py api rag graphrag_engine
Pass the folders the API imports. Then READ the file and remove anything dev-only.
torch is excluded on purpose (the Dockerfile installs the CPU build).
"""
import ast
import sys
from importlib import metadata
from pathlib import Path

EXCLUDE = {"torch", "pytest", "deepeval", "graphrag", "pip", "setuptools", "wheel"}
ALWAYS = ["uvicorn"]  # runs the app but is never imported by it
SKIP_DIRS = {".venv", ".venv-graphrag", "node_modules", "tests", "__pycache__"}


def top_level_imports(folder: Path):
    names = set()
    for py in folder.rglob("*.py"):
        if SKIP_DIRS & set(py.parts):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def main():
    folders = [Path(a) for a in sys.argv[1:]] or [Path(".")]
    imports = set()
    for f in folders:
        if not f.exists():
            print(f"skip (missing): {f}")
            continue
        imports |= top_level_imports(f)
    dist_map = metadata.packages_distributions()
    pins, unknown = {}, []
    for name in sorted(imports - set(sys.stdlib_module_names)):
        dists = dist_map.get(name)
        if not dists:
            unknown.append(name)  # local package or not installed
            continue
        for d in dists:
            if d.lower() not in EXCLUDE:
                pins[d] = metadata.version(d)
    for extra in ALWAYS:
        try:
            pins[extra] = metadata.version(extra)
        except metadata.PackageNotFoundError:
            pass
    lines = [f"{k}=={v}" for k, v in sorted(pins.items(), key=lambda kv: kv[0].lower())]
    Path("requirements-api.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote requirements-api.txt with {len(lines)} packages")
    if unknown:
        print("not matched to an installed package (local modules are normal):")
        print("  " + ", ".join(unknown))


if __name__ == "__main__":
    main()
