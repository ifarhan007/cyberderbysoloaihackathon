"""
Build ../code.zip for Devpost: the code/ folder only.
Excludes secrets (.env), virtual environments, caches, data/ and dataset/.

    python package_submission.py
"""
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "code.zip"
EXCLUDE_DIRS = {"venv", ".venv", "env", "__pycache__", "node_modules", ".git", "data", "dataset", ".pytest_cache"}
EXCLUDE_FILES = {".env"}

files = []
for p in sorted(HERE.rglob("*")):
    rel = p.relative_to(HERE)
    if p.is_dir() or any(part in EXCLUDE_DIRS for part in rel.parts):
        continue
    if p.name in EXCLUDE_FILES or p.suffix in (".pyc", ".zip"):
        continue
    files.append((p, Path("code") / rel))

with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for src, arc in files:
        z.write(src, arc.as_posix())

names = zipfile.ZipFile(OUT).namelist()
assert not any(n.endswith("/.env") or n == "code/.env" for n in names), ".env leaked into zip!"
print(f"[+] {OUT}  ({len(names)} files, {OUT.stat().st_size // 1024} KB)")
for n in names:
    print("    " + n)
