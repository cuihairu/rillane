#!/usr/bin/env python3
"""Check that every internal .md link under docs/ lands on a real file.

Run from the repo root:  python3 scripts/check_docs_links.py [docs_dir]

Scope: markdown links whose target ends in ".md" (the convention used by this
site). Externals (http(s)/mailto), pure anchors (#...), site-absolute paths and
assets are skipped. A link is "dead" when the file it resolves to does not exist
on disk. Site-absolute "/x/y.md" targets resolve against the docs root.
Relative links may climb out of the docs tree to repo-root files (todo.md);
a path that climbs out of the repo itself is dead.

Exit status 0 = no dead links, 1 = at least one dead link.
"""

import os
import re
import sys

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SKIP_DIRS = {"node_modules", "cache", "dist"}


def iter_md_files(docs_dir):
    for dirpath, dirnames, filenames in os.walk(docs_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if fn.endswith(".md"):
                yield os.path.join(dirpath, fn)


def split_target(target):
    """Split an inline-link target into (path, is_site_absolute, is_external)."""
    path = target.split("#", 1)[0].split("?", 1)[0]
    is_abs = path.startswith("/")
    is_ext = re.match(r"^[a-z][a-z0-9+.-]*:", path) is not None
    return path, is_abs, is_ext


def resolve(link_file, path, is_abs, docs_dir):
    if is_abs:
        return os.path.normpath(os.path.join(docs_dir, path.lstrip("/")))
    return os.path.normpath(os.path.join(os.path.dirname(link_file), path))


def candidates(resolved, repo_root):
    """Files a VitePress route for `resolved` may map to.

    Links may climb out of the docs tree to reach a repo-root file (todo.md);
    a path that climbs out of the repo itself cannot be a page, so no
    candidate is offered for it.
    """
    if not resolved.startswith(os.path.abspath(repo_root) + os.sep):
        return []
    if resolved.endswith(".md"):
        return [resolved]
    return [resolved + ".md", os.path.join(resolved, "index.md")]


def main():
    docs_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "docs")
    if not os.path.isdir(docs_dir):
        print(f"docs dir not found: {docs_dir}", file=sys.stderr)
        return 2

    checked = 0
    dead = []
    repo_root = os.path.dirname(docs_dir)
    for f in iter_md_files(docs_dir):
        rel = os.path.relpath(f, docs_dir)
        with open(f, encoding="utf-8") as fh:
            text = fh.read()
        for lineno, line in enumerate(text.splitlines(), 1):
            for target in LINK_RE.findall(line):
                target = target.strip()
                if target.startswith("<") and target.endswith(">"):
                    target = target[1:-1]
                path, is_abs, is_ext = split_target(target)
                if is_ext or not path.endswith(".md"):
                    continue
                checked += 1
                resolved = resolve(f, path, is_abs, docs_dir)
                if not any(os.path.isfile(c) for c in candidates(resolved, repo_root)):
                    dead.append((rel, lineno, target, resolved))

    for rel, lineno, target, resolved in dead:
        print(f"DEAD {rel}:{lineno} -> {target} ({resolved})")
    print(f"checked={checked} dead={len(dead)}")
    return 1 if dead else 0


if __name__ == "__main__":
    sys.exit(main())
