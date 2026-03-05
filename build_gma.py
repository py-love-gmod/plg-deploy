from __future__ import annotations

import json
import struct
import time
import zlib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class AddonMeta:
    title: str
    description: str
    author: str
    ignore: list[str]


@dataclass(frozen=True)
class FileEntry:
    rel_path_posix: str
    content: bytes
    crc32: int


# https://github.com/Facepunch/gmad/blob/master/include/AddonWhiteList.h
WHITELIST: tuple[str, ...] = (
    "lua/*.lua",
    "scenes/*.vcd",
    "particles/*.pcf",
    "resource/fonts/*.ttf",
    "scripts/vehicles/*.txt",
    "resource/localization/*/*.properties",
    "maps/*.bsp",
    "maps/*.lmp",
    "maps/*.nav",
    "maps/*.ain",
    "maps/thumb/*.png",
    "sound/*.wav",
    "sound/*.mp3",
    "sound/*.ogg",
    "materials/*.vmt",
    "materials/*.vtf",
    "materials/*.png",
    "materials/*.jpg",
    "materials/*.jpeg",
    "materials/colorcorrection/*.raw",
    "models/*.mdl",
    "models/*.phy",
    "models/*.ani",
    "models/*.vvd",
    "models/*.vtx",
    "!models/*.sw.vtx",
    "!models/*.360.vtx",
    "!models/*.xbox.vtx",
    "gamemodes/*/*.txt",
    "!gamemodes/*/*/*.txt",
    "gamemodes/*/*.fgd",
    "!gamemodes/*/*/*.fgd",
    "gamemodes/*/logo.png",
    "gamemodes/*/icon24.png",
    "gamemodes/*/gamemode/*.lua",
    "gamemodes/*/entities/effects/*.lua",
    "gamemodes/*/entities/weapons/*.lua",
    "gamemodes/*/entities/entities/*.lua",
    "gamemodes/*/backgrounds/*.png",
    "gamemodes/*/backgrounds/*.jpg",
    "gamemodes/*/backgrounds/*.jpeg",
    "gamemodes/*/content/models/*.mdl",
    "gamemodes/*/content/models/*.phy",
    "gamemodes/*/content/models/*.ani",
    "gamemodes/*/content/models/*.vvd",
    "gamemodes/*/content/models/*.vtx",
    "!gamemodes/*/content/models/*.sw.vtx",
    "!gamemodes/*/content/models/*.360.vtx",
    "!gamemodes/*/content/models/*.xbox.vtx",
    "gamemodes/*/content/materials/*.vmt",
    "gamemodes/*/content/materials/*.vtf",
    "gamemodes/*/content/materials/*.png",
    "gamemodes/*/content/materials/*.jpg",
    "gamemodes/*/content/materials/*.jpeg",
    "gamemodes/*/content/materials/colorcorrection/*.raw",
    "gamemodes/*/content/scenes/*.vcd",
    "gamemodes/*/content/particles/*.pcf",
    "gamemodes/*/content/resource/fonts/*.ttf",
    "gamemodes/*/content/scripts/vehicles/*.txt",
    "gamemodes/*/content/resource/localization/*/*.properties",
    "gamemodes/*/content/maps/*.bsp",
    "gamemodes/*/content/maps/*.nav",
    "gamemodes/*/content/maps/*.ain",
    "gamemodes/*/content/maps/thumb/*.png",
    "gamemodes/*/content/sound/*.wav",
    "gamemodes/*/content/sound/*.mp3",
    "gamemodes/*/content/sound/*.ogg",
    "data_static/*.txt",
    "data_static/*.dat",
    "data_static/*.json",
    "data_static/*.xml",
    "data_static/*.csv",
    "shaders/fxc/*.vcs",
)


def load_addon_json(addon_json: Path) -> AddonMeta:
    data = json.loads(addon_json.read_text(encoding="utf-8"))

    title = str(data.get("title") or "No title provided")
    description = str(data.get("description") or "No description provided")

    author = data.get("author")
    if not author:
        authors = data.get("authors")
        if isinstance(authors, list) and authors:
            author = ", ".join(map(str, authors))

        else:
            author = "No author provided"

    ignore = data.get("ignore") or []
    if not isinstance(ignore, list):
        raise ValueError("addon.json: 'ignore' must be a list of glob patterns")

    return AddonMeta(
        title=title,
        description=description,
        author=str(author),
        ignore=[str(x) for x in ignore],
    )


def _split_allow_deny(patterns: Iterable[str]) -> tuple[list[str], list[str]]:
    allow: list[str] = []
    deny: list[str] = []
    for p in patterns:
        p = p.strip()
        if not p:
            continue

        if p.startswith("!"):
            deny.append(p[1:])

        else:
            allow.append(p)

    return allow, deny


_ALLOW, _DENY = _split_allow_deny(WHITELIST)


def _matches_any(path_posix: str, globs: Iterable[str]) -> bool:
    return any(fnmatchcase(path_posix, g) for g in globs)


def whitelisted(path_posix: str) -> bool:
    if not _matches_any(path_posix, _ALLOW):
        return False

    if _matches_any(path_posix, _DENY):
        return False

    return True


def ignored(path_posix: str, ignore_globs: list[str]) -> bool:
    if not ignore_globs:
        return False

    return _matches_any(path_posix, ignore_globs) or _matches_any(
        "./" + path_posix, ignore_globs
    )


def collect_files(root: Path, meta: AddonMeta) -> list[FileEntry]:
    root = root.resolve()
    entries: list[FileEntry] = []

    for p in root.rglob("*"):
        if not p.is_file():
            continue

        rel_posix = p.relative_to(root).as_posix()

        if not whitelisted(rel_posix):
            continue

        if ignored(rel_posix, meta.ignore):
            continue

        content = p.read_bytes()
        crc = zlib.crc32(content) & 0xFFFFFFFF
        entries.append(FileEntry(rel_path_posix=rel_posix, content=content, crc32=crc))

    entries.sort(key=lambda e: e.rel_path_posix)
    return entries


def pack_gma(
    meta: AddonMeta,
    files: list[FileEntry],
    *,
    steamid: int = 0,
    timestamp: int | None = None,
) -> bytes:
    ts = int(time.time() if timestamp is None else timestamp)

    def z(s: str) -> bytes:
        return s.encode("utf-8") + b"\x00"

    buf = bytearray()
    buf += b"GMAD"
    buf += struct.pack("<BQQ", 3, int(steamid), ts)
    buf += z(meta.title)
    buf += z(meta.description)
    buf += z(meta.author)
    buf += struct.pack("<I", 1)  # addon version

    # File headers
    for idx, f in enumerate(files, start=1):
        buf += struct.pack("<I", idx)
        buf += z(f.rel_path_posix)
        buf += struct.pack("<Q", len(f.content))
        buf += struct.pack("<I", f.crc32)

    buf += struct.pack("<I", 0)  # file list terminator

    # File bodies
    for f in files:
        buf += f.content

    buf += struct.pack("<I", 0)  # end terminator
    return bytes(buf)


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("output_file", help="Output .gma file path")
    ap.add_argument("addon_json", help="Path to addon.json")
    ap.add_argument("--root", default=".", help="Addon root directory (default: .)")
    ap.add_argument("--steamid", default="0", help="SteamID64 (default: 0)")
    ap.add_argument("--timestamp", default="", help="Timestamp override (unix epoch)")
    args = ap.parse_args()

    out_path = Path(args.output_file)
    addon_json = Path(args.addon_json)
    root = Path(args.root)

    meta = load_addon_json(addon_json)
    files = collect_files(root, meta)

    ts = int(args.timestamp) if args.timestamp else None
    gma = pack_gma(meta, files, steamid=int(args.steamid), timestamp=ts)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(gma)

    print(f"Packed {len(files)} files -> {out_path}")


if __name__ == "__main__":
    main()
