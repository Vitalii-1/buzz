#!/usr/bin/env python3
"""Validate structural discovery for ignored PostgreSQL-backed Rust tests."""

from __future__ import annotations

import re
import sys
from pathlib import Path

IGNORE_ATTRIBUTE = re.compile(r"#\s*\[\s*ignore\s*=")
FUNCTION = re.compile(r"\b(?:async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
MODULE = re.compile(r"\bmod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{")
EXTERNAL_INFRA = re.compile(r"\b(?:s3|minio|storage|docker|network)\b", re.IGNORECASE)
RAW_STRING = re.compile(r'(?:b?r)(?P<hashes>#{0,255})"')
CHAR_LITERAL = re.compile(r"(?:b)?'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^\\'\n])'")


def sanitize_rust(source: str) -> str:
    """Blank comments and literals while preserving byte offsets and braces."""
    chars = list(source)
    index = 0
    length = len(source)
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end == -1 else end
            for offset in range(index, end):
                chars[offset] = " "
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            for offset in range(start, index):
                if chars[offset] != "\n":
                    chars[offset] = " "
            continue

        character = CHAR_LITERAL.match(source, index)
        if character:
            start = index
            index = character.end()
            for offset in range(start, index):
                chars[offset] = " "
            continue

        raw = RAW_STRING.match(source, index)
        if raw:
            start = index
            terminator = '"' + raw.group("hashes")
            index = raw.end()
            end = source.find(terminator, index)
            index = length if end == -1 else end + len(terminator)
            for offset in range(start, index):
                if chars[offset] != "\n":
                    chars[offset] = " "
            continue

        quote_start = index
        if source.startswith('b"', index):
            index += 1
        if source[index] == '"':
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            for offset in range(quote_start, min(index, length)):
                if chars[offset] != "\n":
                    chars[offset] = " "
            continue
        index += 1
    return "".join(chars)


def parse_rust_string_literal(source: str, start: int) -> tuple[str, int] | None:
    """Parse an ordinary or raw Rust string literal at or after start."""
    index = start
    while index < len(source) and source[index].isspace():
        index += 1

    raw = RAW_STRING.match(source, index)
    if raw:
        content_start = raw.end()
        terminator = '"' + raw.group("hashes")
        content_end = source.find(terminator, content_start)
        if content_end == -1:
            return None
        return source[content_start:content_end], content_end + len(terminator)

    if index >= len(source) or source[index] != '"':
        return None
    index += 1
    content = []
    while index < len(source):
        if source[index] == "\\":
            if index + 1 >= len(source):
                return None
            content.append(source[index + 1])
            index += 2
        elif source[index] == '"':
            return "".join(content), index + 1
        else:
            content.append(source[index])
            index += 1
    return None


def ignore_attributes(source: str, sanitized: str) -> list[tuple[int, int, str]]:
    """Return real ignore attributes and reasons, excluding comments."""
    attributes = []
    for match in IGNORE_ATTRIBUTE.finditer(sanitized):
        parsed = parse_rust_string_literal(source, match.end())
        if parsed is None:
            continue
        reason, literal_end = parsed
        attribute_end = literal_end
        while attribute_end < len(source) and source[attribute_end].isspace():
            attribute_end += 1
        if attribute_end >= len(source) or source[attribute_end] != "]":
            continue
        attributes.append((match.start(), attribute_end + 1, reason))
    return attributes


def module_ranges(source: str) -> list[tuple[int, int, str]]:
    sanitized = sanitize_rust(source)
    brace_pairs: dict[int, int] = {}
    stack: list[int] = []
    for index, char in enumerate(sanitized):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            brace_pairs[stack.pop()] = index

    ranges = []
    for match in MODULE.finditer(sanitized):
        open_brace = sanitized.find("{", match.start(), match.end())
        close_brace = brace_pairs.get(open_brace)
        if close_brace is not None:
            ranges.append((open_brace, close_brace, match.group("name")))
    return ranges


def integration_binary_is_postgres(path: Path) -> bool:
    crate_root = path.parent.parent
    return (
        path.parent.name == "tests"
        and path.name.startswith("postgres_")
        and (crate_root / "Cargo.toml").is_file()
    )


def validate_file(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    sanitized = sanitize_rust(source)
    ranges = module_ranges(source)
    errors = []

    for attribute_start, attribute_end, reason in ignore_attributes(source, sanitized):
        reason_lower = reason.lower()
        mentions_postgres = "postgres" in reason_lower or "postgresql" in reason_lower
        mentions_redis = "redis" in reason_lower
        if not mentions_postgres and not mentions_redis:
            continue

        function = FUNCTION.search(sanitized, attribute_end)
        if function is None:
            errors.append(f"{path}: ignored infrastructure test has no following function")
            continue
        function_name = function.group("name")
        modules = [
            name for start, end, name in ranges if start < attribute_start < end
        ]
        in_postgres_lane = (
            any(name.endswith("postgres_tests") for name in modules)
            or integration_binary_is_postgres(path)
        )
        in_external_module = any(name.startswith("external_infra") for name in modules)
        needs_external_infra = bool(EXTERNAL_INFRA.search(reason))

        if mentions_redis and not mentions_postgres and in_postgres_lane and not in_external_module:
            errors.append(
                f"{path}:{source.count(chr(10), 0, function.start()) + 1}: "
                f"{function_name} is Redis-only but sits inside PostgreSQL discovery; "
                "move it under an external_infra* module"
            )
        elif needs_external_infra and not in_external_module:
            errors.append(
                f"{path}:{source.count(chr(10), 0, function.start()) + 1}: "
                f"{function_name} requires infrastructure beyond PostgreSQL/Redis; "
                "move it under an external_infra* module"
            )
        elif mentions_postgres and not needs_external_infra and not in_postgres_lane:
            errors.append(
                f"{path}:{source.count(chr(10), 0, function.start()) + 1}: "
                f"{function_name} requires PostgreSQL but is not discoverable; "
                "place it under postgres_tests or in a postgres_* integration binary"
            )

    return errors


def rust_files(arguments: list[str]) -> list[Path]:
    files = []
    for argument in arguments:
        path = Path(argument)
        if path.is_dir():
            files.extend(candidate for candidate in path.rglob("*.rs") if "target" not in candidate.parts)
        elif path.suffix == ".rs":
            files.append(path)
        else:
            raise ValueError(f"not a Rust source file or directory: {path}")
    return sorted(set(files))


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {Path(sys.argv[0]).name} <Rust source file or directory> [...]", file=sys.stderr)
        return 2
    try:
        files = rust_files(sys.argv[1:])
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    errors = [error for path in files for error in validate_file(path)]
    if errors:
        print("PostgreSQL test discovery validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"validated PostgreSQL test discovery across {len(files)} Rust source files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
