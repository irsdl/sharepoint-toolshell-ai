#!/usr/bin/env python3
"""
Convert saved HTML articles in additional_resources/ into lightweight Markdown/text
with YAML-style metadata for RAG ingestion.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional


BLOCK_TAGS = {
    "p",
    "div",
    "article",
    "section",
    "header",
    "footer",
    "li",
    "ul",
    "ol",
    "br",
    "hr",
    "blockquote",
    "pre",
    "table",
    "tr",
    "td",
    "th",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
}
SKIP_TAGS = {"script", "style", "noscript", "svg"}


def normalize_whitespace(value: str) -> str:
    value = re.sub(r"\r\n?", "\n", value)
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


class ContentExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._buffer: List[str] = []
        self._skip_stack: List[str] = []
        self._in_title = False
        self.title_fragments: List[str] = []
        self.meta: Dict[str, str] = {}
        self.canonical: Optional[str] = None

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        attr_dict = {k.lower(): v for k, v in attrs}

        if tag in SKIP_TAGS:
            self._skip_stack.append(tag)
            return

        if self._skip_stack:
            return

        if tag in BLOCK_TAGS:
            self._buffer.append("\n")

        if tag == "title":
            self._in_title = True

        if tag == "meta":
            name = attr_dict.get("name") or attr_dict.get("property")
            content = attr_dict.get("content")
            if name and content:
                self.meta[name.lower()] = content.strip()

        if tag == "link":
            rel = attr_dict.get("rel", "").lower()
            href = attr_dict.get("href")
            if href and "canonical" in rel:
                self.canonical = href.strip()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in SKIP_TAGS:
            if self._skip_stack:
                self._skip_stack.pop()
            return

        if self._skip_stack:
            return

        if tag in BLOCK_TAGS:
            self._buffer.append("\n")

        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._skip_stack:
            return
        text = data.strip()
        if not text:
            return
        if self._in_title:
            self.title_fragments.append(text)
        self._buffer.append(text + " ")

    def get_text(self) -> str:
        body = "".join(self._buffer)
        return normalize_whitespace(body)

    def get_title(self) -> str:
        if self.title_fragments:
            return normalize_whitespace(" ".join(self.title_fragments))
        for key in ("og:title", "twitter:title", "title"):
            if key in self.meta:
                return normalize_whitespace(self.meta[key])
        return ""


def detect_source(html_text: str, extractor: ContentExtractor) -> str:
    if extractor.canonical:
        return extractor.canonical
    for key in ("og:url", "twitter:url", "article:original_url"):
        if key in extractor.meta:
            return extractor.meta[key]
    saved = re.search(r"saved from url=\(\d+\)(.*?)-->", html_text, re.IGNORECASE | re.DOTALL)
    if saved:
        return saved.group(1).strip()
    return ""


def detect_publish_date(extractor: ContentExtractor) -> str:
    candidates = [
        "article:published_time",
        "og:published_time",
        "publication_date",
        "pubdate",
        "date",
        "dc.date",
    ]
    for key in candidates:
        if key in extractor.meta:
            return extractor.meta[key]
    return ""


def build_front_matter(title: str, source: str, published: str, original_path: str) -> str:
    def quote(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    lines = ['---']
    if title:
        lines.append(f'title: "{quote(title)}"')
    if source:
        lines.append(f'source: "{quote(source)}"')
    if published:
        lines.append(f'published: "{quote(published)}"')
    lines.append(f'original_path: "{quote(original_path)}"')
    generated = dt.datetime.now(dt.timezone.utc).isoformat()
    lines.append(f'generated: "{generated}"')
    lines.append('---')
    return "\n".join(lines)


def convert_html_file(source_root: Path, output_root: Path, html_path: Path) -> None:
    relative = html_path.relative_to(source_root)
    output_path = output_root / relative
    output_path = output_path.with_suffix(".md")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    raw_html = html_path.read_text(encoding="utf-8", errors="ignore")
    extractor = ContentExtractor()
    extractor.feed(raw_html)
    extractor.close()

    article_text = extractor.get_text()
    if not article_text:
        article_text = "(No textual content extracted.)"

    title = extractor.get_title() or html_path.stem
    source = detect_source(raw_html, extractor)
    published = detect_publish_date(extractor)
    front_matter = build_front_matter(title, source, published, str(relative))

    output = f"{front_matter}\n\n{article_text}\n"
    output_path.write_text(output, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert saved HTML resources to Markdown/text for RAG.")
    parser.add_argument("--source", default="additional_resources", help="Directory containing saved HTML files.")
    parser.add_argument("--output", default="additional_resources_text", help="Directory to write cleaned Markdown.")
    args = parser.parse_args()

    source_root = Path(args.source).resolve()
    output_root = Path(args.output).resolve()
    html_files = sorted(source_root.rglob("*.html"))
    if not html_files:
        print(f"No HTML files found under {source_root}")
        return

    for html_file in html_files:
        convert_html_file(source_root, output_root, html_file)
    print(f"Converted {len(html_files)} HTML files into {output_root}")


if __name__ == "__main__":
    main()
