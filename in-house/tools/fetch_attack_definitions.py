#!/usr/bin/env python3
"""Pin official website definitions for a supplied ATT&CK detector-gap audit.

HTML snapshots stay outside the rules repository. This command deliberately
does not create rules or award detector capacity from technique descriptions.
"""

import argparse
import concurrent.futures
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path


class TechniquePage(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.description = []
        self.title = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "h1":
            self.in_title = True
        if tag == "div":
            if self.depth:
                self.depth += 1
            elif "description-body" in attrs.get("class", "").split() and not self.description:
                self.depth = 1
        if self.depth and tag in {"p", "li", "br"}:
            self.description.append("\n")

    def handle_endtag(self, tag):
        if tag == "h1":
            self.in_title = False
        if tag == "div" and self.depth:
            self.depth -= 1

    def handle_data(self, text):
        if self.in_title:
            self.title.append(text)
        if self.depth:
            self.description.append(text)

    def result(self):
        title = " ".join("".join(self.title).split())
        paragraphs = [" ".join(p.split()) for p in "".join(self.description).split("\n")]
        return title, "\n".join(p for p in paragraphs if p)


def fetch(technique, cache):
    attack_id = technique["attack_id"]
    url = "https://attack.mitre.org/techniques/" + attack_id.replace(".", "/") + "/"
    snapshot = cache / (attack_id + ".html")
    if snapshot.exists():
        raw = snapshot.read_bytes()
    else:
        for attempt in range(3):
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "GTISC-ATTACK-rule-review/1.0"})
                with urllib.request.urlopen(request, timeout=45) as response:
                    raw = response.read()
                snapshot.write_bytes(raw)
                break
            except Exception:
                if attempt == 2:
                    raise
                time.sleep(attempt + 1)
    parser = TechniquePage()
    parser.feed(raw.decode("utf-8"))
    title, definition = parser.result()
    if not title or not definition or technique["name"].casefold() not in title.casefold():
        raise ValueError(f"missing or mismatched official definition: {attack_id}: {title}")
    return {
        "attack_id": attack_id,
        "name": technique["name"],
        "official_url": url,
        "website_title": title,
        "website_sha256": hashlib.sha256(raw).hexdigest(),
        "definition_sha256": hashlib.sha256(definition.encode()).hexdigest(),
        "official_definition": definition,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()
    source = args.audit.read_bytes()
    audit = json.loads(source)
    missing = set(audit["static_or_runtime_detector_gap_ids"])
    targets = [row for row in audit["techniques"] if row["attack_id"] in missing]
    args.cache.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        rows = list(executor.map(lambda row: fetch(row, args.cache), targets))
    result = {
        "schema": 1,
        "scope": "Official MITRE website definitions for the frozen detector gap; definitions are design inputs, never evidence.",
        "retrieved_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_audit_sha256": hashlib.sha256(source).hexdigest(),
        "technique_count": len(rows),
        "techniques": sorted(rows, key=lambda row: row["attack_id"]),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"definitions": len(rows), "out": str(args.out)}))


if __name__ == "__main__":
    main()
