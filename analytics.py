import re
import json
import os
from urllib.parse import urlparse, urljoin, urldefrag
from constants import ANALYTICS_FILE, STOP_WORDS
_analytics = None

def generate_report(output_path="crawler_report.txt"):
    if not os.path.exists(ANALYTICS_FILE):
        print(f"No {ANALYTICS_FILE} found. Run the crawler first.")
        return
    with open(ANALYTICS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    lines = []
    unique_urls = data.get("unique_urls", [])
    if isinstance(unique_urls, dict):
        unique_urls = list(unique_urls.keys())
    lines.append(f"1. Unique pages found: {len(unique_urls)}")
    lines.append("")
    longest_url = data.get("longest_page_url", "")
    longest_words = data.get("longest_page_words", 0)
    lines.append(f"2. Longest page (by word count): {longest_words} words")
    lines.append(f"   URL: {longest_url}")
    lines.append("")
    word_freq = data.get("word_freq", {})
    top50 = sorted(word_freq.items(), key=lambda x: -x[1])[:50]
    lines.append("3. Top 50 most common words (excluding stop words), ordered by frequency:")
    for w, c in top50:
        lines.append(f"   {w}: {c}")
    lines.append("")
    subdomain_count = data.get("subdomain_count", {})
    lines.append("4. Subdomains in uci.edu (alphabetically), with unique page count:")
    for subdomain in sorted(subdomain_count.keys()):
        lines.append(f"   {subdomain}, {subdomain_count[subdomain]}")
    text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Report written to {output_path}")

def _load_analytics():
    global _analytics
    if _analytics is not None:
        return _analytics
    if os.path.exists(ANALYTICS_FILE):
        try:
            with open(ANALYTICS_FILE, "r", encoding="utf-8") as f:
                _analytics = json.load(f)
            if "unique_urls" not in _analytics:
                _analytics["unique_urls"] = {}
            if isinstance(_analytics["unique_urls"], list):
                _analytics["unique_urls"] = {u: 1 for u in _analytics["unique_urls"]}
            if "content_hashes" not in _analytics:
                _analytics["content_hashes"] = {}
            if isinstance(_analytics["content_hashes"], list):
                _analytics["content_hashes"] = {h: 1 for h in _analytics["content_hashes"]}
            return _analytics
        except (json.JSONDecodeError, IOError):
            pass
    _analytics = {
        "unique_urls": {},
        "word_freq": {},
        "subdomain_count": {},
        "longest_page_url": "",
        "longest_page_words": 0,
        "content_hashes": {},
    }
    return _analytics


def _save_analytics():
    global _analytics
    if _analytics is None:
        return
    out = {
        "unique_urls": list(_analytics["unique_urls"].keys()),
        "word_freq": _analytics["word_freq"],
        "subdomain_count": _analytics["subdomain_count"],
        "longest_page_url": _analytics["longest_page_url"],
        "longest_page_words": _analytics["longest_page_words"],
        "content_hashes": list(_analytics.get("content_hashes", {}).keys()),
    }
    try:
        with open(ANALYTICS_FILE, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
    except IOError:
        pass


def _update_analytics(url, text):
    if not text or not url:
        return
    defragged, _ = urldefrag(url)
    defragged = defragged.strip().rstrip("/") or defragged

    data = _load_analytics()
    is_new = defragged not in data["unique_urls"]
    data["unique_urls"][defragged] = 1

    if is_new:
        try:
            parsed = urlparse(defragged)
            host = (parsed.netloc or "").lower()
            host = host.split(":")[0]
            if host and host.endswith("uci.edu"):
                data["subdomain_count"][host] = data["subdomain_count"].get(host, 0) + 1
        except Exception:
            pass
    words = re.findall(r"[a-zA-Z]{3,}", text.lower())
    word_count = len(words)
    if word_count > data["longest_page_words"]:
        data["longest_page_url"] = defragged
        data["longest_page_words"] = word_count

    for w in words:
        w = w.lower()
        if w not in STOP_WORDS:
            data["word_freq"][w] = data["word_freq"].get(w, 0) + 1

    _save_analytics()
