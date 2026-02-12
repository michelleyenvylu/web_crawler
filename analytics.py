import re
import json
import os
from urllib.parse import urlparse, urljoin, urldefrag
from constants import ANALYTICS_FILE, STOP_WORDS
_analytics = None

def is_real_word(token: str) -> bool:
    """
    Heuristic for 'real words':
    - all lowercase letters a–z
    - length >= 3
    - not in STOP_WORDS
    """
    if not token:
        return False
    if token in STOP_WORDS:
        return False
    if not re.fullmatch(r"[a-z]+", token):
        return False
    if len(token) < 3:
        return False
    return True

def generate_clean_report(output_path: str = "crawler_report_clean.txt") -> None:
    if not os.path.exists(ANALYTICS_FILE):
        print(f"No {ANALYTICS_FILE} found. Run the crawler first.")
        return

    with open(ANALYTICS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    lines = []


    unique_urls = data.get("unique_urls", [])
    lines.append(f"1. Unique pages found: {len(unique_urls)}")
    lines.append("")


    longest_url = data.get("longest_page_url", "")
    longest_words = data.get("longest_page_words", 0)
    lines.append(f"2. Longest page (by word count): {longest_words} words")
    lines.append(f"   URL: {longest_url}")
    lines.append("")


    raw_word_freq = data.get("word_freq", {})

    clean_word_freq = {}
    for token, count in raw_word_freq.items():
        token = token.lower()
        if is_real_word(token):
            clean_word_freq[token] = clean_word_freq.get(token, 0) + count

    top50 = sorted(clean_word_freq.items(), key=lambda x: -x[1])[:50]

    lines.append("3. Top 50 most common words (excluding stop words, filtered), ordered by frequency:")
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

    print(f"Clean report written to {output_path}")

def _load_analytics():
    global _analytics
    if _analytics is not None:
        return _analytics
    if os.path.exists(ANALYTICS_FILE):
        try:
            with open(ANALYTICS_FILE, "r", encoding="utf-8") as f:
                _analytics = json.load(f)
            if "unique_urls" not in _analytics:
                _analytics["unique_urls"] = set()
            if isinstance(_analytics["unique_urls"], list):
                # _analytics["unique_urls"] = {u: 1 for u in _analytics["unique_urls"]}
                _analytics["unique_urls"] = set(_analytics["unique_urls"])

            if "content_hashes" not in _analytics:
                _analytics["content_hashes"] = set()
            if isinstance(_analytics["content_hashes"], list):
                # _analytics["content_hashes"] = {h: 1 for h in _analytics["content_hashes"]}
                _analytics["content_hashes"] = set(_analytics["content_hashes"])
            return _analytics
        except (json.JSONDecodeError, IOError):
            pass
    _analytics = {
        "unique_urls": set(),
        "word_freq": {},
        "subdomain_count": {},
        "longest_page_url": "",
        "longest_page_words": 0,
        "content_hashes": set(),
    }
    return _analytics


def _save_analytics():
    global _analytics
    if _analytics is None:
        return
    out = {
        # "unique_urls": list(_analytics["unique_urls"].keys()),
        "unique_urls": list(_analytics["unique_urls"]),
        "word_freq": _analytics["word_freq"],
        "subdomain_count": _analytics["subdomain_count"],
        "longest_page_url": _analytics["longest_page_url"],
        "longest_page_words": _analytics["longest_page_words"],
        # "content_hashes": list(_analytics.get("content_hashes", {}).keys()),
        "content_hashes": list(_analytics.get("content_hashes", set())),
    }
    try:
        with open(ANALYTICS_FILE, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
    except IOError:
        pass


def _update_analytics(url, text):
    if not text or not url:
        return
    
    data = _load_analytics()

    # add defragged URL to list of 
    defragged, _ = urldefrag(url)
    defragged = defragged.strip().rstrip("/") or defragged
    is_new = defragged not in data["unique_urls"]
    # data["unique_urls"][defragged] = 1
    data["unique_urls"].add(defragged)

    if is_new:
        try:
            parsed = urlparse(defragged)
            host = (parsed.netloc or "").lower()
            host = host.split(":")[0]
            if host and host.endswith("uci.edu"):
                data["subdomain_count"][host] = data["subdomain_count"].get(host, 0) + 1
        except Exception:
            pass
    # words = re.findall(r"[a-zA-Z]{3,}", text.lower())
    words = tokenize(text)
    word_count = len(words)
    if word_count > data["longest_page_words"]:
        data["longest_page_url"] = defragged
        data["longest_page_words"] = word_count

    for w in words:
        # w = w.lower()
        if w not in STOP_WORDS:
            data["word_freq"][w] = data["word_freq"].get(w, 0) + 1

    _save_analytics()

def tokenize(text):
    tokens = []

    words = text.split()

    for word in words:
        # .isalnum() accepts non-English characters while .isascii() doesn't
        # .isascii() accepts punctuation (, ! . - etc) while .isalnum() doesn't
        if word.isalnum() and word.isascii() and len(word) > 1:
            tokens.append(word.lower())
        else:
            start_index = 0
            end_index = 0
            for index in range(len(word)):
                if not(word[index].isalnum() and word[index].isascii()):
                    end_index = index
                    # to make sure it is not appending an empty string into the token list
                    if start_index != end_index and start_index - end_index > 1:
                        tokens.append(word[start_index:end_index].lower())
                    start_index = end_index + 1
            # to get the last part of the word (e.g. 'minded' in 'open-minded')
            if start_index != len(word) and start_index - end_index > 1:
                tokens.append(word[start_index:].lower())

    return tokens

if __name__ == "__main__":
    generate_clean_report()