import re
import json
import os
import hashlib
from collections import Counter
from urllib.parse import urlparse, urljoin, urldefrag

try:
    from bs4 import BeautifulSoup  # type: ignore[import-untyped]
except ImportError:
    BeautifulSoup = None

ALLOWED_DOMAINS = (
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu",
)

MAX_CONTENT_BYTES = 2 * 1024 * 1024
MIN_WORDS = 50
CONTENT_HASH_CHARS = 5000
ANALYTICS_FILE = "analytics.json"
STOP_WORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "if", "then", "else", "when", "at", "by", "for",
    "with", "about", "against", "between", "into", "through", "during", "before", "after",
    "above", "below", "to", "from", "up", "down", "in", "out", "on", "off", "over", "under",
    "again", "further", "once", "here", "there", "all", "each", "few", "more", "most",
    "other", "some", "such", "no", "nor", "not", "only", "own", "same", "so", "than",
    "too", "very", "just", "can", "will", "would", "could", "should", "may", "might",
    "must", "shall", "is", "are", "was", "were", "be", "been", "being", "have", "has",
    "had", "do", "does", "did", "doing", "i", "me", "my", "myself", "we", "our", "ours",
    "ourselves", "you", "your", "yours", "yourself", "yourselves", "he", "him", "his",
    "himself", "she", "her", "hers", "herself", "it", "its", "itself", "they", "them",
    "their", "theirs", "themselves", "what", "which", "who", "whom", "this", "that",
    "these", "those", "am", "because", "until", "while", "of", "as",
})

_analytics = None


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


def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    result = []
    if resp is None:
        return result
    if resp.status != 200:
        return result
    if getattr(resp, "raw_response", None) is None:
        return result

    raw = resp.raw_response
    content = getattr(raw, "content", None)
    if content is None or not isinstance(content, bytes):
        return result
    if len(content) > MAX_CONTENT_BYTES:
        return result
    headers = getattr(raw, "headers", {}) or {}
    ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if "text/html" not in ctype:
        return result
    base_url = getattr(resp, "url", url) or url
    if isinstance(base_url, bytes):
        base_url = base_url.decode("utf-8", errors="replace")
    try:
        html = content.decode("utf-8", errors="replace")
    except Exception:
        html = content.decode("latin-1", errors="replace")
    def _normalize(u):
        u, _ = urldefrag(u)
        u = (u or "").strip().rstrip("/") or u
        return u

    if BeautifulSoup is None:
        text = re.sub(r"<[^>]+>", " ", html)
        words = re.findall(r"[a-zA-Z]{3,}", text.lower())
        if len(words) < MIN_WORDS:
            return result
        data = _load_analytics()
        content_hashes = data.setdefault("content_hashes", {})
        h = hashlib.sha256(text[:CONTENT_HASH_CHARS].encode("utf-8", errors="replace")).hexdigest()
        if h in content_hashes:
            return result
        content_hashes[h] = 1
        _update_analytics(base_url, text)
        seen = set()
        href_pattern = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            href = match.group(1).strip()
            if not href or href.startswith("#") or href.lower().startswith("javascript:"):
                continue
            absolute = urljoin(base_url, href)
            norm = _normalize(absolute)
            if norm and norm not in seen:
                seen.add(norm)
                result.append(norm)
        return result

    soup = BeautifulSoup(html, "html.parser")
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    text = soup.get_text(separator=" ", strip=True)
    words = re.findall(r"[a-zA-Z]{3,}", text.lower())
    if len(words) < MIN_WORDS:
        return result
    data = _load_analytics()
    content_hashes = data.setdefault("content_hashes", {})
    h = hashlib.sha256(text[:CONTENT_HASH_CHARS].encode("utf-8", errors="replace")).hexdigest()
    if h in content_hashes:
        return result
    content_hashes[h] = 1
    _update_analytics(base_url, text)
    seen = set()
    for tag in soup.find_all(["a", "area"]):
        href = tag.get("href")
        if not href or not isinstance(href, str):
            continue
        href = href.strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            continue
        absolute = urljoin(base_url, href)
        norm = _normalize(absolute)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        result.append(norm)

    return result


def is_valid(url):
    # Decide whether to crawl this url or not.
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        if len(url) > 300:
            return False
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False

        host = (parsed.netloc or "").lower()
        if not host:
            return False
        allowed = False
        for domain in ALLOWED_DOMAINS:
            if host == domain or host.endswith("." + domain):
                allowed = True
                break
        if not allowed:
            return False
        path = (parsed.path or "").lower()
        path_parts = [p for p in path.split("/") if p]
        if len(path_parts) >= 10:
            return False
        if path_parts:
            seg_counts = Counter(path_parts)
            if any(c >= 3 for c in seg_counts.values()):
                return False
        if re.search(r"/\d{4}/\d{2}(/\d{2})?$", path):
            return False
        if re.search(r"/events/\d{4}/", path) or "/events/20" in path:
            return False
        query = (parsed.query or "").lower()
        if query.count("&") >= 5:
            return False
        if re.search(r"(^|&)page=\d+($|&)", query):
            return False
        trap_params = ("action=", "share=", "do=", "tab=", "calendar_date=")
        if any(p in query for p in trap_params):
            return False
        trap_path_segments = ("calendar", "login", "session")
        if any(seg in path_parts for seg in trap_path_segments):
            return False
        trap_keywords = ("replytocom", "sort=", "filter=")
        if any(k in (path + "?" + query) for k in trap_keywords):
            return False
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            r"|png|tiff?|mid|mp2|mp3|mp4"
            r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            r"|epub|dll|cnf|tgz|sha1"
            r"|thmx|mso|arff|rtf|jar|csv"
            r"|rm|smil|wmv|swf|wma|zip|rar|gz)$",
            path,
        ):
            return False

        return True

    except TypeError:
        return False


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
