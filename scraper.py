import re
import hashlib
from collections import Counter
from urllib.parse import urlparse, urljoin, urldefrag
from analytics import _load_analytics, _save_analytics, _update_analytics
from constants import MAX_CONTENT_BYTES, MIN_WORDS, CONTENT_HASH_CHARS, ALLOWED_DOMAINS

try:
    from bs4 import BeautifulSoup  # type: ignore[import-untyped]
except ImportError:
    BeautifulSoup = None

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

    # initial base check on resp
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
        u, _ = urldefrag(u) # removes fragments after #
        u = (u or "").strip().rstrip("/") or u
        return u

    # if BeautifulSoup is not installed, default to using regex
    if BeautifulSoup is None:
        text = re.sub(r"<[^>]+>", " ", html) # filter out opening and closing tags in html

        words = re.findall(r"[a-zA-Z]{3,}", text.lower())
        if len(words) < MIN_WORDS: # if content in webpage is too short, don't crawl it
            return result
        
        # creating content hashes to check for duplicates or near duplicates
        data = _load_analytics()
        content_hashes = data.setdefault("content_hashes", set())
        h = hashlib.sha256(text[:CONTENT_HASH_CHARS].encode("utf-8", errors="replace")).hexdigest()
        if h in content_hashes:
            return result
        # content_hashes[h] = 1
        content_hashes.add(h)
        _update_analytics(base_url, text)
        
        # adding hyperlinks to result and making sure there are no duplicate links
        seen = set()
        href_pattern = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE) # finding all hyperlinks referenced
        for match in href_pattern.finditer(html):
            href = match.group(1).strip() # getting only the url
            if not href or href.startswith("#") or href.lower().startswith("javascript:"):
                continue
            absolute = urljoin(base_url, href)
            norm = _normalize(absolute)
            if norm and norm not in seen: # add link if it is not a duplicate
                seen.add(norm)
                result.append(norm)
        return result

    # using BeautifulSoup if it is installed
    soup = BeautifulSoup(html, "html.parser")
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    
    text = soup.get_text(separator=" ", strip=True)
    words = re.findall(r"[a-zA-Z]{3,}", text.lower())
    if len(words) < MIN_WORDS: # if content in webpage is too short, don't crawl it
        return result
    
    # creating content hashes to check for duplicates or near duplicates
    data = _load_analytics()
    content_hashes = data.setdefault("content_hashes", set)
    h = hashlib.sha256(text[:CONTENT_HASH_CHARS].encode("utf-8", errors="replace")).hexdigest()
    if h in content_hashes: # webpage has already been looked at before
        return result
    # content_hashes[h] = 1
    content_hashes.add(h)
    _update_analytics(base_url, text)

    # adding hyperlinks to result and making sure there are no duplicate links
    seen = set()
    for tag in soup.find_all(["a", "area"]): # finding all hyperlinks referenced
        href = tag.get("href") # getting only the url
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
            return False # don't try to crawl for urls that are too long; a potential trap
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False

        # host = (parsed.netloc or "").lower()
        host = parsed.netloc.lower()
        if not host:
            return False # host not found
        
        # checking if the host is in one of the acceptable domains, return False if not
        allowed = False
        for domain in ALLOWED_DOMAINS:
            if host == domain or host.endswith("." + domain):
                allowed = True
                break
        if not allowed:
            return False

        # trap-checking on the URL path
        # path = (parsed.path or "").lower() -- no need for 'or ""' if path is empty, parsed.path with return an empty string
        path = parsed.path.lower()
        path_parts = [p for p in path.split("/") if p] # getting each path segment
        if len(path_parts) >= 10:
            return False # having many path segments is a potential trap
        if path_parts:
            seg_counts = Counter(path_parts)
            if any(c >= 3 for c in seg_counts.values()): # if a path segment shows up 3+ times in the path
                return False
        
        # searching for possible inifinite dynamic URLs like in calendars
        trap_path_segments = ("calendar", "login", "session")
        if any(seg in path_parts for seg in trap_path_segments):
            return False
        if re.search(r"/\d{4}/\d{2}(/\d{2})?$", path):
            return False
        if re.search(r"/events/\d{4}/", path) or "/events/20" in path:
            return False
        
        # trap-checking on the query section of URL
        # query = (parsed.query or "").lower() -- no need for 'or ""' if query is empty, parsed.query with return an empty string
        query = parsed.query.lower()
        if query.count("&") >= 5:
            return False
        if re.search(r"(^|&)page=\d+($|&)", query):
            return False
        trap_params = ("action=", "share=", "do=", "tab=", "calendar_date=")
        if any(p in query for p in trap_params):
            return False
        # trap_path_segments = ("calendar", "login", "session")
        # if any(seg in path_parts for seg in trap_path_segments):
        #     return False
        trap_keywords = ("replytocom", "sort=", "filter=")
        if any(k in (path + "?" + query) for k in trap_keywords):
            return False
        
        # check if URL is a static or downloadable file
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

if __name__ == "__main__":
    pass