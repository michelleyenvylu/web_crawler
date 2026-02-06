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