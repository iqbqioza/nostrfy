//! NIP-50: Search Capability.
//!
//! Filters may carry a `search` string. The relay maintains a word index of
//! event content: an event matches when at least one query term appears in
//! its content, and the results are ordered by relevance — each term is
//! weighted by its inverse document frequency (`1 / (1 + ln df)`, estimated
//! from the word index), so rarer terms dominate the ranking — with the
//! `limit` applied after that ordering. The number of query terms used is
//! capped (see `SEARCH_MAX_TERMS` in the scan engine) so a pathological
//! search string cannot fan out into hundreds of index ranges.

/// Tokenizes text into lowercase alphanumeric words of length >= 2.
///
/// Lowercasing is Unicode-aware (`to_lowercase`) so that the indexed words
/// match the per-event term check in the scan engine, which lowercases the
/// content with the same function: a query for an accented or non-ASCII
/// uppercase term must find the same events the index contains.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut numeric = true;
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            numeric &= ch.is_ascii_digit();
            current.extend(ch.to_lowercase());
        } else if !current.is_empty() {
            if current.len() >= 2 && !numeric {
                words.push(std::mem::take(&mut current));
                // The next token starts fresh: a leading letter must not
                // inherit the "numeric" flag of the previous token, or the
                // indexing would depend on the token's position in the text.
                numeric = true;
            } else {
                current.clear();
                numeric = true;
            }
        }
    }
    if current.len() >= 2 && !numeric {
        words.push(current);
    }
    words
}

/// Maximum bytes of a `search` string examined when deriving query terms.
///
/// The WebSocket path (`REQ`/`COUNT`/`NEG-OPEN`) has no byte cap of its own
/// (unlike the REST API's `limits.max_api_search_bytes`), so a multi-megabyte
/// search string would otherwise be fully allocated and tokenized on the
/// shared reader thread before the caller truncates to `SEARCH_MAX_TERMS` —
/// a reader-thread CPU/RAM stall from a single filter. Truncation happens at
/// a character boundary; over-long queries silently match on their prefix,
/// exactly like the existing term-count truncation.
pub const MAX_SEARCH_BYTES: usize = 8_192;

fn floor_char_boundary(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Tokenizes for a *query*: unlike the index tokenizer, numeric-only words
/// stay in the term list. They are not in the word index, so the index walk
/// finds nothing for them (such searches return no results instead of
/// matching everything). A mixed query like "nostr 2023" constrains the
/// walk to "nostr"; the per-event match only requires one term (NIP-50:
/// any of the terms), so "2023" does not act as an additional constraint.
///
/// Stops once `limit` terms are collected so a pathological string cannot
/// force the allocation of hundreds of thousands of terms before the caller
/// truncates.
fn query_tokenize_capped(text: &str, out: &mut Vec<String>, limit: usize) {
    if out.len() >= limit {
        return;
    }
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            current.extend(ch.to_lowercase());
        } else if !current.is_empty() {
            if current.len() >= 2 {
                out.push(std::mem::take(&mut current));
                if out.len() >= limit {
                    return;
                }
            } else {
                current.clear();
            }
        }
    }
    if current.len() >= 2 && out.len() < limit {
        out.push(current);
    }
}

/// Search terms derived from a filter's `search` value.
///
/// NIP-50: a query string may contain `key:value` pairs (two words
/// separated by a colon); these are extensions and relays SHOULD ignore
/// the ones they do not support. Such tokens are dropped from the query so
/// that e.g. `include:spam` does not match events containing the words
/// "include" or "spam".
pub fn terms(search: &str) -> Vec<String> {
    // Bounded from both sides before any allocation: the byte window keeps
    // the whitespace scan cheap, and the per-token loop below stops as soon
    // as enough terms are collected. Processing whitespace-separated tokens
    // one at a time is equivalent to the old join-then-tokenize (the joiner
    // space is a tokenizer delimiter too) without ever materializing the
    // intermediate string or the full term vector.
    let search = floor_char_boundary(search, MAX_SEARCH_BYTES);
    let mut out = Vec::new();
    for token in search.split_whitespace() {
        if out.len() >= crate::db::SEARCH_MAX_TERMS {
            break;
        }
        if token.contains(':') {
            continue;
        }
        query_tokenize_capped(token, &mut out, crate::db::SEARCH_MAX_TERMS);
    }
    out
}

/// Whether any of `terms` appears in `content` as a whole word.
///
/// The word index stores whole words (see [`tokenize`]), so the per-event
/// check must compare whole words too: a substring check would match events
/// the index never returns (e.g. the term "ru" against the indexed word
/// "rust"), making search results depend on whether the word index is
/// enabled. With whole-word matching the index, the non-indexed fallback
/// scan and the live delivery all agree.
pub fn matches_terms(content: &str, terms: &[String]) -> bool {
    if terms.is_empty() {
        return true;
    }
    let words = tokenize(content);
    terms.iter().any(|t| words.iter().any(|w| w == t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer() {
        // Numeric-only words are not indexed (they dominate the word
        // index of machine-generated content and bloat the random
        // inserts); mixed words are.
        assert_eq!(tokenize("Hello, World! 123"), vec!["hello", "world"]);
        assert_eq!(tokenize("a bc"), vec!["bc"]);
        assert_eq!(tokenize("2023 nostr"), vec!["nostr"]);
        assert_eq!(tokenize("nostr 2023"), vec!["nostr"]);
        assert_eq!(tokenize("abc123 def"), vec!["abc123", "def"]);
        assert_eq!(tokenize("12ab 34"), vec!["12ab"]);
        assert_eq!(tokenize("I have 123 apples"), vec!["have", "apples"]);
        assert!(tokenize("").is_empty());
        assert!(tokenize("  !!!  ").is_empty());
    }

    #[test]
    fn query_terms_keep_numeric_words() {
        // The query side keeps numeric words: a search for "nostr 2023"
        // walks the index on "nostr" (numeric words are not indexed); the
        // per-event match requires any one term, so "2023" does not act as
        // an additional constraint. A numeric-only query yields terms (which
        // the index walk cannot satisfy — no results — instead of the
        // "no search" fallback that would match everything).
        assert_eq!(terms("nostr 2023"), vec!["nostr", "2023"]);
        assert_eq!(terms("123"), vec!["123"]);
        assert_eq!(terms("include:spam 2023"), vec!["2023"]);
    }

    #[test]
    fn terms_lowercase() {
        assert_eq!(terms("Rust Nostr"), vec!["rust", "nostr"]);
    }

    #[test]
    fn key_value_extensions_are_ignored() {
        // NIP-50: `key:value` pairs are extensions; unsupported ones are
        // dropped instead of being matched as ordinary words.
        assert_eq!(terms("include:spam"), Vec::<String>::new());
        assert_eq!(terms("nostr include:spam"), vec!["nostr"]);
        assert_eq!(terms("domain:example.com rust"), vec!["rust"]);
        // A colon inside a larger token is an extension too.
        assert_eq!(terms("a:b:c"), Vec::<String>::new());
        // Normal queries are untouched.
        assert_eq!(terms("best nostr apps"), vec!["best", "nostr", "apps"]);
    }

    #[test]
    fn terms_are_bounded_by_bytes_and_count() {
        // A pathological search string must not fan out: the term vector
        // stops at SEARCH_MAX_TERMS even with far more candidates.
        let huge = "ab ".repeat(500_000);
        let got = terms(&huge);
        assert_eq!(got.len(), crate::db::SEARCH_MAX_TERMS);
        // Only the leading byte window is examined.
        let mut long = "zz ".repeat(10_000);
        long.push_str("uniqueword");
        assert!(
            !terms(&long).iter().any(|t| t == "uniqueword"),
            "terms past the byte window must be ignored"
        );
        // Ordinary queries are untouched.
        assert_eq!(terms("nostr 2023"), vec!["nostr", "2023"]);
    }

    #[test]
    fn whole_word_matching() {
        let terms = super::terms("ru");
        // "ru" must not match "rust" as a substring: the word index stores
        // whole words, so the per-event check must agree with it.
        assert!(!matches_terms("rust", &terms));
        assert!(matches_terms("ru matters", &terms));
        // Any of several terms suffices.
        assert!(matches_terms(
            "only bitcoin",
            &super::terms("nostr bitcoin")
        ));
        assert!(!matches_terms("neither", &super::terms("nostr bitcoin")));
    }
}
