//! Parsing of `@import` directives inside `AGENTS.md` documents.
//!
//! An `@path` directive lets a project memory file pull in other files, so
//! shared guidance can live in one place and be referenced from many. Codex's
//! `AGENTS.md` loader (see [`crate::agents_md`]) historically only concatenated
//! the files found along the project-root → cwd path, with no way to factor
//! common instructions out into an included file. This module supplies the
//! missing first half of that feature: a pure,
//! dependency-free parser that extracts the import targets from a document.
//!
//! Recursive expansion (reading the referenced files, enforcing the byte
//! budget, and breaking cycles) is layered on top by the loader, which owns
//! the async filesystem handle. Keeping the parser pure makes its behavior
//! exhaustively testable without any I/O.
//!
//! ## Directive syntax
//!
//! A directive is a line whose content, after stripping leading whitespace and
//! an optional Markdown list marker (`-`, `*`, or `+`), begins with `@`
//! immediately followed by a path token. The token runs to the next ASCII
//! whitespace character; a single trailing sentence punctuation character
//! (`.`, `,`, `;`, `:`, `)`) is dropped so prose like `see @docs/style.md.`
//! resolves to `docs/style.md`.
//!
//! To avoid matching social handles and email addresses (`@acme-org/sdk`,
//! `me@example.com`), a token only counts as an import when it *looks like a
//! path*: it contains a `/` separator or ends in a recognized documentation
//! extension (`.md`, `.markdown`, `.txt`). Directives inside fenced code
//! blocks (```` ``` ```` or `~~~`) are ignored so example snippets are never
//! treated as imports.

/// A recognized documentation extension that, on its own, qualifies a bare
/// token (no `/`) as an import path.
const DOC_EXTENSIONS: [&str; 3] = [".md", ".markdown", ".txt"];

/// Trailing characters trimmed from an import token so surrounding prose
/// punctuation does not leak into the path.
const TRAILING_PUNCTUATION: [char; 5] = ['.', ',', ';', ':', ')'];

/// Extracts the ordered, de-duplicated list of `@import` targets from a
/// Markdown document.
///
/// Paths are returned exactly as written (the leading `@` removed), preserving
/// relative/absolute/`~` forms for the caller to resolve. The first occurrence
/// of a duplicate path wins and later repeats are dropped, so a file imported
/// from two directives is only read once.
pub(crate) fn parse_import_directives(markdown: &str) -> Vec<String> {
    let mut imports: Vec<String> = Vec::new();
    let mut in_fenced_block = false;

    for line in markdown.lines() {
        let trimmed = line.trim_start();

        if is_code_fence(trimmed) {
            in_fenced_block = !in_fenced_block;
            continue;
        }
        if in_fenced_block {
            continue;
        }

        let Some(path) = import_path_from_line(trimmed) else {
            continue;
        };
        if !imports.iter().any(|existing| existing == &path) {
            imports.push(path);
        }
    }

    imports
}

/// Returns true when `trimmed` opens or closes a fenced code block.
fn is_code_fence(trimmed: &str) -> bool {
    trimmed.starts_with("```") || trimmed.starts_with("~~~")
}

/// Extracts a single import path from one already-left-trimmed line, if the
/// line is an import directive.
fn import_path_from_line(trimmed: &str) -> Option<String> {
    let candidate = strip_list_marker(trimmed);
    let rest = candidate.strip_prefix('@')?;

    // The token ends at the first whitespace; a directive carries exactly one
    // path, so anything after it is ignored.
    let token = rest.split_whitespace().next().unwrap_or("");
    let token = token.trim_end_matches(TRAILING_PUNCTUATION);

    if token.is_empty() || !looks_like_path(token) {
        return None;
    }
    Some(token.to_string())
}

/// Strips a single leading Markdown list marker (`- `, `* `, or `+ `) so an
/// import can be written as a bullet item.
fn strip_list_marker(trimmed: &str) -> &str {
    for marker in ['-', '*', '+'] {
        if let Some(rest) = trimmed.strip_prefix(marker)
            && let Some(rest) = rest.strip_prefix(' ')
        {
            return rest.trim_start();
        }
    }
    trimmed
}

/// Heuristic that distinguishes an import path from a social handle or email.
fn looks_like_path(token: &str) -> bool {
    if token.contains('/') {
        return true;
    }
    let lowered = token.to_ascii_lowercase();
    DOC_EXTENSIONS
        .iter()
        .any(|extension| lowered.ends_with(extension))
}

#[cfg(test)]
mod tests {
    use super::parse_import_directives;

    #[test]
    fn extracts_simple_and_bulleted_imports() {
        let doc = "\
# Project guidance

@./docs/style.md

Some prose.

- @../shared/AGENTS.md
* @~/global-rules.md
";
        assert_eq!(
            parse_import_directives(doc),
            vec![
                "./docs/style.md".to_string(),
                "../shared/AGENTS.md".to_string(),
                "~/global-rules.md".to_string(),
            ]
        );
    }

    #[test]
    fn ignores_directives_inside_fenced_code_blocks() {
        let doc = "\
Real import:

@real/import.md

```
@not/an/import.md
```

~~~
@also/ignored.md
~~~
";
        assert_eq!(
            parse_import_directives(doc),
            vec!["real/import.md".to_string()]
        );
    }

    #[test]
    fn does_not_match_handles_or_emails() {
        let doc = "\
Thanks @acme-org and contact me@example.com for questions.
@org-handle
";
        assert!(parse_import_directives(doc).is_empty());
    }

    #[test]
    fn trims_trailing_directive_punctuation() {
        // A directive line may end with sentence punctuation; it is trimmed off
        // the resolved path.
        let doc = "@docs/style.md.\n@docs/testing.md;";
        assert_eq!(
            parse_import_directives(doc),
            vec!["docs/style.md".to_string(), "docs/testing.md".to_string()]
        );
    }

    #[test]
    fn ignores_at_tokens_embedded_in_prose() {
        // Imports are directive lines, not any `@token` mentioned mid-sentence,
        // so prose that references a path is never silently pulled in.
        let doc = "See @docs/style.md for the rules.";
        assert!(parse_import_directives(doc).is_empty());
    }

    #[test]
    fn deduplicates_preserving_first_occurrence() {
        let doc = "\
@docs/style.md
@other/file.md
@docs/style.md
";
        assert_eq!(
            parse_import_directives(doc),
            vec!["docs/style.md".to_string(), "other/file.md".to_string()]
        );
    }

    #[test]
    fn returns_empty_when_no_directives_present() {
        let doc = "# Heading\n\nJust ordinary prose with no imports.\n";
        assert!(parse_import_directives(doc).is_empty());
    }

    #[test]
    fn requires_path_shape_for_bare_tokens() {
        // A bare token with no separator and no doc extension is not an import.
        assert!(parse_import_directives("@README").is_empty());
        // ...but a doc-extension token is, even without a separator.
        assert_eq!(
            parse_import_directives("@README.md"),
            vec!["README.md".to_string()]
        );
    }
}
