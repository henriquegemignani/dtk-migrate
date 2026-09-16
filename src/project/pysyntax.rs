//! Just enough Python syntax to edit `configure.py` safely.
//!
//! The only thing this tool changes in a project's build script is the matching
//! status of an `Object(...)` declaration, and the only thing it reads is a list
//! of version strings. A full Python parser would be a lot of machinery for
//! that, but a regex would be worse than useless: `Object(` inside a comment or
//! a docstring is not a declaration, and a status argument can be a call whose
//! own parentheses have to be balanced before the path argument begins.
//!
//! So: a scanner that knows where strings and comments are, and can walk
//! balanced delimiters. Everything it does not recognise, it refuses to touch —
//! a declaration this cannot express is reported, never rewritten into
//! something weaker or stronger than the evidence supports.

/// What a byte of source belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Span {
    /// Ordinary code, including the delimiters this scanner walks.
    Code,
    /// Inside a string literal, quote characters included.
    Text,
    /// Inside a comment, the `#` included.
    Comment,
}

/// Byte-for-byte classification of a Python source file.
///
/// The distinction between [`Span::Text`] and [`Span::Comment`] matters more
/// than it looks: a comment between two arguments is noise to be stepped over,
/// while a string is the argument itself.
#[derive(Debug, Clone)]
pub struct Mask(Vec<Span>);

impl Mask {
    pub fn of(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut spans = vec![Span::Code; bytes.len()];
        let mut index = 0;

        while index < bytes.len() {
            match bytes[index] {
                b'#' => {
                    while index < bytes.len() && bytes[index] != b'\n' {
                        spans[index] = Span::Comment;
                        index += 1;
                    }
                }
                b'"' | b'\'' => {
                    let quote = bytes[index];
                    // A triple quote runs to the matching triple, across lines.
                    let triple = bytes[index..].starts_with(&[quote, quote, quote]);
                    let delimiter = if triple { 3 } else { 1 };
                    for offset in 0..delimiter {
                        spans[index + offset] = Span::Text;
                    }
                    index += delimiter;
                    while index < bytes.len() {
                        // A backslash escapes the next byte even in a raw
                        // string: `r"\""` is one string, not two. Raw-ness
                        // changes what the escape means, not where it ends.
                        if bytes[index] == b'\\' && index + 1 < bytes.len() {
                            spans[index] = Span::Text;
                            spans[index + 1] = Span::Text;
                            index += 2;
                            continue;
                        }
                        if bytes[index] == quote
                            && (!triple || bytes[index..].starts_with(&[quote, quote, quote]))
                        {
                            for offset in 0..delimiter {
                                if index + offset < bytes.len() {
                                    spans[index + offset] = Span::Text;
                                }
                            }
                            index += delimiter;
                            break;
                        }
                        // An unterminated single-quoted string ends at the
                        // newline; anything else swallows the rest of the file.
                        if !triple && bytes[index] == b'\n' {
                            break;
                        }
                        spans[index] = Span::Text;
                        index += 1;
                    }
                }
                _ => index += 1,
            }
        }
        Self(spans)
    }

    pub fn len(&self) -> usize { self.0.len() }

    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    pub fn at(&self, index: usize) -> Span { self.0.get(index).copied().unwrap_or(Span::Code) }

    pub fn is_code(&self, index: usize) -> bool { self.at(index) == Span::Code }

    pub fn is_comment(&self, index: usize) -> bool { self.at(index) == Span::Comment }
}

/// The same text with every comment removed and string literals left intact.
pub fn strip_comments(text: &str) -> String {
    let mask = Mask::of(text);
    text.char_indices().filter(|(index, _)| !mask.is_comment(*index)).map(|(_, c)| c).collect()
}

fn is_identifier_byte(byte: u8) -> bool { byte.is_ascii_alphanumeric() || byte == b'_' }

/// Byte offsets where `name` appears as a complete identifier in code.
pub fn find_identifier(text: &str, mask: &Mask, name: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = text[from..].find(name) {
        let start = from + offset;
        from = start + 1;
        let end = start + name.len();
        if !(start..end).all(|index| mask.is_code(index)) {
            continue;
        }
        if start > 0 && is_identifier_byte(bytes[start - 1]) {
            continue;
        }
        if end < bytes.len() && is_identifier_byte(bytes[end]) {
            continue;
        }
        found.push(start);
    }
    found
}

/// The first byte at or after `from` that is code and not whitespace, stepping
/// over any comment in the way.
pub fn skip_space(text: &str, mask: &Mask, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    (from..bytes.len()).find(|&index| mask.is_code(index) && !bytes[index].is_ascii_whitespace())
}

/// Given the offset of an opening delimiter, the offset of its match.
#[allow(clippy::needless_range_loop)] // the absolute offset is the result
pub fn matching_delimiter(text: &str, mask: &Mask, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    for index in open..bytes.len() {
        if !mask.is_code(index) {
            continue;
        }
        match bytes[index] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Splits the inside of a bracketed group into its top-level, comma-separated
/// argument ranges, each trimmed of surrounding whitespace and comments.
///
/// A trailing comma produces no empty final argument, matching Python.
#[allow(clippy::needless_range_loop)] // the absolute offsets are the result
pub fn split_arguments(text: &str, mask: &Mask, open: usize, close: usize) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut arguments = Vec::new();
    let mut depth = 0usize;
    let mut start = open + 1;
    for index in (open + 1)..close {
        if !mask.is_code(index) {
            continue;
        }
        match bytes[index] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                if let Some(range) = trim(text, mask, start, index) {
                    arguments.push(range);
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    if let Some(range) = trim(text, mask, start, close) {
        arguments.push(range);
    }
    arguments
}

/// Narrows a range to its content: no leading or trailing whitespace, and no
/// comment on either end.
fn trim(text: &str, mask: &Mask, start: usize, end: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let (mut start, mut end) = (start, end);
    let skippable = |index: usize| bytes[index].is_ascii_whitespace() || mask.is_comment(index);
    while start < end && skippable(start) {
        start += 1;
    }
    while end > start && skippable(end - 1) {
        end -= 1;
    }
    (start < end).then_some((start, end))
}

/// Reads a range that must be exactly one plain string literal, returning its
/// value.
///
/// Prefixed literals (`f`, `b`, `r`) and implicit concatenation are rejected
/// rather than guessed at: a path we cannot reproduce verbatim is a path we
/// cannot safely match against a build report.
pub fn string_literal(text: &str, start: usize, end: usize) -> Option<String> {
    let slice = &text[start..end];
    let bytes = slice.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let quote = bytes[0];
    if (quote != b'"' && quote != b'\'') || bytes[bytes.len() - 1] != quote {
        return None;
    }
    let inner = &slice[1..slice.len() - 1];
    let mut value = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            // A bare quote inside means this was two adjacent literals, not one.
            if c as u32 == quote as u32 {
                return None;
            }
            value.push(c);
            continue;
        }
        match chars.next()? {
            'n' => value.push('\n'),
            't' => value.push('\t'),
            'r' => value.push('\r'),
            '\\' => value.push('\\'),
            '\'' => value.push('\''),
            '"' => value.push('"'),
            // Anything more exotic has no business in a source path.
            _ => return None,
        }
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(text: &str) -> String {
        let mask = Mask::of(text);
        text.char_indices()
            .map(|(i, c)| match mask.at(i) {
                Span::Code => c,
                Span::Text => '.',
                Span::Comment => '-',
            })
            .collect()
    }

    #[test]
    fn a_comment_is_not_code() {
        assert_eq!(masked("a = 1  # Object(x)\nb = 2"), "a = 1  -----------\nb = 2");
    }

    #[test]
    fn a_string_is_not_code_but_its_surroundings_are() {
        assert_eq!(masked("f(\"a#b\")"), "f(.....)");
    }

    #[test]
    fn a_triple_quoted_string_spans_lines() {
        assert_eq!(masked("x = \"\"\"a\nb\"\"\"\ny"), "x = .........\ny");
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        assert_eq!(masked(r#"f("a\"b")"#), "f(......)");
    }

    #[test]
    fn stripping_comments_keeps_strings() {
        assert_eq!(strip_comments("f(\"a # b\")  # gone"), "f(\"a # b\")  ");
    }

    #[test]
    fn an_identifier_inside_a_comment_is_not_found() {
        let text = "# Object(a, \"x\")\nObject(b, \"y\")";
        assert_eq!(find_identifier(text, &Mask::of(text), "Object"), vec![17]);
    }

    #[test]
    fn an_identifier_that_is_part_of_a_longer_name_is_not_found() {
        let text = "MyObject(a)\nObject(b)";
        assert_eq!(find_identifier(text, &Mask::of(text), "Object"), vec![12]);
    }

    #[test]
    fn arguments_split_at_the_top_level_only() {
        let text = "Object(MatchingFor(\"A\", \"B\"), \"path.cpp\")";
        let mask = Mask::of(text);
        let open = text.find('(').unwrap();
        let close = matching_delimiter(text, &mask, open).unwrap();
        let arguments = split_arguments(text, &mask, open, close);
        assert_eq!(arguments.len(), 2);
        assert_eq!(&text[arguments[0].0..arguments[0].1], "MatchingFor(\"A\", \"B\")");
        assert_eq!(&text[arguments[1].0..arguments[1].1], "\"path.cpp\"");
    }

    #[test]
    fn a_comment_between_arguments_is_not_part_of_either() {
        let text = "[\n    \"NTSC\",  # first\n    \"PAL\",\n]";
        let mask = Mask::of(text);
        let close = matching_delimiter(text, &mask, 0).unwrap();
        let arguments = split_arguments(text, &mask, 0, close);
        assert_eq!(arguments.len(), 2);
        assert_eq!(&text[arguments[1].0..arguments[1].1], "\"PAL\"");
    }

    #[test]
    fn a_comma_inside_a_string_does_not_split_arguments() {
        let text = "Object(NonMatching, \"a,b.cpp\")";
        let mask = Mask::of(text);
        let open = text.find('(').unwrap();
        let close = matching_delimiter(text, &mask, open).unwrap();
        assert_eq!(split_arguments(text, &mask, open, close).len(), 2);
    }

    #[test]
    fn a_trailing_comma_adds_no_argument() {
        let text = "f(a, b,)";
        let mask = Mask::of(text);
        let close = matching_delimiter(text, &mask, 1).unwrap();
        assert_eq!(split_arguments(text, &mask, 1, close).len(), 2);
    }

    #[test]
    fn a_plain_literal_reads_back_as_its_value() {
        assert_eq!(string_literal("\"a/b.cpp\"", 0, 9).as_deref(), Some("a/b.cpp"));
    }

    #[test]
    fn a_prefixed_or_concatenated_literal_is_refused() {
        assert_eq!(string_literal("f\"x\"", 0, 4), None);
        assert_eq!(string_literal("\"a\" \"b\"", 0, 7), None);
    }
}
