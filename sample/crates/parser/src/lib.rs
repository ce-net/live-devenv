//! A small parser for `key = value` lines.

pub fn parse_line(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once('=')?;
    Some((k.trim().to_string(), v.trim().to_string()))
}

pub fn count_pairs(text: &str) -> usize {
    text.lines().filter(|l| !is_comment(l) && parse_line(l).is_some()).count()
}

pub fn keys(text: &str) -> Vec<String> {
    text.lines().filter(|l| !is_comment(l)).filter_map(parse_line).map(|(k, _)| k).collect()
}

pub fn is_comment(line: &str) -> bool {
    line.starts_with('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_pair() {
        assert_eq!(parse_line("a = 1"), Some(("a".into(), "1".into())));
    }

    #[test]
    fn counts_pairs() {
        assert_eq!(count_pairs("a = 1\nb = 2\n# c = 3\n"), 2);
    }

    #[test]
    fn indented_comment_is_a_comment() {
        assert!(is_comment("    # note = 1"));
    }
}
