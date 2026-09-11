//! Streaming filter for terminal control sequences emitted by sandboxed code.

/// Hard cap for a pending control sequence. Prevents malformed output from
/// growing the filter buffer without bound.
pub(crate) const OSC_MAX_LEN: usize = 1 << 20;

/// Queries that are safe only in explicit terminal-passthrough mode.
pub(crate) fn csi_final_forwardable(
    final_byte: u8,
    prefix: Option<u8>,
) -> bool {
    match final_byte {
        b'u' => matches!(prefix, Some(b'>' | b'<' | b'?')),
        b'c' => true,
        b'q' => prefix == Some(b'>'),
        _ => false,
    }
}

/// Whether a complete CSI sequence is the cursor-position request `ESC [ 6 n`.
/// ConPTY sends exactly that form; parameterised variants are not recognised.
fn cursor_position_query(pending: &[u8]) -> bool {
    let start = if pending[0] == 0x9b { 1 } else { 2 };
    pending.get(start..pending.len() - 1) == Some(b"6".as_slice())
}

/// Conservative recognition of replies produced by a real terminal.
pub(crate) fn looks_like_terminal_reply(data: &[u8]) -> bool {
    (data.starts_with(b"\x1b[") || data.starts_with(&[0x9b]))
        && data.last().is_some_and(|b| matches!(b, b'R' | b'c' | b'n'))
        || data.starts_with(b"\x1bP")
        || data
            .first()
            .is_some_and(|b| matches!(b, 0x90 | 0x9d | 0x9e | 0x9f))
}

enum FilterState {
    Ground,
    Esc,
    Csi,
    String,
    StringEsc,
    /// Inside `ESC %` — a character-set designation, dropped whole.
    Charset,
}

/// Retains text and display controls while dropping OSC, DCS, APC, PM, and
/// terminal capability queries.
///
/// The child's output is UTF-8. A byte in `0x80..=0x9f` is only an 8-bit C1
/// control when it stands on its own; inside a multi-byte character it is a
/// continuation byte and must pass through untouched. The block characters
/// U+2590..U+259F (`▐▛▜▝…`, the Claude Code logo) encode as `E2 96 90..9F`,
/// so without that distinction the filter mistook them for DCS/CSI/OSC
/// introducers and a C1 ST, swallowing rows of the banner and leaking the
/// tail of the window-title OSC as text.
pub(crate) struct TerminalFilter {
    state: FilterState,
    pending: Vec<u8>,
    /// Continuation bytes still expected for the UTF-8 character in
    /// progress; while non-zero, `0x80..=0xbf` is character data.
    utf8_remaining: u8,
    /// Cursor-position requests dropped since the last drain. ConPTY opens
    /// by asking the host where the cursor is and withholds every byte the
    /// child writes until it is answered, so the caller has to reply on the
    /// terminal's behalf instead of forwarding the query to it.
    cursor_reports: u32,
}

impl TerminalFilter {
    pub(crate) fn new() -> Self {
        Self {
            state: FilterState::Ground,
            pending: Vec::new(),
            utf8_remaining: 0,
            cursor_reports: 0,
        }
    }

    /// Take the cursor-position requests seen since the last call.
    pub(crate) fn take_cursor_reports(&mut self) -> u32 {
        std::mem::take(&mut self.cursor_reports)
    }

    /// Track UTF-8 sequence boundaries. Returns `true` when `byte` is part
    /// of a multi-byte character (lead or continuation byte) and must be
    /// treated as plain data rather than a C1 control.
    fn utf8_char_byte(&mut self, byte: u8) -> bool {
        if self.utf8_remaining > 0 {
            if (0x80..=0xbf).contains(&byte) {
                self.utf8_remaining -= 1;
                return true;
            }
            // Truncated sequence: `byte` stands on its own.
            self.utf8_remaining = 0;
        }
        self.utf8_remaining = match byte {
            0xc2..=0xdf => 1,
            0xe0..=0xef => 2,
            0xf0..=0xf4 => 3,
            _ => 0,
        };
        self.utf8_remaining > 0
    }

    pub(crate) fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &byte in data {
            if self.utf8_char_byte(byte) {
                // Character data: never an introducer or terminator.
                match self.state {
                    FilterState::Ground => out.push(byte),
                    FilterState::Esc => {
                        self.pending.push(byte);
                        out.extend_from_slice(&self.pending);
                        self.pending.clear();
                        self.state = FilterState::Ground;
                    }
                    FilterState::Csi => {
                        self.pending.push(byte);
                        if self.pending.len() > OSC_MAX_LEN {
                            self.pending.clear();
                            self.state = FilterState::Ground;
                        }
                    }
                    FilterState::String => {}
                    FilterState::StringEsc => {
                        self.state = FilterState::String;
                    }
                    // Payload bytes here are ASCII in practice; drop any
                    // stray byte with the rest of the sequence.
                    FilterState::Charset => self.state = FilterState::Ground,
                }
                continue;
            }
            match self.state {
                FilterState::Ground => {
                    if byte == 0x1b {
                        self.pending.push(byte);
                        self.state = FilterState::Esc;
                    } else if byte == 0x9b {
                        self.pending.push(byte);
                        self.state = FilterState::Csi;
                    } else if matches!(byte, 0x90 | 0x9d | 0x9e | 0x9f) {
                        self.state = FilterState::String;
                    } else {
                        out.push(byte);
                    }
                }
                FilterState::Esc => match byte {
                    b'[' => {
                        self.pending.push(byte);
                        self.state = FilterState::Csi;
                    }
                    // `ESC % @` returns the terminal to ISO 8859-1, where
                    // 0x80..=0x9f are C1 controls again. Everything below
                    // assumes the terminal stays in UTF-8 mode — that is what
                    // makes it safe to pass a continuation byte through as
                    // character data — so the sequence that revokes the
                    // assumption has to go. Dropped rather than forwarded:
                    // ai-jail always speaks UTF-8 to the terminal.
                    b'%' => {
                        self.pending.clear();
                        self.state = FilterState::Charset;
                    }
                    b']' | b'P' | b'X' | b'^' | b'_' => {
                        self.pending.clear();
                        self.state = FilterState::String;
                    }
                    _ => {
                        self.pending.push(byte);
                        out.extend_from_slice(&self.pending);
                        self.pending.clear();
                        self.state = FilterState::Ground;
                    }
                },
                // `ESC % / F` designates a multi-byte set; `/` means one
                // more byte follows. Anything else ends the sequence.
                FilterState::Charset => {
                    if byte != b'/' {
                        self.state = FilterState::Ground;
                    }
                }
                FilterState::Csi => {
                    self.pending.push(byte);
                    if (0x40..=0x7e).contains(&byte) {
                        let prefix = self
                            .pending
                            .get(if self.pending[0] == 0x9b { 1 } else { 2 })
                            .copied()
                            .filter(|p| matches!(p, b'>' | b'<' | b'?'));
                        if byte == b'n'
                            && prefix.is_none()
                            && cursor_position_query(&self.pending)
                        {
                            self.cursor_reports += 1;
                        }
                        if !csi_final_forwardable(byte, prefix) && byte != b'n'
                        {
                            out.extend_from_slice(&self.pending);
                        }
                        self.pending.clear();
                        self.state = FilterState::Ground;
                    } else if self.pending.len() > OSC_MAX_LEN {
                        self.pending.clear();
                        self.state = FilterState::Ground;
                    }
                }
                FilterState::String => match byte {
                    0x07 | 0x9c => self.state = FilterState::Ground,
                    0x1b => self.state = FilterState::StringEsc,
                    _ => {}
                },
                FilterState::StringEsc => {
                    self.state = if byte == b'\\' || byte == 0x9c {
                        FilterState::Ground
                    } else if byte == 0x1b {
                        FilterState::StringEsc
                    } else {
                        FilterState::String
                    };
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_terminal_queries_and_strings_but_keeps_display_controls() {
        let mut filter = TerminalFilter::new();
        assert_eq!(
            filter.feed(b"ok\x1b[31mred\x1b[0m\x1b[c\x1b]52;c;secret\x07done"),
            b"ok\x1b[31mred\x1b[0mdone"
        );
    }

    #[test]
    fn handles_sequences_split_across_reads() {
        let mut filter = TerminalFilter::new();
        assert_eq!(filter.feed(b"before\x1b]52;c;sec"), b"before");
        assert_eq!(filter.feed(b"ret\x07after"), b"after");
    }

    #[test]
    fn passes_utf8_block_characters_through() {
        // U+2590..U+259F encode as E2 96 90..9F: the continuation bytes
        // coincide with the C1 DCS (0x90), CSI (0x9b), ST (0x9c), OSC
        // (0x9d) codes. The Claude Code logo is drawn with them.
        let mut filter = TerminalFilter::new();
        let logo = " ▐\x1b[48;2;0;0;0m▛████▜█\x1b[12G\x1b[1mClaude\x1b[19GCode"
            .as_bytes();
        assert_eq!(filter.feed(logo), logo);
        assert_eq!(filter.feed("😀 ok".as_bytes()), "😀 ok".as_bytes());
    }

    #[test]
    fn utf8_character_split_across_reads() {
        let mut filter = TerminalFilter::new();
        assert_eq!(filter.feed(b"\xe2\x96"), b"\xe2\x96");
        // 0x9c here is the last byte of U+259C, not a C1 ST.
        assert_eq!(filter.feed(b"\x9c rest"), b"\x9c rest");
    }

    #[test]
    fn drops_osc_title_with_utf8_payload_whole() {
        // OSC 0 with "✳" (E2 9C B3) in the title: the 0x9c continuation
        // byte used to terminate the string early and leak the tail as text.
        let mut filter = TerminalFilter::new();
        assert_eq!(
            filter.feed("\x1b]0;✳ Claude Code\x07after".as_bytes()),
            b"after"
        );
    }

    #[test]
    fn c1_after_complete_utf8_char_is_still_recognized() {
        let mut filter = TerminalFilter::new();
        assert_eq!(filter.feed(b"\xc3\xa9\x9d0;evil\x07ok"), b"\xc3\xa9ok");
    }

    #[test]
    fn counts_the_cursor_position_requests_it_drops() {
        // ConPTY withholds every byte the child writes until this query is
        // answered, so dropping it without recording it deadlocks the proxy.
        let mut filter = TerminalFilter::new();
        assert_eq!(filter.feed(b"\x1b[6n"), b"");
        assert_eq!(filter.take_cursor_reports(), 1);
        assert_eq!(filter.take_cursor_reports(), 0);
        assert_eq!(filter.feed(b"a\x1b[6"), b"a");
        assert_eq!(filter.take_cursor_reports(), 0);
        assert_eq!(filter.feed(b"n\x1b[6nb"), b"b");
        assert_eq!(filter.take_cursor_reports(), 2);
    }

    #[test]
    fn other_status_reports_are_not_cursor_queries() {
        let mut filter = TerminalFilter::new();
        assert_eq!(filter.feed(b"\x1b[5n\x1b[?6n\x1b[n\x1b[16n"), b"");
        assert_eq!(filter.take_cursor_reports(), 0);
    }

    #[test]
    fn drops_charset_designation() {
        // `ESC % @` returns the terminal to ISO 8859-1, where 0x80..=0x9f
        // are C1 controls again, so an agent could smuggle a C1 CSI through
        // as a UTF-8 continuation byte.
        let mut filter = TerminalFilter::new();
        assert_eq!(filter.feed(b"\x1b%@"), b"");
        assert_eq!(filter.feed(b"\x1b%G"), b"");
        // `ESC % / F` designates a multi-byte set: three bytes after ESC.
        assert_eq!(filter.feed(b"\x1b%/4"), b"");
        assert_eq!(filter.feed(b"ok\x1b%@done"), b"okdone");
        assert_eq!(filter.feed(b"\x1b%@\xe2\x96\x9c"), b"\xe2\x96\x9c");
    }
}
