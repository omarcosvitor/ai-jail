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
}

/// Retains text and display controls while dropping OSC, DCS, APC, PM, and
/// terminal capability queries.
pub(crate) struct TerminalFilter {
    state: FilterState,
    pending: Vec<u8>,
}

impl TerminalFilter {
    pub(crate) fn new() -> Self {
        Self {
            state: FilterState::Ground,
            pending: Vec::new(),
        }
    }

    pub(crate) fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &byte in data {
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
                FilterState::Csi => {
                    self.pending.push(byte);
                    if (0x40..=0x7e).contains(&byte) {
                        let prefix = self
                            .pending
                            .get(if self.pending[0] == 0x9b { 1 } else { 2 })
                            .copied()
                            .filter(|p| matches!(p, b'>' | b'<' | b'?'));
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
}
