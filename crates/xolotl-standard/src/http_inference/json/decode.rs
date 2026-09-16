//! Pull-independent JSON grammar. Scratch grows only with active nesting.

use super::{Utf8, invalid};
use crate::http_inference::error::HttpInferenceError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::http_inference) enum Kind {
    Object,
    Array,
    String,
    Number,
    True,
    False,
    Null,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::http_inference) enum Event<'a> {
    Start(Kind),
    End(Kind),
    KeyStart,
    KeyEnd,
    Data(&'a [u8]),
}

type Result<T> = std::result::Result<T, HttpInferenceError>;

pub(in crate::http_inference) struct Decoder {
    frames: Vec<Frame>,
    mode: Mode,
    root: bool,
    utf8: Utf8,
    max_frames: Option<usize>,
}

#[derive(Clone, Copy)]
struct Frame {
    kind: Kind,
    state: State,
}

#[derive(Clone, Copy)]
enum State {
    KeyOrEnd,
    Key,
    Colon,
    Value,
    ValueOrEnd,
    AfterValue,
}

#[derive(Clone, Copy)]
enum Mode {
    Syntax,
    String { key: bool, escape: Escape },
    Number(Number),
    Literal { kind: Kind, offset: usize },
}

#[derive(Clone, Copy)]
enum Escape {
    None,
    Slash,
    Unicode { digits: u8, value: u16 },
    LowSlash(u16),
    LowU(u16),
    LowUnicode { high: u16, digits: u8, value: u16 },
}

#[derive(Clone, Copy)]
enum Number {
    Minus,
    Zero,
    Integer,
    Dot,
    Fraction,
    E,
    Sign,
    Exponent,
}

impl Decoder {
    pub(in crate::http_inference) fn new(max_frames: Option<usize>) -> Self {
        Self {
            frames: Vec::new(),
            mode: Mode::Syntax,
            root: false,
            utf8: Utf8::default(),
            max_frames,
        }
    }

    pub(in crate::http_inference) fn push(
        &mut self,
        mut bytes: &[u8],
        mut emit: impl FnMut(Event<'_>) -> Result<()>,
    ) -> Result<()> {
        self.utf8.push(bytes)?;
        while let Some(&byte) = bytes.first() {
            match self.mode {
                Mode::String {
                    key,
                    escape: Escape::None,
                } => {
                    let plain = bytes
                        .iter()
                        .position(|byte| *byte == b'"' || *byte == b'\\' || *byte < 0x20)
                        .unwrap_or(bytes.len());
                    if plain != 0 {
                        emit(Event::Data(&bytes[..plain]))?;
                        bytes = &bytes[plain..];
                        continue;
                    }
                    match byte {
                        b'"' => {
                            self.mode = Mode::Syntax;
                            emit(if key {
                                Event::KeyEnd
                            } else {
                                Event::End(Kind::String)
                            })?;
                        }
                        b'\\' => {
                            self.mode = Mode::String {
                                key,
                                escape: Escape::Slash,
                            }
                        }
                        _ => return Err(invalid("unescaped control byte in JSON string")),
                    }
                }
                Mode::String { key, escape } => self.escape(key, escape, byte, &mut emit)?,
                Mode::Number(state) => {
                    if let Some(next) = state.advance(byte)? {
                        self.mode = Mode::Number(next);
                        emit(Event::Data(&bytes[..1]))?;
                    } else {
                        if !state.complete() {
                            return Err(invalid("unfinished JSON number"));
                        }
                        self.mode = Mode::Syntax;
                        emit(Event::End(Kind::Number))?;
                        continue;
                    }
                }
                Mode::Literal { kind, offset } => {
                    let literal = literal(kind);
                    if byte != literal[offset] {
                        return Err(invalid("invalid JSON literal"));
                    }
                    if offset + 1 == literal.len() {
                        self.mode = Mode::Syntax;
                        emit(Event::End(kind))?;
                    } else {
                        self.mode = Mode::Literal {
                            kind,
                            offset: offset + 1,
                        };
                    }
                }
                Mode::Syntax => {
                    if byte.is_ascii_whitespace() {
                        if !matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                            return Err(invalid("invalid JSON whitespace"));
                        }
                    } else {
                        self.syntax(byte, &mut emit)?;
                    }
                }
            }
            bytes = &bytes[1..];
        }
        Ok(())
    }

    pub(in crate::http_inference) fn finish(
        &mut self,
        mut emit: impl FnMut(Event<'_>) -> Result<()>,
    ) -> Result<()> {
        self.utf8.finish()?;
        if let Mode::Number(number) = self.mode {
            if !number.complete() {
                return Err(invalid("unfinished JSON number"));
            }
            self.mode = Mode::Syntax;
            emit(Event::End(Kind::Number))?;
        }
        if !self.root || !self.frames.is_empty() || !matches!(self.mode, Mode::Syntax) {
            return Err(invalid("unfinished JSON document"));
        }
        Ok(())
    }

    fn syntax(&mut self, byte: u8, emit: &mut impl FnMut(Event<'_>) -> Result<()>) -> Result<()> {
        if let Some(frame) = self.frames.last_mut() {
            match frame.state {
                State::KeyOrEnd if byte == b'}' => return self.close(Kind::Object, emit),
                State::ValueOrEnd if byte == b']' => return self.close(Kind::Array, emit),
                State::KeyOrEnd | State::Key => {
                    if byte != b'"' {
                        return Err(invalid("expected JSON object key"));
                    }
                    frame.state = State::Colon;
                    self.mode = Mode::String {
                        key: true,
                        escape: Escape::None,
                    };
                    return emit(Event::KeyStart);
                }
                State::Colon => {
                    if byte != b':' {
                        return Err(invalid("expected JSON colon"));
                    }
                    frame.state = State::Value;
                    return Ok(());
                }
                State::AfterValue => {
                    if byte == b',' {
                        frame.state = if frame.kind == Kind::Object {
                            State::Key
                        } else {
                            State::Value
                        };
                        return Ok(());
                    }
                    let closing = if frame.kind == Kind::Object {
                        b'}'
                    } else {
                        b']'
                    };
                    if byte != closing {
                        return Err(invalid("expected JSON separator or container end"));
                    }
                    let kind = frame.kind;
                    return self.close(kind, emit);
                }
                State::Value | State::ValueOrEnd => frame.state = State::AfterValue,
            }
        } else if self.root {
            return Err(invalid("trailing JSON data"));
        } else {
            self.root = true;
        }

        let kind = match byte {
            b'{' => Kind::Object,
            b'[' => Kind::Array,
            b'"' => Kind::String,
            b'-' | b'0'..=b'9' => Kind::Number,
            b't' => Kind::True,
            b'f' => Kind::False,
            b'n' => Kind::Null,
            _ => return Err(invalid("expected JSON value")),
        };
        emit(Event::Start(kind))?;
        self.mode = match kind {
            Kind::Object | Kind::Array => {
                if self.max_frames.is_some_and(|max| self.frames.len() >= max) {
                    return Err(invalid("JSON active-frame policy exceeded"));
                }
                self.frames.push(Frame {
                    kind,
                    state: if kind == Kind::Object {
                        State::KeyOrEnd
                    } else {
                        State::ValueOrEnd
                    },
                });
                Mode::Syntax
            }
            Kind::String => Mode::String {
                key: false,
                escape: Escape::None,
            },
            Kind::Number => {
                emit(Event::Data(&[byte]))?;
                Mode::Number(match byte {
                    b'-' => Number::Minus,
                    b'0' => Number::Zero,
                    _ => Number::Integer,
                })
            }
            _ => Mode::Literal { kind, offset: 1 },
        };
        Ok(())
    }

    fn close(&mut self, kind: Kind, emit: &mut impl FnMut(Event<'_>) -> Result<()>) -> Result<()> {
        self.frames.pop();
        emit(Event::End(kind))
    }

    fn escape(
        &mut self,
        key: bool,
        escape: Escape,
        byte: u8,
        emit: &mut impl FnMut(Event<'_>) -> Result<()>,
    ) -> Result<()> {
        let next = match escape {
            Escape::Slash => {
                if byte == b'u' {
                    Escape::Unicode {
                        digits: 0,
                        value: 0,
                    }
                } else {
                    let decoded = match byte {
                        b'"' | b'\\' | b'/' => byte,
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        _ => return Err(invalid("invalid JSON string escape")),
                    };
                    emit(Event::Data(&[decoded]))?;
                    Escape::None
                }
            }
            Escape::Unicode { digits, value } => {
                let value = (value << 4) | hex(byte)?;
                if digits < 3 {
                    Escape::Unicode {
                        digits: digits + 1,
                        value,
                    }
                } else if (0xd800..=0xdbff).contains(&value) {
                    Escape::LowSlash(value)
                } else {
                    emit_scalar(u32::from(value), emit)?;
                    Escape::None
                }
            }
            Escape::LowSlash(high) => {
                if byte != b'\\' {
                    return Err(invalid("missing low JSON surrogate"));
                }
                Escape::LowU(high)
            }
            Escape::LowU(high) => {
                if byte != b'u' {
                    return Err(invalid("missing low JSON surrogate"));
                }
                Escape::LowUnicode {
                    high,
                    digits: 0,
                    value: 0,
                }
            }
            Escape::LowUnicode {
                high,
                digits,
                value,
            } => {
                let value = (value << 4) | hex(byte)?;
                if digits < 3 {
                    Escape::LowUnicode {
                        high,
                        digits: digits + 1,
                        value,
                    }
                } else {
                    if !(0xdc00..=0xdfff).contains(&value) {
                        return Err(invalid("invalid low JSON surrogate"));
                    }
                    emit_scalar(
                        0x10000 + ((u32::from(high) - 0xd800) << 10) + u32::from(value) - 0xdc00,
                        emit,
                    )?;
                    Escape::None
                }
            }
            Escape::None => return Err(invalid("invalid JSON escape state")),
        };
        self.mode = Mode::String { key, escape: next };
        Ok(())
    }
}

impl Number {
    fn advance(self, byte: u8) -> Result<Option<Self>> {
        let digit = byte.is_ascii_digit();
        let next = match self {
            Self::Minus => match byte {
                b'0' => Self::Zero,
                b'1'..=b'9' => Self::Integer,
                _ => return Err(invalid("invalid JSON number")),
            },
            Self::Zero if digit => return Err(invalid("leading zero in JSON number")),
            Self::Integer if digit => Self::Integer,
            Self::Zero | Self::Integer if byte == b'.' => Self::Dot,
            Self::Dot if digit => Self::Fraction,
            Self::Fraction if digit => Self::Fraction,
            Self::Zero | Self::Integer | Self::Fraction if matches!(byte, b'e' | b'E') => Self::E,
            Self::E if matches!(byte, b'-' | b'+') => Self::Sign,
            Self::E | Self::Sign | Self::Exponent if digit => Self::Exponent,
            _ => return Ok(None),
        };
        Ok(Some(next))
    }
    fn complete(self) -> bool {
        matches!(
            self,
            Self::Zero | Self::Integer | Self::Fraction | Self::Exponent
        )
    }
}

fn literal(kind: Kind) -> &'static [u8] {
    match kind {
        Kind::True => b"true",
        Kind::False => b"false",
        _ => b"null",
    }
}

fn hex(byte: u8) -> Result<u16> {
    match byte {
        b'0'..=b'9' => Ok(u16::from(byte - b'0')),
        b'a'..=b'f' => Ok(u16::from(byte - b'a' + 10)),
        b'A'..=b'F' => Ok(u16::from(byte - b'A' + 10)),
        _ => Err(invalid("invalid JSON Unicode escape")),
    }
}

fn emit_scalar(value: u32, emit: &mut impl FnMut(Event<'_>) -> Result<()>) -> Result<()> {
    let scalar = char::from_u32(value).ok_or_else(|| invalid("unpaired JSON surrogate"))?;
    let mut bytes = [0; 4];
    emit(Event::Data(scalar.encode_utf8(&mut bytes).as_bytes()))
}
