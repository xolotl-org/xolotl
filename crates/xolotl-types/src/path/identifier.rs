//! Shared identifier rules for resident and fragmented path fields.

const STANDARD_SCHEMES: [&[u8]; 6] = [b"state", b"effect", b"process", b"proc", b"blob", b"tensor"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentifierKind {
    Scheme,
    Cluster,
    Segment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentifierError {
    Empty,
    Character,
    ReservedCluster,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Identifier {
    kind: IdentifierKind,
    position: u8,
    wildcards: u8,
    reserved: u8,
    invalid: bool,
}

impl Identifier {
    pub(crate) const fn new(kind: IdentifierKind) -> Self {
        Self {
            kind,
            position: 0,
            wildcards: 0,
            reserved: 0b11_1111,
            invalid: false,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), IdentifierError> {
        if self.invalid {
            return Err(IdentifierError::Character);
        }
        for &byte in bytes {
            let first = self.position == 0;
            let valid = match self.kind {
                IdentifierKind::Scheme if first => byte.is_ascii_alphabetic(),
                IdentifierKind::Scheme | IdentifierKind::Cluster => {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
                }
                IdentifierKind::Segment if self.wildcards > 0 || first && byte == b'*' => {
                    let valid = byte == b'*' && self.wildcards < 2;
                    self.wildcards += u8::from(valid);
                    valid
                }
                IdentifierKind::Segment if first => byte.is_ascii_alphanumeric(),
                IdentifierKind::Segment => {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
                }
            };
            if !valid {
                self.invalid = true;
                return Err(IdentifierError::Character);
            }
            if self.kind == IdentifierKind::Cluster {
                for (index, scheme) in STANDARD_SCHEMES.iter().enumerate() {
                    if scheme.get(usize::from(self.position)) != Some(&byte) {
                        self.reserved &= !(1 << index);
                    }
                }
            }
            // Eight distinguishes every reserved scheme from an arbitrary suffix.
            self.position = self.position.saturating_add(1).min(8);
        }
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<(), IdentifierError> {
        if self.invalid {
            return Err(IdentifierError::Character);
        }
        if self.position == 0 {
            return Err(IdentifierError::Empty);
        }
        if self.kind == IdentifierKind::Cluster
            && STANDARD_SCHEMES.iter().enumerate().any(|(index, scheme)| {
                self.reserved & (1 << index) != 0 && scheme.len() == usize::from(self.position)
            })
        {
            return Err(IdentifierError::ReservedCluster);
        }
        Ok(())
    }
}

pub(super) fn validate(bytes: &[u8], kind: IdentifierKind) -> Result<(), IdentifierError> {
    let mut identifier = Identifier::new(kind);
    identifier.push(bytes)?;
    identifier.finish()
}

pub(super) fn is_standard_scheme(bytes: &[u8]) -> bool {
    STANDARD_SCHEMES.contains(&bytes)
}
