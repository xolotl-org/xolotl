//! Exact delivered-item counts without a cumulative stream bound.

pub(super) enum DeliveryCount {
    Small(u64),
    /// Least-significant-first ASCII decimal digits, allocated only on overflow.
    Decimal(Vec<u8>),
}

impl DeliveryCount {
    pub(super) const fn new() -> Self {
        Self::Small(0)
    }

    pub(super) fn reached(&self, limit: Option<u64>) -> bool {
        limit.is_some_and(|limit| match self {
            Self::Small(count) => *count >= limit,
            Self::Decimal(_) => true,
        })
    }

    pub(super) fn increment(&mut self) {
        match self {
            Self::Small(count) => {
                if let Some(next) = count.checked_add(1) {
                    *count = next;
                } else {
                    let mut digits = (u128::from(u64::MAX) + 1).to_string().into_bytes();
                    digits.reverse();
                    *self = Self::Decimal(digits);
                }
            }
            Self::Decimal(digits) => {
                for digit in digits.iter_mut() {
                    if *digit < b'9' {
                        *digit += 1;
                        return;
                    }
                    *digit = b'0';
                }
                digits.push(b'1');
            }
        }
    }

    pub(super) fn into_decimal(self) -> String {
        match self {
            Self::Small(count) => count.to_string(),
            Self::Decimal(digits) => digits.into_iter().rev().map(char::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivered_counts_continue_past_machine_integer_width() {
        let mut count = DeliveryCount::Small(u64::MAX);
        count.increment();
        assert!(!count.reached(None));
        assert!(count.reached(Some(u64::MAX)));
        for _ in 0..4 {
            count.increment();
        }
        assert_eq!(count.into_decimal(), "18446744073709551620");
    }

    #[test]
    fn decimal_counts_grow_without_saturating_or_wrapping() {
        let mut count = DeliveryCount::Decimal(vec![b'9'; 40]);
        count.increment();
        assert!(!count.reached(None));
        assert_eq!(count.into_decimal(), format!("1{}", "0".repeat(40)));
    }
}
