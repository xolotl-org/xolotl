use crate::object::ObjectWriteChunk;
use anyhow::ensure;

#[test]
fn write_progress_validates_partial_full_empty_and_full_width_offsets() -> anyhow::Result<()> {
    for (offset, offered, bytes_written, next_offset) in [
        (0, 8, 3, 3),
        (3, 5, 5, 8),
        (u64::MAX - 4, 4, 4, u64::MAX),
        (u64::MAX, 0, 0, u64::MAX),
    ] {
        let progress = ObjectWriteChunk {
            bytes_written,
            next_offset,
        };
        ensure!(progress.checked_next_offset(offset, offered)? == next_offset);
    }
    for (offset, offered, bytes_written, next_offset) in [
        (0, 8, 0, 0),
        (0, 8, 9, 9),
        (0, 8, 3, 4),
        (3, 5, 1, 8),
        (u64::MAX, 1, 1, 0),
        (u64::MAX - 1, 2, 2, u64::MAX),
        (0, 0, 1, 1),
    ] {
        ensure!(
            ObjectWriteChunk {
                bytes_written,
                next_offset,
            }
            .checked_next_offset(offset, offered)
            .is_err()
        );
    }
    Ok(())
}
