use alloc::vec::Vec;
use anyhow::{Context as _, Result, ensure};

use super::{ErrorKind, Event, FrameEncoder, RecordHeader, State, data_chunk_len};

type TestResult = Result<()>;

#[test]
fn data_continues_with_another_record_after_a_chunk_boundary() -> TestResult {
    let mut encoder = FrameEncoder::new();
    let mut bytes = Vec::new();
    {
        let mut writer = encoder.start_event(Event::Data(b"abcdef"))?;
        // Exercise a record rollover without allocating a multi-gigabyte slice.
        writer.header = RecordHeader::data(3).map_err(|kind| writer.encoder.fail(kind))?;
        writer.chunk_remaining = 3;
        while !writer.is_complete() {
            let mut output = [0; 2];
            let count = writer.write(&mut output)?;
            ensure!(count != 0);
            bytes.extend_from_slice(&output[..count]);
        }
    }
    let mut ending = [0; 1];
    let count = encoder.finish(&mut ending)?;
    bytes.extend_from_slice(&ending[..count]);
    ensure!(bytes == b"\x83\x4cxolotl.value\x01\x9f\x82\x0d\x43abc\x82\x0d\x43def\xff");
    Ok(())
}

#[test]
fn byte_offsets_cross_u32_and_fail_without_wrapping_u64() -> TestResult {
    let mut encoder = FrameEncoder::new();
    encoder.offset = u32::MAX as u64;
    ensure!(encoder.finish(&mut [0; 64])? == 17);
    ensure!(encoder.bytes_written() == u32::MAX as u64 + 17);

    let mut encoder = FrameEncoder::new();
    encoder.offset = u64::MAX;
    let mut output = [0xa5; 1];
    let error = encoder
        .finish(&mut output)
        .err()
        .context("offset wrapped")?;
    ensure!(error.kind == ErrorKind::OffsetOverflow);
    ensure!(error.offset == u64::MAX);
    ensure!(output == [0xa5]);
    ensure!(encoder.finish(&mut output) == Err(error));
    Ok(())
}

#[test]
fn abandoned_active_state_cannot_be_reused() -> TestResult {
    let mut encoder = FrameEncoder::new();
    encoder.state = State::Active;
    let error = encoder
        .finish(&mut [0; 1])
        .err()
        .context("active encoder closed")?;
    ensure!(error.kind == ErrorKind::IncompleteEvent);
    ensure!(encoder.finish(&mut [0; 1]) == Err(error));
    Ok(())
}

#[test]
fn data_record_ceiling_does_not_reject_larger_source_lengths() {
    assert_eq!(data_chunk_len(0), 0);
    assert_eq!(data_chunk_len(usize::MAX), u32::MAX as usize);
    #[cfg(target_pointer_width = "64")]
    assert_eq!(data_chunk_len(u32::MAX as usize + 1), u32::MAX as usize);
}
