use alloc::vec::Vec;
use anyhow::{Context as _, Result, ensure};

use super::{DecodeStatus, ErrorKind, FrameDecoder, State};

type TestResult = Result<()>;

#[test]
fn decoder_offsets_cross_u32_and_fail_without_wrapping_u64() -> TestResult {
    let mut decoder = FrameDecoder::new();
    decoder.offset = u32::MAX as u64;
    ensure!(decoder.decode(b"\x83\x4cxolotl.value\x01\x9f\xff")?.status == DecodeStatus::End);
    decoder.finish()?;
    ensure!(decoder.bytes_read() == u32::MAX as u64 + 17);

    let mut decoder = FrameDecoder::new();
    decoder.offset = u64::MAX;
    let error = decoder.decode(&[0x83]).err().context("offset wrapped")?;
    ensure!(error.kind == ErrorKind::OffsetOverflow);
    ensure!(error.offset == u64::MAX);
    ensure!(decoder.decode(&[0x83]) == Err(error));
    ensure!(decoder.finish() == Err(error));
    Ok(())
}

#[test]
fn payload_offset_overflow_is_sticky() -> TestResult {
    let mut decoder = FrameDecoder::new();
    decoder.state = State::Data { remaining: 3 };
    decoder.offset = u64::MAX - 1;
    let error = decoder
        .decode(b"abc")
        .err()
        .context("payload offset wrapped")?;
    ensure!(error.kind == ErrorKind::OffsetOverflow);
    ensure!(error.offset == u64::MAX - 1);
    ensure!(decoder.decode(b"abc") == Err(error));
    Ok(())
}

#[test]
fn largest_data_record_needs_no_payload_allocation() -> TestResult {
    let mut decoder = FrameDecoder::new();
    let header = b"\x83\x4cxolotl.value\x01\x9f\x82\x0d\x5a\xff\xff\xff\xff";
    for byte in header {
        let step = decoder.decode(core::slice::from_ref(byte))?;
        ensure!(step.consumed == 1);
        ensure!(step.status == DecodeStatus::NeedInput);
    }
    ensure!(matches!(decoder.state, State::Data { remaining } if remaining == u32::MAX as usize));
    let step = decoder.decode(b"a")?;
    ensure!(step.consumed == 1);
    ensure!(matches!(step.status, DecodeStatus::Event(_)));
    let error = decoder
        .finish()
        .err()
        .context("incomplete payload was accepted")?;
    ensure!(error.kind == ErrorKind::Truncated);
    Ok(())
}

#[test]
fn data_record_ceiling_is_distinct_from_logical_field_length() -> TestResult {
    let mut bytes = Vec::from(&b"\x83\x4cxolotl.value\x01\x9f\x82\x0d\x5b"[..]);
    bytes.extend_from_slice(&(u32::MAX as u64 + 1).to_be_bytes());
    let mut decoder = FrameDecoder::new();
    let error = decoder
        .decode(&bytes)
        .err()
        .context("oversized record was accepted")?;
    #[cfg(target_pointer_width = "64")]
    ensure!(error.kind == ErrorKind::DataRecordTooLarge(u32::MAX as u64 + 1));
    #[cfg(not(target_pointer_width = "64"))]
    ensure!(error.kind == ErrorKind::InvalidCbor);
    ensure!(decoder.decode(&[]) == Err(error));
    Ok(())
}
