use alloc::{vec, vec::Vec};
use anyhow::{Context as _, Result, ensure};
use xolotl_types::value::{
    DType, FrameKind,
    event::{Atom, Event, Kind},
};

use super::{DecodeStatus, Error, ErrorKind, FrameDecoder, FrameEncoder};

type TestResult = Result<()>;

const PREFIX: &[u8] = b"\x83\x4cxolotl.value\x01\x9f";

fn encode(events: &[Event<'_>], window: usize) -> Result<Vec<u8>> {
    let mut encoder = FrameEncoder::new();
    let mut bytes = Vec::new();
    let mut output = vec![0; window];
    for &event in events {
        let mut writer = encoder.start_event(event)?;
        while !writer.is_complete() {
            let count = writer.write(&mut output)?;
            ensure!(count != 0);
            bytes.extend_from_slice(&output[..count]);
        }
        ensure!(writer.write(&mut output)? == 0);
    }
    while !encoder.is_complete() {
        let count = encoder.finish(&mut output)?;
        ensure!(count != 0);
        bytes.extend_from_slice(&output[..count]);
    }
    ensure!(encoder.finish(&mut output)? == 0);
    ensure!(encoder.bytes_written() == bytes.len() as u64);
    Ok(bytes)
}

fn feed<'input>(
    decoder: &mut FrameDecoder,
    mut input: &'input [u8],
    events: &mut Vec<Event<'input>>,
) -> Result<()> {
    while !input.is_empty() {
        let step = decoder.decode(input)?;
        ensure!(step.consumed != 0);
        input = &input[step.consumed..];
        match step.status {
            DecodeStatus::Event(event) => events.push(event),
            DecodeStatus::NeedInput | DecodeStatus::End => ensure!(input.is_empty()),
        }
    }
    Ok(())
}

fn decode(bytes: &[u8], window: usize) -> Result<Vec<Event<'_>>> {
    let mut decoder = FrameDecoder::new();
    let mut events = Vec::new();
    for input in bytes.chunks(window) {
        feed(&mut decoder, input, &mut events)?;
    }
    decoder.finish()?;
    ensure!(decoder.bytes_read() == bytes.len() as u64);
    ensure!(decoder.decode(&[])?.status == DecodeStatus::End);
    decoder.finish()?;
    Ok(events)
}

fn stream(record: &[u8]) -> Vec<u8> {
    let mut bytes = PREFIX.to_vec();
    bytes.extend_from_slice(record);
    bytes.push(0xff);
    bytes
}

#[test]
fn container_ids_are_stable() -> TestResult {
    let kinds = [
        Kind::Document,
        Kind::Taint,
        Kind::String,
        Kind::Bytes,
        Kind::List,
        Kind::Map,
        Kind::Key,
        Kind::Blob,
        Kind::Tensor,
        Kind::Shape,
        Kind::Frame,
        Kind::StreamError,
        Kind::Inbound,
        Kind::Fetched,
        Kind::Protected,
        Kind::Path,
        Kind::PathSegments,
    ];
    for (id, kind) in kinds.into_iter().enumerate() {
        let expected = stream(&[0x82, 0, id as u8, 0x82, 1, id as u8]);
        let events = [Event::Begin(kind), Event::End(kind)];
        ensure!(encode(&events, 1)? == expected);
        ensure!(decode(&expected, 1)? == events);
    }
    Ok(())
}

#[test]
fn atom_ids_and_numeric_representations_are_stable() -> TestResult {
    let cases: &[(Atom, &[u8])] = &[
        (Atom::Null, &[0x81, 2]),
        (Atom::Bool(false), &[0x81, 3]),
        (Atom::Bool(true), &[0x81, 4]),
        (Atom::I64(0), &[0x82, 5, 0]),
        (Atom::I64(-1), &[0x82, 5, 0x20]),
        (
            Atom::I64(i64::MIN),
            &[
                0x82, 5, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        ),
        (
            Atom::I64(i64::MAX),
            &[
                0x82, 5, 0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        ),
        (
            Atom::F64Bits(0x7ff8_0000_0000_1234),
            &[0x82, 6, 0x1b, 0x7f, 0xf8, 0, 0, 0, 0, 0x12, 0x34],
        ),
        (
            Atom::F64Bits(0x8000_0000_0000_0000),
            &[0x82, 6, 0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            Atom::U64(u64::MAX),
            &[
                0x82, 7, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        ),
        (Atom::Author, &[0x81, 10]),
        (Atom::Model, &[0x81, 11]),
        (Atom::StreamDone, &[0x81, 12]),
    ];
    for &(atom, record) in cases {
        let expected = stream(record);
        ensure!(encode(&[Event::Atom(atom)], 1)? == expected);
        ensure!(decode(&expected, 1)? == [Event::Atom(atom)]);
    }
    Ok(())
}

#[test]
fn dtype_and_frame_kind_ids_are_stable() -> TestResult {
    let dtypes = [
        DType::F16,
        DType::Bf16,
        DType::F32,
        DType::F64,
        DType::I8,
        DType::I16,
        DType::I32,
        DType::I64,
        DType::U8,
        DType::Bool,
    ];
    for (id, dtype) in dtypes.into_iter().enumerate() {
        let expected = stream(&[0x82, 8, id as u8]);
        let event = Event::Atom(Atom::DType(dtype));
        ensure!(encode(&[event], 1)? == expected);
        ensure!(decode(&expected, 1)? == [event]);
    }
    let kinds = [
        FrameKind::Audio,
        FrameKind::Video,
        FrameKind::Pose,
        FrameKind::Sensor,
    ];
    for (id, kind) in kinds.into_iter().enumerate() {
        let expected = stream(&[0x82, 9, id as u8]);
        let event = Event::Atom(Atom::FrameKind(kind));
        ensure!(encode(&[event], 1)? == expected);
        ensure!(decode(&expected, 1)? == [event]);
    }
    Ok(())
}

#[test]
fn every_header_split_preserves_integer_values() -> TestResult {
    let values = [
        0,
        23,
        24,
        u8::MAX as u64,
        u8::MAX as u64 + 1,
        u16::MAX as u64,
        u16::MAX as u64 + 1,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        u64::MAX,
    ];
    let expected: Vec<_> = values
        .into_iter()
        .map(|value| Event::Atom(Atom::U64(value)))
        .collect();
    let bytes = encode(&expected, 64)?;
    for split in 0..=bytes.len() {
        let mut decoder = FrameDecoder::new();
        let mut actual = Vec::new();
        feed(&mut decoder, &bytes[..split], &mut actual)?;
        ensure!(
            decoder.decode(&[])?.status
                == if split == bytes.len() {
                    DecodeStatus::End
                } else {
                    DecodeStatus::NeedInput
                }
        );
        feed(&mut decoder, &bytes[split..], &mut actual)?;
        decoder.finish()?;
        ensure!(actual == expected);
    }
    Ok(())
}

#[test]
fn output_windows_do_not_change_the_wire_stream() -> TestResult {
    let payload = vec![0xa5; 256];
    let events = [
        Event::Begin(Kind::Document),
        Event::Begin(Kind::Bytes),
        Event::Data(&[]),
        Event::Data(&payload),
        Event::End(Kind::Bytes),
        Event::End(Kind::Document),
    ];
    let expected = encode(&events, 512)?;
    for window in [1, 2, 3, 7, 9, 16, 17, 31, 256] {
        ensure!(encode(&events, window)? == expected);
    }
    ensure!(decode(&expected, expected.len())? == events);
    Ok(())
}

#[test]
fn data_borrows_input_and_survives_further_decoder_calls() -> TestResult {
    let bytes = stream(&[0x82, 13, 0x43, b'a', b'b', b'c']);
    let split = PREFIX.len() + 5;
    let mut decoder = FrameDecoder::new();
    let first = decoder.decode(&bytes[..split])?;
    let DecodeStatus::Event(Event::Data(first_data)) = first.status else {
        anyhow::bail!("expected the first borrowed data fragment");
    };
    ensure!(first_data == b"ab");
    ensure!(first_data.as_ptr() == bytes[PREFIX.len() + 3..].as_ptr());
    let second = decoder.decode(&bytes[split..])?;
    ensure!(second.consumed == 1);
    ensure!(second.status == DecodeStatus::Event(Event::Data(b"c")));
    ensure!(decoder.decode(&bytes[split + 1..])?.status == DecodeStatus::End);
    decoder.finish()?;
    ensure!(first_data == b"ab");
    Ok(())
}

#[test]
fn data_can_split_inside_utf8_and_empty_records_remain_visible() -> TestResult {
    let utf8 = [0xf0, 0x9f, 0x92, 0xa1];
    let events = [
        Event::Begin(Kind::String),
        Event::Data(&[]),
        Event::Data(&utf8),
        Event::End(Kind::String),
    ];
    let bytes = encode(&events, 1)?;
    let actual = decode(&bytes, 1)?;
    ensure!(actual[0] == events[0]);
    ensure!(actual[1] == Event::Data(&[]));
    ensure!(actual.last() == Some(&events[3]));
    let data: Vec<_> = actual
        .iter()
        .filter_map(|event| match event {
            Event::Data(bytes) => Some(*bytes),
            _ => None,
        })
        .flatten()
        .copied()
        .collect();
    ensure!(data == utf8);
    ensure!(actual.len() == 7);
    Ok(())
}

#[test]
fn data_header_widths_can_be_fragmented() -> TestResult {
    for size in [0, 23, 24, 255, 256, 65_535, 65_536] {
        let payload = vec![0xa7; size];
        let bytes = encode(&[Event::Data(&payload)], 257)?;
        let actual = decode(&bytes, 127)?;
        let mut flattened = Vec::new();
        for event in actual {
            let Event::Data(data) = event else {
                anyhow::bail!("expected only data fragments");
            };
            flattened.extend_from_slice(data);
        }
        ensure!(flattened == payload);
        for split in PREFIX.len()..(PREFIX.len() + 7).min(bytes.len()) {
            let mut decoder = FrameDecoder::new();
            let mut events = Vec::new();
            feed(&mut decoder, &bytes[..split], &mut events)?;
            feed(&mut decoder, &bytes[split..], &mut events)?;
            decoder.finish()?;
        }
    }
    Ok(())
}

#[test]
fn malformed_records_fail_stickily() -> TestResult {
    let cases: &[(&[u8], ErrorKind)] = &[
        (&[0x9f], ErrorKind::InvalidRecord),
        (&[0x80], ErrorKind::InvalidRecord),
        (&[0x83], ErrorKind::InvalidRecord),
        (&[0x81, 0], ErrorKind::InvalidRecord),
        (&[0x82, 2], ErrorKind::InvalidRecord),
        (&[0x81, 14], ErrorKind::UnknownEvent(14)),
        (&[0x82, 0, 17], ErrorKind::UnknownKind(17)),
        (&[0x82, 1, 17], ErrorKind::UnknownKind(17)),
        (&[0x82, 8, 10], ErrorKind::UnknownDType(10)),
        (&[0x82, 9, 4], ErrorKind::UnknownFrameKind(4)),
        (&[0x82, 0, 0x20], ErrorKind::InvalidRecord),
        (&[0x82, 5, 0xf9, 0, 0], ErrorKind::InvalidRecord),
        (&[0x82, 6, 0xf9, 0, 0], ErrorKind::InvalidRecord),
        (&[0x82, 7, 0x20], ErrorKind::InvalidRecord),
        (&[0x82, 13, 0x5f], ErrorKind::InvalidRecord),
        (&[0x82, 13, 0x60], ErrorKind::InvalidRecord),
        (&[0x81, 0x1c], ErrorKind::InvalidCbor),
        (&[0x81, 0x1f], ErrorKind::InvalidCbor),
        (
            &[0x82, 5, 0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0],
            ErrorKind::InvalidInteger,
        ),
        (
            &[0x82, 5, 0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0],
            ErrorKind::InvalidInteger,
        ),
    ];
    for &(record, kind) in cases {
        let bytes = stream(record);
        let mut decoder = FrameDecoder::new();
        let error = feed(&mut decoder, &bytes, &mut Vec::new())
            .err()
            .context("invalid record was accepted")?
            .downcast::<Error>()?;
        ensure!(error.kind == kind);
        ensure!(decoder.decode(&[]) == Err(error));
        ensure!(decoder.decode(PREFIX) == Err(error));
        ensure!(decoder.finish() == Err(error));
    }
    Ok(())
}

#[test]
fn envelope_magic_version_and_container_shape_are_checked() -> TestResult {
    for (index, value, kind) in [
        (0, 0x82, ErrorKind::InvalidEnvelope),
        (1, 0x6c, ErrorKind::InvalidEnvelope),
        (2, b'X', ErrorKind::InvalidEnvelope),
        (PREFIX.len() - 2, 2, ErrorKind::UnsupportedVersion(2)),
        (PREFIX.len() - 1, 0x80, ErrorKind::InvalidEnvelope),
    ] {
        let mut bytes = stream(&[]);
        bytes[index] = value;
        let error = decode(&bytes, 1)
            .err()
            .context("invalid envelope was accepted")?
            .downcast::<Error>()?;
        ensure!(error.kind == kind);
    }
    Ok(())
}

#[test]
fn every_truncated_prefix_requires_more_input() -> TestResult {
    let bytes = encode(
        &[
            Event::Begin(Kind::Document),
            Event::Data(b"payload"),
            Event::Atom(Atom::U64(u64::MAX)),
            Event::End(Kind::Document),
        ],
        3,
    )?;
    for cut in 0..bytes.len() {
        let mut decoder = FrameDecoder::new();
        feed(&mut decoder, &bytes[..cut], &mut Vec::new())?;
        let error = decoder.finish().err().context("truncation was accepted")?;
        ensure!(error.kind == ErrorKind::Truncated);
        ensure!(error.offset == cut as u64);
        ensure!(decoder.decode(&bytes[cut..]) == Err(error));
        ensure!(decoder.finish() == Err(error));
    }
    Ok(())
}

#[test]
fn trailing_data_is_rejected_before_and_after_eof() -> TestResult {
    let mut bytes = stream(&[]);
    bytes.push(0);
    let error = decode(&bytes, bytes.len())
        .err()
        .context("trailing byte was accepted")?
        .downcast::<Error>()?;
    ensure!(error.kind == ErrorKind::TrailingData);
    ensure!(error.offset == (bytes.len() - 1) as u64);
    for finish in [false, true] {
        let mut decoder = FrameDecoder::new();
        ensure!(decoder.decode(&bytes[..bytes.len() - 1])?.status == DecodeStatus::End);
        if finish {
            decoder.finish()?;
        }
        ensure!(decoder.decode(&bytes[bytes.len() - 1..]) == Err(error));
        ensure!(decoder.finish() == Err(error));
    }
    Ok(())
}

#[test]
fn cancelled_event_writes_poison_even_before_first_output() -> TestResult {
    for cut in [0, 1, 16, 17, 18, 20] {
        let mut encoder = FrameEncoder::new();
        let mut output = [0; 20];
        {
            let mut writer = encoder.start_event(Event::Data(b"abcdef"))?;
            ensure!(writer.write(&mut output[..cut])? == cut);
            ensure!(!writer.is_complete());
        }
        let error = encoder
            .start_event(Event::Atom(Atom::Null))
            .err()
            .context("cancelled encoder accepted another event")?;
        ensure!(error.kind == ErrorKind::Cancelled);
        ensure!(error.offset == cut as u64);
        ensure!(encoder.finish(&mut output) == Err(error));
        ensure!(!encoder.is_complete());
    }
    Ok(())
}

#[test]
fn empty_output_windows_are_retryable_and_finish_closes_event_admission() -> TestResult {
    let mut encoder = FrameEncoder::new();
    {
        let mut writer = encoder.start_event(Event::Atom(Atom::Null))?;
        ensure!(writer.write(&mut [])? == 0);
        ensure!(!writer.is_complete());
        let mut output = [0; 64];
        ensure!(writer.write(&mut output)? == PREFIX.len() + 2);
        ensure!(writer.is_complete());
    }
    ensure!(encoder.finish(&mut [])? == 0);
    ensure!(!encoder.is_complete());
    ensure!(encoder.finish(&mut [0])? == 1);
    ensure!(encoder.is_complete());
    let error = encoder
        .start_event(Event::Atom(Atom::Null))
        .err()
        .context("closed encoder accepted another event")?;
    ensure!(error.kind == ErrorKind::Closed);
    Ok(())
}

#[test]
fn framing_does_not_duplicate_semantic_validation() -> TestResult {
    let events = [
        Event::End(Kind::Map),
        Event::Data(&[]),
        Event::Atom(Atom::Model),
    ];
    let bytes = encode(&events, 1)?;
    ensure!(decode(&bytes, 1)? == events);
    Ok(())
}
