//! Explicit resident materialization after full object and codec validation.

use xolotl_state::object::ObjectRead;
use xolotl_types::{
    TaintSet, TaintedValue,
    value::event::{MaterializationLimits, ValueBuilder},
};
use xolotl_value_codec::validation::KeyStore;

use super::{ReadError, ReadFailure, ValueObjectReader};
use crate::EncodedValueRef;

/// Materialize a complete encoded object through an explicitly admitted port.
///
/// The builder stays private until object EOF and codec validation produce a
/// completion receipt. The result combines caller, metadata, every read chunk,
/// and recorded document provenance. Recorded claims never supply authority to
/// read the object or disclose the result. Nested references remain descriptors.
///
/// `limits` is explicit admission policy for resident materialization. Its
/// default imposes no cumulative size or depth limit; the same `max_frames`
/// governs both codec and builder. Use [`ValueObjectReader`] with a streaming
/// consumer when retaining the complete value is unnecessary.
///
/// Failure or cancellation drops the private value and all unfinished storage.
/// A returned failure retains all actual sources and completely parsed claims.
pub async fn read_value<R: ObjectRead + ?Sized, K: KeyStore>(
    store: &R,
    reference: &EncodedValueRef,
    scratch: &mut [u8],
    keys: K,
    initial_sources: TaintSet,
    limits: MaterializationLimits,
) -> Result<TaintedValue, ReadFailure<K::Error>> {
    let mut reader = ValueObjectReader::open(
        store,
        reference,
        scratch,
        keys,
        limits.max_frames,
        initial_sources,
    )
    .await?;
    let mut builder = ValueBuilder::new(limits);
    loop {
        match reader.next_event().await {
            Ok(Some(event)) => {
                if let Err(error) = builder.push(event.event) {
                    let mut taint = event.taint.clone();
                    taint.union(builder.observed_taint());
                    return Err(ReadFailure {
                        error: ReadError::Materialization(error),
                        taint,
                    });
                }
            }
            Ok(None) => break,
            Err(mut failure) => {
                failure.taint.union(builder.observed_taint());
                return Err(failure);
            }
        }
    }
    let receipt = reader.finish().map_err(|mut failure| {
        failure.taint.union(builder.observed_taint());
        failure
    })?;
    let claimed = builder.observed_taint().clone();
    let mut value = builder.finish().map_err(|error| ReadFailure {
        error: ReadError::Materialization(error),
        taint: claimed.clone().merged(receipt.taint()),
    })?;
    drop(claimed);
    value.taint.union(receipt.taint());
    Ok(value)
}
