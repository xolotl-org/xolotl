use xolotl_state::host::object::ObjectStore;
use xolotl_types::{Outcome, TaintedValue};
use xolotl_value_codec::validation::KeyStore;
use xolotl_value_object::{CommittedValue, encode_failure, encode_value};

use super::GatewayOutputExternalizationError;
use crate::{GatewayError, GatewayOutputEvent};

pub(super) async fn event<K: KeyStore>(
    objects: &ObjectStore,
    scratch: &mut [u8],
    keys: K,
    max_frames: Option<usize>,
    event: &GatewayOutputEvent,
) -> Result<CommittedValue, GatewayOutputExternalizationError>
where
    K::Error: core::fmt::Display,
{
    let encoded = match event {
        GatewayOutputEvent::Chunk(chunk) => {
            encode_value(objects, scratch, keys, max_frames, chunk).await
        }
        GatewayOutputEvent::Complete(completion) => {
            match &completion.output.outcome {
                Outcome::Done(value) | Outcome::Short(value) => {
                    // Cloning resident values and source labels only shares their
                    // handles. Payloads remain owned by the original completion.
                    let value = TaintedValue::new(value.clone(), completion.output.taint.clone());
                    encode_value(objects, scratch, keys, max_frames, &value).await
                }
                Outcome::Fail(failure) => {
                    encode_failure(
                        objects,
                        scratch,
                        keys,
                        max_frames,
                        failure,
                        &completion.output.taint,
                    )
                    .await
                }
            }
        }
    };
    encoded.map_err(|failure| GatewayOutputExternalizationError {
        error: GatewayError::Rejected(format!(
            "structured output encoding failed: {}",
            failure.error
        )),
        taint: failure.taint,
    })
}
