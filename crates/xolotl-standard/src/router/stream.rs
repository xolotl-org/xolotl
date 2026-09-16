use super::{RouteMethod, Router, is_retryable};
use crate::inference::{InferenceStream, RequestRequirements};
use xolotl_kernel::DriverOutput;
use xolotl_types::Value;

impl Router {
    pub(crate) async fn infer_stream(
        &self,
        input: &Value,
        requirements: &RequestRequirements,
        stream: &InferenceStream<'_>,
    ) -> Result<DriverOutput, String> {
        self.route_stream(input, requirements, stream, RouteMethod::Infer)
            .await
    }

    pub(crate) async fn plan_stream(
        &self,
        input: &Value,
        requirements: &RequestRequirements,
        stream: &InferenceStream<'_>,
    ) -> Result<DriverOutput, String> {
        self.route_stream(input, requirements, stream, RouteMethod::Plan)
            .await
    }

    async fn route_stream(
        &self,
        input: &Value,
        requirements: &RequestRequirements,
        stream: &InferenceStream<'_>,
        method: RouteMethod,
    ) -> Result<DriverOutput, String> {
        let mut group_name = self.default_group.as_str();
        let mut visited = Vec::new();
        loop {
            if visited.contains(&group_name) {
                return Err(format!("routing cycle through group '{group_name}'"));
            }
            visited.push(group_name);
            let candidates = self.candidates(group_name, requirements, method);
            let mut last_error = format!("no model in group '{group_name}' satisfies the request");
            for index in self.order_candidates(group_name, &candidates) {
                let model = &self.models[index];
                for attempt in 0..=self.max_retries {
                    let started = std::time::Instant::now();
                    let result = match method {
                        RouteMethod::Infer => model.backend.infer_stream(input, stream).await,
                        RouteMethod::Plan => model.backend.plan_stream(input, stream).await,
                        _ => return Err("route method is not text inference".into()),
                    };
                    model.record(started.elapsed().as_micros() as u64, result.is_ok());
                    match result {
                        Ok(output) => return Ok(output),
                        Err(error) => {
                            // Accepted output cannot be replayed by another
                            // attempt without duplicating the caller's stream.
                            if stream.has_output() {
                                return Err(error);
                            }
                            last_error = error;
                            if !is_retryable(&last_error) || attempt == self.max_retries {
                                break;
                            }
                        }
                    }
                }
            }
            match self
                .groups
                .get(group_name)
                .and_then(|group| group.fallback.as_deref())
            {
                Some(fallback) => group_name = fallback,
                None => return Err(last_error),
            }
        }
    }
}

#[cfg(test)]
mod tests;
