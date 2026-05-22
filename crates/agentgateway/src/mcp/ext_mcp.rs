use std::sync::Arc;

use macro_rules_attribute::apply;
use prost_wkt_types::Struct;
use rmcp::model::{ClientRequest, JsonRpcRequest};
use serde_json;

use crate::http::ext_proc::{FailureMode, GrpcReferenceChannel};
use crate::mcp::ext_mcp::proto::ext_mcp_client::ExtMcpClient;
use crate::mcp::ext_mcp::proto::{McpRequest, Metadata, MutatedMcpRequest};
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::SimpleBackendReference;
use crate::*;

pub mod proto {
	pub use protos::model_context_protocol::*;
}

#[apply(schema!)]
pub struct ExtMcp {
	#[serde(flatten)]
	pub target: Arc<SimpleBackendReference>,
	#[serde(default)]
	pub failure_mode: FailureMode,
	/// Additional metadata to send to the external processing service.
	/// Maps to the `metadata_context.filter_metadata` field in ProcessingRequest, and allows dynamic CEL expressions.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub metadata_context: Option<HashMap<String, HashMap<String, Arc<cel::Expression>>>>,
}

impl ExtMcp {
	/// Convert protobuf MutatedMcpRequest back to json rpc ClientRequest
	fn protobuf_to_json_rpc(
		mutated_request: MutatedMcpRequest,
	) -> Result<ClientRequest, crate::proxy::ProxyError> {
		if let Some(result) = mutated_request.result {
			match result {
				crate::mcp::ext_mcp::proto::mutated_mcp_request::Result::McpRequest(mcp_struct) => {
					// Convert protobuf Struct back to JSON and then to ClientRequest
					let json_value = serde_json::to_value(mcp_struct).map_err(|e| {
						crate::proxy::ProxyError::Processing(anyhow::anyhow!(
							"Failed to convert protobuf Struct to JSON: {}",
							e
						))
					})?;

					let client_request: ClientRequest = serde_json::from_value(json_value).map_err(|e| {
						crate::proxy::ProxyError::Processing(anyhow::anyhow!(
							"Failed to deserialize JSON to ClientRequest: {}",
							e
						))
					})?;

					Ok(client_request)
				},
				crate::mcp::ext_mcp::proto::mutated_mcp_request::Result::Error(_) => {
					Err(crate::proxy::ProxyError::Processing(anyhow::anyhow!(
						"AuthorizationError should never be received in protobuf_to_json_rpc"
					)))
				},
			}
		} else {
			Err(crate::proxy::ProxyError::Processing(anyhow::anyhow!(
				"Protobuf MutatedMcpRequest result should have been set"
			)))
		}
	}

	/// Convert JsonRpcRequest to protobuf McpRequest
	fn json_rpc_to_protobuf(
		&self,
		service_name: &str,
		json_rpc_request: &JsonRpcRequest<ClientRequest>,
		ctx: &IncomingRequestContext,
	) -> Result<McpRequest, crate::proxy::ProxyError> {
		// Convert the entire ClientRequest to JSON and then to protobuf Struct
		let json_value = serde_json::to_value(&json_rpc_request.request).map_err(|e| {
			crate::proxy::ProxyError::Processing(anyhow::anyhow!(
				"Failed to serialize ClientRequest to JSON: {}",
				e
			))
		})?;

		let mcp_struct = serde_json::from_value::<Struct>(json_value).map_err(|e| {
			crate::proxy::ProxyError::Processing(anyhow::anyhow!(
				"Failed to convert JSON to protobuf Struct: {}",
				e
			))
		})?;

		// Create a CEL executor with JWT claims if available
		let mut exec = crate::cel::Executor::new_empty();
		if let Some(claims) = ctx.claims() {
			tracing::trace!(
				"Adding JWT claims to CEL executor for ext_mcp metadata evaluation: {:?}",
				claims.inner
			);
			exec.jwt = crate::cel::ExtensionOrDirect::Direct(Some(claims));
		} else {
			tracing::trace!("No JWT claims available for ext_mcp metadata evaluation");
		}
		let metadata_context = self.metadata_context.as_ref().map(|meta| {
			tracing::trace!("Processing metadata_context with {} namespaces", meta.len());
			let filter_metadata: std::collections::HashMap<String, prost_wkt_types::Struct> = meta
				.iter()
				.filter_map(|(n, e)| {
					tracing::trace!(
						"Processing namespace '{}' with {} expressions",
						n,
						e.clone().len()
					);
					for (key, expr) in e.clone().iter() {
						tracing::trace!("Expression '{}': {:?}", key, expr);
					}
					match crate::http::ext_proc::eval_to_struct(&exec, e) {
						Ok(v) => {
							tracing::trace!(
								"Successfully evaluated metadata for namespace '{}': {:?}",
								n,
								v
							);
							Some((n.clone(), v))
						},
						Err(error) => {
							tracing::trace!(
								"Failed to evaluate metadata for namespace '{}': {}",
								n,
								error
							);
							None
						},
					}
				})
				.collect();
			tracing::trace!(
				">#> Metadata processing complete, final filter_metadata: {:?}",
				filter_metadata
			);
			Metadata { filter_metadata }
		});
		Ok(McpRequest {
			service_name: service_name.to_string(),
			mcp_request: Some(mcp_struct),
			metadata_context,
		})
	}

	pub async fn mutate_request(
		&self,
		service_name: &str,
		client: PolicyClient,
		json_rpc_request: JsonRpcRequest<ClientRequest>,
		ctx: &IncomingRequestContext,
	) -> Result<JsonRpcRequest<ClientRequest>, UpstreamError> {
		trace!(
			protocol = "grpc",
			"ext_mcp mutate_request connecting to {:?}", self.target
		);

		let chan = GrpcReferenceChannel {
			target: self.target.clone(),
			client,
			policies: Arc::new(Vec::new()),
		};

		let mut grpc_client = ExtMcpClient::new(chan);

		// Convert JSON-RPC MCP request to protobuf format for external processing
		let mcp_req = self
			.json_rpc_to_protobuf(service_name, &json_rpc_request, ctx)
			.map_err(|e| {
				UpstreamError::InvalidRequest(format!("Failed to convert JSON-RPC to protobuf: {}", e))
			})?;

		match grpc_client.mutate_request(mcp_req).await {
			Ok(response) => {
				let mutated_mcp_req = response.into_inner();

				// Check if the response contains an authorization error
				if let Some(crate::mcp::ext_mcp::proto::mutated_mcp_request::Result::Error(auth_error)) =
					mutated_mcp_req.result.as_ref()
				{
					return Err(UpstreamError::Authorization {
						resource_type: auth_error.resource.clone(),
						resource_name: auth_error.name.clone(),
					});
				}

				// convert the protobuf mcp request to json rpc
				let client_req = Self::protobuf_to_json_rpc(mutated_mcp_req)
					.map_err(|_| UpstreamError::ExternalMcpProcessFailed)?;
				return Ok(JsonRpcRequest {
					jsonrpc: json_rpc_request.jsonrpc,
					id: json_rpc_request.id,
					request: client_req,
				});
			},
			Err(e) => {
				if self.failure_mode == FailureMode::FailClosed {
					warn!("ext_mcp request failed: {:?}", e);
					return Err(UpstreamError::ExternalMcpProcessFailed);
				} else {
					// return the original request
					return Ok(json_rpc_request);
				}
			},
		}
	}
}
