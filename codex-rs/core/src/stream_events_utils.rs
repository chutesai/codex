use std::pin::Pin;
use std::sync::Arc;

use codex_protocol::config_types::ModeKind;
use codex_protocol::items::TurnItem;
use tokio_util::sync::CancellationToken;

use crate::codex::Session;
use crate::codex::TurnContext;
use crate::error::CodexErr;
use crate::error::Result;
use crate::function_tool::FunctionCallError;
use crate::parse_turn_item;
use crate::proposed_plan_parser::strip_proposed_plan_blocks;
use crate::tools::parallel::ToolCallRuntime;
use crate::tools::router::ToolCall;
use crate::tools::router::ToolRouter;
use codex_protocol::models::FunctionCallOutputBody;
use codex_protocol::models::FunctionCallOutputPayload;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use futures::Future;
use serde_json::Value;
use tracing::debug;
use tracing::instrument;
use uuid::Uuid;

/// Handle a completed output item from the model stream, recording it and
/// queuing any tool execution futures. This records items immediately so
/// history and rollout stay in sync even if the turn is later cancelled.
pub(crate) type InFlightFuture<'f> =
    Pin<Box<dyn Future<Output = Result<ResponseInputItem>> + Send + 'f>>;

#[derive(Default)]
pub(crate) struct OutputItemResult {
    pub last_agent_message: Option<String>,
    pub needs_follow_up: bool,
    pub tool_futures: Vec<InFlightFuture<'static>>,
}

pub(crate) struct HandleOutputCtx {
    pub sess: Arc<Session>,
    pub turn_context: Arc<TurnContext>,
    pub tool_runtime: ToolCallRuntime,
    pub cancellation_token: CancellationToken,
}

fn base_url_is_chutes_responses_proxy(base_url: &str) -> bool {
    let base_url = base_url.trim_end_matches('/').to_ascii_lowercase();
    base_url.starts_with("https://responses.chutes.ai")
        || base_url.starts_with("http://responses.chutes.ai")
}

fn should_parse_proxy_tool_calls(provider: &crate::model_provider_info::ModelProviderInfo) -> bool {
    provider
        .base_url
        .as_deref()
        .is_some_and(base_url_is_chutes_responses_proxy)
}

fn parse_proxy_function_calls(item: &ResponseItem) -> Option<Vec<(String, String)>> {
    let ResponseItem::Message { role, content, .. } = item else {
        return None;
    };
    if role != "assistant" {
        return None;
    }

    let combined = content
        .iter()
        .filter_map(|entry| match entry {
            codex_protocol::models::ContentItem::OutputText { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<String>();
    if combined.is_empty() {
        return None;
    }

    parse_proxy_function_calls_text(&combined)
}

fn parse_proxy_function_calls_text(text: &str) -> Option<Vec<(String, String)>> {
    let mut remaining = text.trim_start();
    let first_idx = remaining.find("<function")?;
    remaining = &remaining[first_idx..];

    let mut calls = Vec::new();
    loop {
        let (name, after_header) = parse_proxy_function_header(remaining)?;
        let (arguments, after_args) = parse_proxy_function_arguments(after_header)?;
        calls.push((name, arguments));

        if let Some(next_idx) = after_args.find("<function") {
            remaining = &after_args[next_idx..];
        } else {
            break;
        }
    }

    (!calls.is_empty()).then_some(calls)
}

fn parse_proxy_function_header(text: &str) -> Option<(String, &str)> {
    if let Some(after_prefix) = text.strip_prefix("<function=") {
        let end = after_prefix
            .find('>')
            .or_else(|| after_prefix.find('\n'))
            .unwrap_or(after_prefix.len());
        let name = after_prefix[..end].trim();
        if name.is_empty() {
            return None;
        }
        let mut remaining = &after_prefix[end..];
        if let Some(after_gt) = remaining.strip_prefix('>') {
            remaining = after_gt;
        }
        return Some((name.to_string(), remaining));
    }

    let after_prefix = text.strip_prefix("<function>")?;
    let end = after_prefix
        .find("</function>")
        .or_else(|| after_prefix.find('\n'))
        .unwrap_or(after_prefix.len());
    let name = after_prefix[..end].trim();
    if name.is_empty() {
        return None;
    }

    let mut remaining = &after_prefix[end..];
    if let Some(after_close) = remaining.strip_prefix("</function>") {
        remaining = after_close;
    }
    Some((name.to_string(), remaining))
}

fn parse_proxy_function_arguments(text: &str) -> Option<(String, &str)> {
    let mut remaining = text.trim_start();
    if let Some(after_json) = remaining.strip_prefix("json") {
        remaining = after_json;
    }
    remaining = remaining
        .strip_prefix('\n')
        .unwrap_or(remaining)
        .trim_start();

    if remaining.starts_with('{') {
        let mut stream = serde_json::Deserializer::from_str(remaining).into_iter::<Value>();
        let parsed = stream.next()?.ok()?;
        let args = match parsed {
            Value::Object(_) => parsed,
            _ => return None,
        };
        let offset = stream.byte_offset();
        let remaining = remaining.get(offset..)?;
        return Some((serde_json::to_string(&args).ok()?, remaining));
    }

    if remaining.starts_with("<parameter=") {
        return parse_proxy_parameter_arguments(remaining);
    }

    if remaining.starts_with("<parameter>") {
        return parse_proxy_legacy_parameter_arguments(remaining);
    }

    None
}

fn parse_proxy_parameter_arguments(text: &str) -> Option<(String, &str)> {
    let mut remaining = text;
    let mut args = serde_json::Map::new();
    loop {
        let trimmed = remaining.trim_start();
        let Some(after_prefix) = trimmed.strip_prefix("<parameter=") else {
            break;
        };
        let end_name = after_prefix.find('>')?;
        let name = after_prefix[..end_name].trim();
        if name.is_empty() {
            return None;
        }
        let after_gt = &after_prefix[end_name + 1..];
        let (value, after_value) = after_gt.split_once("</parameter>")?;
        args.insert(name.to_string(), Value::String(value.trim().to_string()));
        remaining = after_value;
    }

    if args.is_empty() {
        return None;
    }
    Some((serde_json::to_string(&Value::Object(args)).ok()?, remaining))
}

fn parse_proxy_legacy_parameter_arguments(text: &str) -> Option<(String, &str)> {
    let mut remaining = text;
    let mut args = serde_json::Map::new();
    while let Some(start) = remaining.find("<parameter>") {
        remaining = &remaining[start + "<parameter>".len()..];
        let (param_name, after_name) = remaining.split_once("</parameter>")?;
        let param_name = param_name.trim();
        if param_name.is_empty() {
            return None;
        }

        let value_end = after_name
            .find("</parameter>")
            .or_else(|| after_name.find('\n'))
            .or_else(|| after_name.find("</function>"))
            .or_else(|| after_name.find("<function"))
            .unwrap_or(after_name.len());
        let value = after_name[..value_end].trim();
        args.insert(param_name.to_string(), Value::String(value.to_string()));

        remaining = &after_name[value_end..];
        if let Some(after_close) = remaining.strip_prefix("</parameter>") {
            remaining = after_close;
        }
    }

    if args.is_empty() {
        return None;
    }

    Some((serde_json::to_string(&Value::Object(args)).ok()?, remaining))
}

#[instrument(level = "trace", skip_all)]
pub(crate) async fn handle_output_item_done(
    ctx: &mut HandleOutputCtx,
    item: ResponseItem,
    previously_active_item: Option<TurnItem>,
) -> Result<OutputItemResult> {
    let mut output = OutputItemResult::default();
    let plan_mode = ctx.turn_context.collaboration_mode.mode == ModeKind::Plan;

    match ToolRouter::build_tool_call(ctx.sess.as_ref(), item.clone()).await {
        // The model emitted a tool call; log it, persist the item immediately, and queue the tool execution.
        Ok(Some(call)) => {
            let payload_preview = call.payload.log_payload().into_owned();
            tracing::info!(
                thread_id = %ctx.sess.conversation_id,
                "ToolCall: {} {}",
                call.tool_name,
                payload_preview
            );

            ctx.sess
                .record_conversation_items(&ctx.turn_context, std::slice::from_ref(&item))
                .await;

            let cancellation_token = ctx.cancellation_token.child_token();
            let tool_future: InFlightFuture<'static> = Box::pin(
                ctx.tool_runtime
                    .clone()
                    .handle_tool_call(call, cancellation_token),
            );

            output.needs_follow_up = true;
            output.tool_futures.push(tool_future);
        }
        // No tool call: convert messages/reasoning into turn items and mark them as complete.
        Ok(None) => {
            if let Some(turn_item) = handle_non_tool_response_item(&item, plan_mode).await {
                if previously_active_item.is_none() {
                    ctx.sess
                        .emit_turn_item_started(&ctx.turn_context, &turn_item)
                        .await;
                }

                ctx.sess
                    .emit_turn_item_completed(&ctx.turn_context, turn_item)
                    .await;
            }

            ctx.sess
                .record_conversation_items(&ctx.turn_context, std::slice::from_ref(&item))
                .await;

            if should_parse_proxy_tool_calls(&ctx.turn_context.provider) {
                if let Some(calls) = parse_proxy_function_calls(&item) {
                    for (tool_name, arguments) in calls {
                        let call = ToolCall {
                            tool_name,
                            call_id: format!("proxy_call_{}", Uuid::new_v4()),
                            payload: crate::tools::context::ToolPayload::Function { arguments },
                        };

                        let payload_preview = call.payload.log_payload().into_owned();
                        tracing::info!(
                            thread_id = %ctx.sess.conversation_id,
                            "ToolCall (proxy text): {} {}",
                            call.tool_name,
                            payload_preview
                        );

                        let cancellation_token = ctx.cancellation_token.child_token();
                        let tool_future: InFlightFuture<'static> = Box::pin(
                            ctx.tool_runtime
                                .clone()
                                .handle_tool_call(call, cancellation_token),
                        );

                        output.tool_futures.push(tool_future);
                    }

                    output.needs_follow_up = !output.tool_futures.is_empty();
                    output.last_agent_message = None;
                } else {
                    output.last_agent_message = last_assistant_message_from_item(&item, plan_mode);
                }
            } else {
                output.last_agent_message = last_assistant_message_from_item(&item, plan_mode);
            }
        }
        // Guardrail: the model issued a LocalShellCall without an id; surface the error back into history.
        Err(FunctionCallError::MissingLocalShellCallId) => {
            let msg = "LocalShellCall without call_id or id";
            ctx.turn_context
                .otel_manager
                .log_tool_failed("local_shell", msg);
            tracing::error!(msg);

            let response = ResponseInputItem::FunctionCallOutput {
                call_id: String::new(),
                output: FunctionCallOutputPayload {
                    body: FunctionCallOutputBody::Text(msg.to_string()),
                    ..Default::default()
                },
            };
            ctx.sess
                .record_conversation_items(&ctx.turn_context, std::slice::from_ref(&item))
                .await;
            if let Some(response_item) = response_input_to_response_item(&response) {
                ctx.sess
                    .record_conversation_items(
                        &ctx.turn_context,
                        std::slice::from_ref(&response_item),
                    )
                    .await;
            }

            output.needs_follow_up = true;
        }
        // The tool request should be answered directly (or was denied); push that response into the transcript.
        Err(FunctionCallError::RespondToModel(message)) => {
            let response = ResponseInputItem::FunctionCallOutput {
                call_id: String::new(),
                output: FunctionCallOutputPayload {
                    body: FunctionCallOutputBody::Text(message),
                    ..Default::default()
                },
            };
            ctx.sess
                .record_conversation_items(&ctx.turn_context, std::slice::from_ref(&item))
                .await;
            if let Some(response_item) = response_input_to_response_item(&response) {
                ctx.sess
                    .record_conversation_items(
                        &ctx.turn_context,
                        std::slice::from_ref(&response_item),
                    )
                    .await;
            }

            output.needs_follow_up = true;
        }
        // A fatal error occurred; surface it back into history.
        Err(FunctionCallError::Fatal(message)) => {
            return Err(CodexErr::Fatal(message));
        }
    }

    Ok(output)
}

pub(crate) async fn handle_non_tool_response_item(
    item: &ResponseItem,
    plan_mode: bool,
) -> Option<TurnItem> {
    debug!(?item, "Output item");

    match item {
        ResponseItem::Message { .. }
        | ResponseItem::Reasoning { .. }
        | ResponseItem::WebSearchCall { .. } => {
            let mut turn_item = parse_turn_item(item)?;
            if plan_mode && let TurnItem::AgentMessage(agent_message) = &mut turn_item {
                let combined = agent_message
                    .content
                    .iter()
                    .map(|entry| match entry {
                        codex_protocol::items::AgentMessageContent::Text { text } => text.as_str(),
                    })
                    .collect::<String>();
                let stripped = strip_proposed_plan_blocks(&combined);
                agent_message.content =
                    vec![codex_protocol::items::AgentMessageContent::Text { text: stripped }];
            }
            Some(turn_item)
        }
        ResponseItem::FunctionCallOutput { .. } | ResponseItem::CustomToolCallOutput { .. } => {
            debug!("unexpected tool output from stream");
            None
        }
        _ => None,
    }
}

pub(crate) fn last_assistant_message_from_item(
    item: &ResponseItem,
    plan_mode: bool,
) -> Option<String> {
    if let ResponseItem::Message { role, content, .. } = item
        && role == "assistant"
    {
        let combined = content
            .iter()
            .filter_map(|ci| match ci {
                codex_protocol::models::ContentItem::OutputText { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<String>();
        if combined.is_empty() {
            return None;
        }
        return if plan_mode {
            let stripped = strip_proposed_plan_blocks(&combined);
            (!stripped.trim().is_empty()).then_some(stripped)
        } else {
            Some(combined)
        };
    }
    None
}

pub(crate) fn response_input_to_response_item(input: &ResponseInputItem) -> Option<ResponseItem> {
    match input {
        ResponseInputItem::FunctionCallOutput { call_id, output } => {
            Some(ResponseItem::FunctionCallOutput {
                call_id: call_id.clone(),
                output: output.clone(),
            })
        }
        ResponseInputItem::CustomToolCallOutput { call_id, output } => {
            Some(ResponseItem::CustomToolCallOutput {
                call_id: call_id.clone(),
                output: output.clone(),
            })
        }
        ResponseInputItem::McpToolCallOutput { call_id, result } => {
            let output = match result {
                Ok(call_tool_result) => FunctionCallOutputPayload::from(call_tool_result),
                Err(err) => FunctionCallOutputPayload {
                    body: FunctionCallOutputBody::Text(err.clone()),
                    success: Some(false),
                },
            };
            Some(ResponseItem::FunctionCallOutput {
                call_id: call_id.clone(),
                output,
            })
        }
        _ => None,
    }
}
