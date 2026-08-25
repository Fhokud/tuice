use std::sync::Arc;

use axum::http::{
	HeaderName, Request, Response, Uri,
	header::{HOST, HeaderValue},
};
use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use h3::server;
use reqwest::{Body, Client, Method, Url};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};
use tuic_core::quinn::QuinnConnection;

use crate::{AppContext, config::CamouflageConfig};

#[derive(Debug)]
struct IdleTimeout {
	phase: &'static str,
	duration: std::time::Duration,
	response_started: bool,
}

impl std::fmt::Display for IdleTimeout {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{} idle timeout after {:?}", self.phase, self.duration)
	}
}

impl std::error::Error for IdleTimeout {}

pub async fn handle(
	ctx: Arc<AppContext>,
	conn: QuinnConnection,
	prefetched_uni: Option<crate::h3_quinn_compat::PeekableRecvStream>,
	prefetched_bi: Option<crate::h3_quinn_compat::PrefetchedBiRecv>,
) -> eyre::Result<()> {
	let Some(camouflage) = ctx.cfg.camouflage.as_ref().filter(|cfg| cfg.enabled) else {
		return Ok(());
	};

	let (backend, backend_host_override, client) = build_backend_route(camouflage)?;
	let remote_ip = conn.remote_address().ip();
	let idle_timeout = camouflage.request_timeout;

	info!(
		id = conn.stable_id() as u32,
		addr = %conn.remote_address(),
		"HTTP/3 camouflage enabled, reverse proxy target={target}, backend_host={host:?}",
		target = backend,
		host = backend_host_override
	);

	let quic_conn = crate::h3_quinn_compat::Connection::new_with_prefetched(conn, prefetched_uni, prefetched_bi);
	let mut h3_conn = server::Connection::new(quic_conn).await?;
	let mut requests = JoinSet::new();

	while let Some(resolver) = h3_conn.accept().await? {
		let (request, mut stream) = resolver.resolve_request().await?;
		debug!(
			"[camouflage] incoming h3 request: method={} uri={}",
			request.method(),
			request.uri()
		);

		let client = client.clone();
		let backend = backend.clone();
		let backend_host_override = backend_host_override.clone();
		requests.spawn(async move {
			if let Err(err) = forward_request(
				&client,
				&backend,
				backend_host_override.as_deref(),
				remote_ip,
				idle_timeout,
				request,
				&mut stream,
			)
			.await
			{
				warn!("[camouflage] request forwarding failed: {err}");
				let timeout = err.downcast_ref::<IdleTimeout>();
				if !timeout.is_some_and(|timeout| timeout.response_started) {
					let status = if timeout.is_some() { 504 } else { 502 };
					if let Ok(resp) = Response::builder().status(status).body(()) {
						_ = stream.send_response(resp).await;
					}
				}
				_ = stream.finish().await;
			}
		});

		while let Some(result) = requests.try_join_next() {
			if let Err(err) = result {
				warn!("[camouflage] request task failed: {err}");
			}
		}
	}

	while let Some(result) = requests.join_next().await {
		if let Err(err) = result {
			warn!("[camouflage] request task failed: {err}");
		}
	}

	Ok(())
}

fn build_backend_route(camouflage: &CamouflageConfig) -> eyre::Result<(Url, Option<String>, Client)> {
	let mut backend = Url::parse(camouflage.reverse_proxy_url.as_str())?;
	let backend_host = backend
		.host_str()
		.ok_or_else(|| eyre::eyre!("`camouflage.reverse_proxy_url` must contain a host"))?
		.to_string();
	let backend_port = backend
		.port_or_known_default()
		.ok_or_else(|| eyre::eyre!("`camouflage.reverse_proxy_url` has no known port"))?;

	let mut client_builder = Client::builder()
		.danger_accept_invalid_certs(camouflage.skip_backend_tls_verify)
		.connect_timeout(camouflage.request_timeout);
	let mut backend_host_override = camouflage.reverse_proxy_hostname.clone();

	if let Some(reverse_proxy_hostname) = camouflage.reverse_proxy_hostname.as_deref() {
		backend
			.set_host(Some(reverse_proxy_hostname))
			.map_err(|_| eyre::eyre!("invalid `camouflage.reverse_proxy_hostname`: {reverse_proxy_hostname}"))?;
		if let Ok(ip) = backend_host.parse::<std::net::IpAddr>() {
			client_builder = client_builder.resolve(reverse_proxy_hostname, std::net::SocketAddr::new(ip, backend_port));
		}
		backend_host_override = Some(reverse_proxy_hostname.to_string());
	}

	let client = client_builder.build()?;
	Ok((backend, backend_host_override, client))
}

async fn forward_request<S>(
	client: &Client,
	backend: &Url,
	backend_host_override: Option<&str>,
	remote_ip: std::net::IpAddr,
	idle_timeout: std::time::Duration,
	request: Request<()>,
	stream: &mut server::RequestStream<S, Bytes>,
) -> eyre::Result<()>
where
	S: h3::quic::BidiStream<Bytes>,
{
	let target = rewrite_target_url(backend, request.uri())?;
	let method = Method::from_bytes(request.method().as_str().as_bytes())?;
	let mut backend_request = client.request(method, target);

	for (name, value) in request.headers() {
		if is_forwardable_header(name) && !is_proxy_identity_header(name) {
			backend_request = backend_request.header(name, value);
		}
	}
	let forwarded_for = request
		.headers()
		.get("x-forwarded-for")
		.and_then(|value| value.to_str().ok())
		.filter(|value| !value.is_empty())
		.map_or_else(|| remote_ip.to_string(), |value| format!("{value}, {remote_ip}"));
	let forwarded_host = backend_host_override.map(str::to_owned).or_else(|| {
		request
			.headers()
			.get(HOST)
			.and_then(|value| value.to_str().ok())
			.map(str::to_owned)
	});
	backend_request = backend_request
		.header("x-forwarded-for", forwarded_for)
		.header("x-forwarded-proto", "https")
		.header("x-forwarded-port", "443")
		.header("x-real-ip", remote_ip.to_string());
	if let Some(forwarded_host) = forwarded_host {
		backend_request = backend_request.header("x-forwarded-host", forwarded_host);
	}
	if let Some(host) = backend_host_override {
		backend_request = backend_request.header(HOST, host);
	} else if let Some(host) = request
		.headers()
		.get(HOST)
		.and_then(|h| HeaderValue::from_bytes(h.as_bytes()).ok())
	{
		backend_request = backend_request.header(HOST, host);
	}

	let (body_tx, body_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(8);
	backend_request = backend_request.body(Body::wrap_stream(ReceiverStream::new(body_rx)));
	let mut backend_response = tokio::spawn(async move { backend_request.send().await });

	let upload_result = async {
		while let Some(mut chunk) =
			tokio::time::timeout(idle_timeout, stream.recv_data())
				.await
				.map_err(|_| IdleTimeout {
					phase: "client request body",
					duration: idle_timeout,
					response_started: false,
				})?? {
			let remaining = chunk.remaining();
			if remaining != 0 {
				tokio::time::timeout(idle_timeout, body_tx.send(Ok(chunk.copy_to_bytes(remaining))))
					.await
					.map_err(|_| IdleTimeout {
						phase: "backend request body",
						duration: idle_timeout,
						response_started: false,
					})?
					.map_err(|_| eyre::eyre!("backend stopped receiving the request body"))?;
			}
		}
		tokio::time::timeout(idle_timeout, stream.recv_trailers())
			.await
			.map_err(|_| IdleTimeout {
				phase: "client request trailers",
				duration: idle_timeout,
				response_started: false,
			})??;
		Ok::<_, eyre::Report>(())
	}
	.await;
	if let Err(err) = upload_result {
		backend_response.abort();
		_ = backend_response.await;
		return Err(err);
	}
	drop(body_tx);

	let backend_response = match tokio::time::timeout(idle_timeout, &mut backend_response).await {
		Ok(result) => result??,
		Err(_) => {
			backend_response.abort();
			_ = backend_response.await;
			return Err(IdleTimeout {
				phase: "backend response headers",
				duration: idle_timeout,
				response_started: false,
			}
			.into());
		}
	};
	let status = backend_response.status();
	let headers = backend_response.headers().clone();

	let mut response = Response::builder().status(status);
	for (name, value) in &headers {
		if is_forwardable_header(name) {
			response = response.header(name, value);
		}
	}
	let response = response.body(())?;
	stream.send_response(response).await?;

	let mut body_stream = backend_response.bytes_stream();
	while let Some(chunk) = tokio::time::timeout(idle_timeout, body_stream.next())
		.await
		.map_err(|_| IdleTimeout {
			phase: "backend response body",
			duration: idle_timeout,
			response_started: true,
		})? {
		let chunk = chunk?;
		if !chunk.is_empty() {
			stream.send_data(chunk).await?;
		}
	}
	stream.finish().await?;
	Ok(())
}

fn rewrite_target_url(backend: &Url, uri: &Uri) -> eyre::Result<Url> {
	let mut target = backend.clone();
	let path_and_query = uri.path_and_query().map(|v| v.as_str()).unwrap_or("/");
	target.set_path("");
	target.set_query(None);
	let target = target.join(path_and_query)?;
	Ok(target)
}

fn is_forwardable_header(name: &HeaderName) -> bool {
	!matches!(
		name.as_str().to_ascii_lowercase().as_str(),
		"connection" | "keep-alive" | "proxy-connection" | "upgrade" | "te" | "trailer" | "host"
	)
}

fn is_proxy_identity_header(name: &HeaderName) -> bool {
	matches!(
		name.as_str(),
		"x-forwarded-for" | "x-forwarded-host" | "x-forwarded-port" | "x-forwarded-proto" | "x-real-ip"
	)
}
