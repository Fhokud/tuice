use std::sync::Arc;

use socks5_proto::{Address, Reply};
use socks5_server::{
	Associate, Bind, Connect,
	connection::{associate, bind, connect},
};
use tokio::io;
use tracing::{debug, info, warn};
use tuic_core::Address as TuicAddress;

use super::{Server, udp_session::UdpSession};
use crate::connection::ERROR_CODE;

impl Server {
	pub async fn handle_associate(
		assoc: Associate<associate::NeedReply>,
		assoc_id: u16,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
		ctx: Arc<crate::AppContext>,
	) {
		let peer_addr = assoc.peer_addr().unwrap();
		let local_ip = assoc.local_addr().unwrap().ip();

		info!(
			"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] starting UDP associate, local_ip: {local_ip}, dual_stack: \
			 {:?}",
			dual_stack
		);

		// Check for existing session with same ID
		{
			let sessions = ctx.socks5_udp_sessions.read().await;
			if sessions.contains_key(&assoc_id) {
				warn!(
					"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] session ID already exists! This may cause conflicts"
				);
			}
		}

		match UdpSession::new(assoc_id, peer_addr, local_ip, dual_stack, max_pkt_size) {
			Ok(session) => {
				let local_addr = session.local_addr().unwrap();
				info!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] bound to {local_addr}");

				let mut assoc = match assoc.reply(Reply::Succeeded, Address::SocketAddress(local_addr)).await {
					Ok(assoc) => assoc,
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}");
						return;
					}
				};

				{
					ctx.socks5_udp_sessions.write().await.insert(assoc_id, session.clone());
				}

				let ctx_loop = ctx.clone();
				let handle_local_incoming_pkt = async move {
					loop {
						let (pkt, target_addr) = match session.recv().await {
							Ok(res) => res,
							Err(err) => {
								warn!(
									"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed to receive UDP packet: {err}"
								);
								continue;
							}
						};

						let ctx_fwd = ctx_loop.clone();
						let forward = async move {
							let target_addr = match target_addr {
								Address::DomainAddress(domain, port) => TuicAddress::DomainAddress(domain, port),
								Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
							};

							match ctx_fwd.get_conn().await {
								Ok(conn) => conn.packet(pkt, target_addr, assoc_id).await,
								Err(err) => Err(err)?,
							}
						};

						tokio::spawn(async move {
							match forward.await {
								Ok(()) => {}
								Err(err) => {
									warn!(
										"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed relaying UDP packet: \
										 {err}"
									);
								}
							}
						});
					}
				};

				match tokio::select! {
					res = assoc.wait_until_closed() => res,
					_ = handle_local_incoming_pkt => unreachable!(),
				} {
					Ok(()) => {}
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] associate connection error: {err}")
					}
				}

				debug!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] stopped associating");

				{
					ctx.socks5_udp_sessions.write().await.remove(&assoc_id).unwrap();
				}

				if let Ok(conn) = ctx.get_conn().await
					&& let Err(err) = conn.dissociate(assoc_id).await
				{
					warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed stopping UDP relaying session: {err}")
				}
			}
			Err(err) => {
				warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed setting up UDP associate session: {err}");

				match assoc.reply(Reply::GeneralFailure, Address::unspecified()).await {
					Ok(mut assoc) => {
						let _ = assoc.shutdown().await;
					}
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}")
					}
				}
			}
		}
	}

	pub async fn handle_bind(bind: Bind<bind::NeedFirstReply>) {
		let peer_addr = bind.peer_addr().unwrap();
		warn!("[socks5] [{peer_addr}] [bind] command not supported");

		match bind.reply(Reply::CommandNotSupported, Address::unspecified()).await {
			Ok(mut bind) => {
				let _ = bind.shutdown().await;
			}
			Err(err) => warn!("[socks5] [{peer_addr}] [bind] command reply error: {err}"),
		}
	}

	pub async fn handle_connect(conn: Connect<connect::NeedReply>, addr: Address, ctx: Arc<crate::AppContext>) {
		let peer_addr = conn.peer_addr().unwrap();
		let target_addr = match addr {
			Address::DomainAddress(domain, port) => TuicAddress::DomainAddress(domain, port),
			Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
		};

		let relay = async { ctx.get_conn().await?.connect(target_addr.clone()).await };

		match connect_with_reply(conn, ctx.socks5.optimistic_open, relay).await {
			Ok((mut conn, mut relay)) => {
				if let Err(err) = io::copy_bidirectional(&mut conn, &mut relay).await {
					let _ = conn.shutdown().await;
					let _ = relay.reset(ERROR_CODE);
					warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] TCP stream relaying error: {err}");
				}
			}
			Err(err) => warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] unable to relay TCP stream: {err}"),
		}
	}
}

/// Keep the reply ordering independent of relay setup so optimistic open also works
/// while the first QUIC connection is still being established. Buffered client
/// data stays in the TCP receive buffer until setup completes (bounded by TCP).
async fn connect_with_reply<T>(
	conn: Connect<connect::NeedReply>,
	optimistic_open: bool,
	relay: impl std::future::Future<Output = Result<T, crate::error::Error>>,
) -> io::Result<(Connect<connect::Ready>, T)> {
	if optimistic_open {
		let mut conn = conn.reply(Reply::Succeeded, Address::unspecified()).await?;
		match relay.await {
			Ok(relay) => Ok((conn, relay)),
			Err(err) => {
				// Success has already been sent: never send a second SOCKS5 reply.
				let _ = conn.shutdown().await;
				Err(io::Error::other(err))
			}
		}
	} else {
		match relay.await {
			Ok(relay) => {
				let conn = conn.reply(Reply::Succeeded, Address::unspecified()).await?;
				Ok((conn, relay))
			}
			Err(err) => {
				let mut conn = conn.reply(Reply::GeneralFailure, Address::unspecified()).await?;
				let _ = conn.shutdown().await;
				Err(io::Error::other(err))
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use std::{sync::Arc, time::Duration};

	use socks5_server::{Connection, Server as Socks5Server, auth::NoAuth};
	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt},
		net::{TcpListener, TcpStream},
		sync::oneshot,
		time::timeout,
	};

	use super::connect_with_reply;

	async fn check_reply_order(optimistic_open: bool, fail: bool) {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		let server = Socks5Server::new(listener, Arc::new(NoAuth));
		let (release, wait) = oneshot::channel::<()>();
		let task = tokio::spawn(async move {
			let (conn, _) = server.accept().await.unwrap();
			let Connection::Connect(conn, _) = conn.handshake().await.unwrap() else {
				panic!("expected CONNECT");
			};
			let result = connect_with_reply(conn, optimistic_open, async {
				wait.await.unwrap();
				if fail { Err(crate::error::Error::Timeout) } else { Ok(()) }
			})
			.await;
			if fail {
				assert!(result.is_err());
			} else {
				let (mut conn, ()) = result.unwrap();
				let mut data = [0; 5];
				conn.read_exact(&mut data).await.unwrap();
				assert_eq!(&data, b"hello");
				conn.write_all(&data).await.unwrap();
			}
		});
		let mut client = TcpStream::connect(addr).await.unwrap();
		client.write_all(&[5, 1, 0]).await.unwrap();
		let mut auth = [0; 2];
		client.read_exact(&mut auth).await.unwrap();
		assert_eq!(auth, [5, 0]);
		client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await.unwrap();
		let mut reply = [0; 10];
		if optimistic_open {
			client.read_exact(&mut reply).await.unwrap();
			assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
			if !fail {
				client.write_all(b"hello").await.unwrap();
			}
		} else {
			// Relay setup is explicitly blocked; no reply may arrive yet.
			assert!(timeout(Duration::from_millis(50), client.read_u8()).await.is_err());
		}
		release.send(()).unwrap();
		if !optimistic_open {
			client.read_exact(&mut reply).await.unwrap();
			assert_eq!(reply, [5, u8::from(fail), 0, 1, 0, 0, 0, 0, 0, 0]);
			if !fail {
				client.write_all(b"hello").await.unwrap();
			}
		}
		let mut remaining = Vec::new();
		client.read_to_end(&mut remaining).await.unwrap();
		assert_eq!(remaining.as_slice(), if fail { &b""[..] } else { &b"hello"[..] });
		task.await.unwrap();
	}

	#[tokio::test]
	async fn optimistic_open_reply_order_and_failure() {
		for optimistic_open in [true, false] {
			for fail in [true, false] {
				timeout(Duration::from_secs(5), check_reply_order(optimistic_open, fail))
					.await
					.unwrap();
			}
		}
	}
}
