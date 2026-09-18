use std::{
	net::{SocketAddr, TcpListener as StdTcpListener},
	sync::{
		Arc,
		atomic::{AtomicU16, Ordering},
	},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socks5_server::{
	Auth, Command, Server as Socks5Server,
	auth::{NoAuth, Password},
};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::error::Error;

mod handle_task;
mod udp_session;

pub use self::udp_session::UdpSession;

pub struct Server {
	inner: Socks5Server<Result<bool, socks5_proto::handshake::password::Error>>,
	optimistic_open: bool,
	dual_stack: Option<bool>,
	max_pkt_size: usize,
	next_assoc_id: AtomicU16,
}

impl Server {
	pub fn new(
		addr: SocketAddr,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
		username: Option<Vec<u8>>,
		password: Option<Vec<u8>>,
	) -> Result<Self, Error> {
		let socket = {
			let domain = match addr {
				SocketAddr::V4(_) => Domain::IPV4,
				SocketAddr::V6(_) => Domain::IPV6,
			};

			let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
				.map_err(|err| Error::Socket("failed to create socks5 server socket", err))?;

			if addr.is_ipv6()
				&& let Some(dual_stack) = dual_stack
			{
				socket
					.set_only_v6(!dual_stack)
					.map_err(|err| Error::Socket("socks5 server dual-stack socket setting error", err))?;
			}

			socket
				.set_reuse_address(true)
				.map_err(|err| Error::Socket("failed to set socks5 server socket to reuse_address", err))?;

			socket
				.set_nonblocking(true)
				.map_err(|err| Error::Socket("failed setting socks5 server socket as non-blocking", err))?;

			socket
				.bind(&SockAddr::from(addr))
				.map_err(|err| Error::Socket("failed to bind socks5 server socket", err))?;

			socket
				.listen(i32::MAX)
				.map_err(|err| Error::Socket("failed to listen on socks5 server socket", err))?;

			TcpListener::from_std(StdTcpListener::from(socket))
				.map_err(|err| Error::Socket("failed to create socks5 server socket", err))?
		};

		let auth = Arc::new(LocalAuth(match (username, password) {
			(Some(username), Some(password)) => Some(Password::new(username, password)),
			(None, None) => None,
			_ => return Err(Error::InvalidSocks5Auth),
		}));

		Ok(Self {
			inner: Socks5Server::new(socket, auth),
			optimistic_open: true,
			dual_stack,
			max_pkt_size,
			next_assoc_id: AtomicU16::new(0),
		})
	}

	/// Configure optimistic SOCKS5 CONNECT replies (enabled by default).
	pub fn with_optimistic_open(mut self, optimistic_open: bool) -> Self {
		self.optimistic_open = optimistic_open;
		self
	}

	pub async fn start(ctx: Arc<crate::AppContext>) {
		let server = ctx.socks5.clone();

		warn!("[socks5] server started, listening on {}", server.inner.local_addr().unwrap());

		loop {
			match server.inner.accept().await {
				Ok((conn, addr)) => {
					debug!("[socks5] [{addr}] connection established");

					let server = server.clone();
					let ctx = ctx.clone();
					tokio::spawn(async move {
						let conn = match conn.authenticate().await {
							Ok((conn, Ok(true))) => conn,
							Ok(_) => {
								warn!("[socks5] [{addr}] authentication failed");
								return;
							}
							Err((err, _)) => {
								warn!("[socks5] [{addr}] handshake error: {err}");
								return;
							}
						};
						match conn.wait().await {
							Ok(Command::Associate(associate, _)) => {
								let assoc_id = server.next_assoc_id.fetch_add(1, Ordering::Relaxed);
								info!("[socks5] [{addr}] [associate] [{assoc_id:#06x}]");
								Self::handle_associate(associate, assoc_id, server.dual_stack, server.max_pkt_size, ctx).await;
							}
							Ok(Command::Bind(bind, _)) => {
								info!("[socks5] [{addr}] [bind]");
								Self::handle_bind(bind).await;
							}
							Ok(Command::Connect(connect, target_addr)) => {
								info!("[socks5] [{addr}] [connect] {target_addr}");
								Self::handle_connect(connect, target_addr, ctx).await;
							}
							Err((err, _)) => warn!("[socks5] [{addr}] command error: {err}"),
						};

						debug!("[socks5] [{addr}] connection closed");
					});
				}
				Err(err) => warn!("[socks5] failed to establish connection: {err}"),
			}
		}
	}
}

// Normalize both authentication methods to a result that must be checked before
// accepting commands; socks5-server no longer rejects failed passwords for us.
struct LocalAuth(Option<Password>);

#[async_trait::async_trait]
impl Auth for LocalAuth {
	type Output = Result<bool, socks5_proto::handshake::password::Error>;

	fn as_handshake_method(&self) -> socks5_proto::handshake::Method {
		match &self.0 {
			Some(auth) => auth.as_handshake_method(),
			None => NoAuth.as_handshake_method(),
		}
	}

	async fn execute(&self, stream: &mut tokio::net::TcpStream) -> Self::Output {
		match &self.0 {
			Some(auth) => auth.execute(stream).await,
			None => Ok(true),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	#[tokio::test]
	async fn password_authentication_checks_credentials() {
		for password in [b"pass".as_slice(), b"nope".as_slice()] {
			let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
			let addr = listener.local_addr().unwrap();
			let server = Socks5Server::new(
				listener,
				Arc::new(LocalAuth(Some(Password::new(b"user".to_vec(), b"pass".to_vec())))),
			);
			let task = tokio::spawn(async move {
				let (conn, _) = server.accept().await.unwrap();
				let (_, result) = conn.authenticate().await.unwrap();
				result.unwrap()
			});
			let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
			client.write_all(&[5, 1, 2]).await.unwrap();
			let mut reply = [0; 2];
			client.read_exact(&mut reply).await.unwrap();
			assert_eq!(reply, [5, 2]);
			client.write_all(b"\x01\x04user\x04").await.unwrap();
			client.write_all(password).await.unwrap();
			client.read_exact(&mut reply).await.unwrap();
			let accepted = password == b"pass";
			assert_eq!(reply[0], 1);
			assert_eq!(reply[1] == 0, accepted);
			assert_eq!(task.await.unwrap(), accepted);
		}
	}
}
