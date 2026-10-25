//! WebSocket-транспорт для пиров yggdrasil (`ws://`/`wss://`).
//!
//! Go-совместимый протокол — бинарные WebSocket-сообщения с subprotocol
//! `ygg-ws`, поверх которых идёт обычный `meta`-handshake. [`WsIo`] снова
//! превращает поток сообщений в байтовый `AsyncRead`/`AsyncWrite`.

use crate::multicast::supported_schemes;
use futures_util::{Sink, Stream};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config, client_async_with_config,
    tungstenite::{
        Bytes, Error as WsError, Message,
        client::ClientRequestBuilder,
        handshake::server::{ErrorResponse, Request, Response},
        http::{HeaderValue, StatusCode, Uri},
        protocol::WebSocketConfig,
    },
};

const WS_SUBPROTOCOL: &str = "ygg-ws";
const MAX_WS_MESSAGE: usize = 16 * 1024 * 1024;

fn ws_error(error: WsError) -> io::Error {
    match error {
        WsError::Io(error) => error,
        WsError::ConnectionClosed | WsError::AlreadyClosed => {
            io::Error::new(io::ErrorKind::UnexpectedEof, error.to_string())
        }
        other => io::Error::other(other.to_string()),
    }
}

fn ws_config() -> WebSocketConfig {
    let mut config = WebSocketConfig::default();
    // Session writer вызывает `write_all`, но не `flush`; отправляем
    // каждое сообщение сразу, чтобы не ждать заполнения буфера.
    config.write_buffer_size = 0;
    config.max_message_size = Some(MAX_WS_MESSAGE);
    config.max_frame_size = Some(MAX_WS_MESSAGE);
    config
}

fn has_ygg_subprotocol(request: &Request) -> bool {
    request
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|protocol| protocol.trim().eq_ignore_ascii_case(WS_SUBPROTOCOL))
        })
}

#[allow(clippy::result_large_err)]
fn accept_subprotocol(
    request: &Request,
    mut response: Response,
) -> Result<Response, ErrorResponse> {
    if !has_ygg_subprotocol(request) {
        let error = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Some("client must speak the ygg-ws subprotocol".to_owned()));
        return Err(error.unwrap_or_default());
    }
    response.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
    Ok(response)
}

fn response_has_ygg_subprotocol<B>(
    response: &tokio_tungstenite::tungstenite::http::Response<B>,
) -> bool {
    response
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(WS_SUBPROTOCOL))
}

/// Подключиться к WebSocket-серверу поверх уже установленного транспорта.
///
/// `uri` должен содержать исходный host/path/query, даже если TCP-соединение
/// открыто по IP-адресу.
pub async fn client<S>(stream: S, uri: &str) -> io::Result<WsIo<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let uri: Uri = uri.parse().map_err(|error| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad ws URI: {error}"))
    })?;
    let request = ClientRequestBuilder::new(uri).with_sub_protocol(WS_SUBPROTOCOL);
    let (websocket, response) = client_async_with_config(request, stream, Some(ws_config()))
        .await
        .map_err(ws_error)?;
    if !response_has_ygg_subprotocol(&response) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer did not negotiate the ygg-ws subprotocol",
        ));
    }
    Ok(WsIo::new(websocket))
}

/// Принять входящий WebSocket и потребовать subprotocol `ygg-ws`.
pub async fn server<S>(stream: S) -> io::Result<WsIo<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let websocket = accept_hdr_async_with_config(stream, accept_subprotocol, Some(ws_config()))
        .await
        .map_err(ws_error)?;
    Ok(WsIo::new(websocket))
}

/// Установить TLS для `wss://`. Сертификат не проверяется по PKI:
/// подлинность peer'а подтверждает последующий `meta`-handshake.
pub async fn tls_connect(stream: TcpStream, server_name: &str) -> io::Result<TlsStream<TcpStream>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(WebSocketAcceptAnyServer))
        .with_no_client_auth();
    let server_name = ServerName::try_from(server_name.to_owned()).map_err(|error| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad TLS SNI: {error}"))
    })?;
    TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(io::Error::other)
}

/// Тот же verifier, что и у multicast TLS, но с отдельным типом, чтобы
/// WebSocket-клиент не зависел от внутренностей `Multicast`.
#[derive(Debug)]
struct WebSocketAcceptAnyServer;

impl ServerCertVerifier for WebSocketAcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        supported_schemes()
    }
}

/// Байтовый адаптер над потоком WebSocket-сообщений.
pub struct WsIo<S> {
    websocket: WebSocketStream<S>,
    read_buf: Vec<u8>,
    read_pos: usize,
    pending_write: Option<usize>,
}

impl<S> WsIo<S> {
    const fn new(websocket: WebSocketStream<S>) -> Self {
        Self {
            websocket,
            read_buf: Vec::new(),
            read_pos: 0,
            pending_write: None,
        }
    }
}

impl<S> AsyncRead for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.read_pos < self.read_buf.len() {
                let available = self.read_buf.len() - self.read_pos;
                let count = available.min(buf.remaining());
                buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + count]);
                self.read_pos += count;
                return Poll::Ready(Ok(()));
            }
            self.read_buf.clear();
            self.read_pos = 0;

            match Pin::new(&mut self.websocket).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => {
                    let error = ws_error(error);
                    if error.kind() == io::ErrorKind::UnexpectedEof {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Some(Ok(message))) => match message {
                    Message::Binary(bytes) => {
                        if bytes.is_empty() {
                            continue;
                        }
                        self.read_buf = bytes.to_vec();
                    }
                    Message::Text(_) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ygg-ws peer sent a text frame",
                        )));
                    }
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(length) = self.pending_write {
            return match Pin::new(&mut self.websocket).poll_flush(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => {
                    self.pending_write = None;
                    Poll::Ready(Ok(length))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(ws_error(error))),
            };
        }

        match Pin::new(&mut self.websocket).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(ws_error(error))),
            Poll::Ready(Ok(())) => {}
        }
        if let Err(error) =
            Pin::new(&mut self.websocket).start_send(Message::Binary(Bytes::copy_from_slice(buf)))
        {
            return Poll::Ready(Err(ws_error(error)));
        }
        let length = buf.len();
        self.pending_write = Some(length);
        match Pin::new(&mut self.websocket).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                self.pending_write = None;
                Poll::Ready(Ok(length))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(ws_error(error))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.websocket).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending_write = None;
                Poll::Ready(result.map_err(ws_error))
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.websocket)
            .poll_close(cx)
            .map_err(ws_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn websocket_byte_stream_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = server(stream).await.unwrap();
            let mut buffer = [0u8; 4];
            websocket.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"ping");
            websocket.write_all(b"pong").await.unwrap();
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let mut websocket = client(stream, &format!("ws://{address}/")).await.unwrap();
        websocket.write_all(b"ping").await.unwrap();
        let mut buffer = [0u8; 4];
        websocket.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn secure_websocket_roundtrip() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::TlsAcceptor;

        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], private_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(stream).await.unwrap();
            let mut websocket = server(tls).await.unwrap();
            let mut buffer = [0u8; 4];
            websocket.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"ping");
            websocket.write_all(b"pong").await.unwrap();
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let tls = tls_connect(stream, "localhost").await.unwrap();
        let mut websocket = client(tls, &format!("wss://localhost:{}/", address.port()))
            .await
            .unwrap();
        websocket.write_all(b"ping").await.unwrap();
        let mut buffer = [0u8; 4];
        websocket.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"pong");
        server.await.unwrap();
    }
}
