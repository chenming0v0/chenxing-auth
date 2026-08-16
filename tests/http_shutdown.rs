//! Issue #520：慢客户端不读响应体时，进程关闭必须在 HTTP drain 截止时间内结束。
//!
//! 应用请求超时只包住 handler future。静态资源和这里这种已经开始写出的响应体
//! 不受那一层限制。Axum graceful shutdown 会一直等连接任务，外层若无总截止时间，
//! `server.await` 会把 worker 的有界 drain 一起拖死。

use std::time::Duration;

use axum::{Router, routing::get};
use chenxing_auth::{
    shutdown,
    workers::{WorkerHealth, WorkerName, WorkerSupervisor},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::oneshot,
};

const HTTP_DRAIN: Duration = Duration::from_millis(200);
const BODY_BYTES: usize = 16 * 1024 * 1024;

#[tokio::test]
async fn unread_response_body_does_not_block_bounded_process_shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind shutdown fixture");
    let address = listener.local_addr().expect("listener address");

    let (worker_saw_shutdown, worker_notified) = oneshot::channel();
    let mut workers = WorkerSupervisor::new(WorkerHealth::new());
    workers.spawn(WorkerName::IssuerSync, move |mut context| async move {
        context.wait_for_shutdown().await;
        let _ = worker_saw_shutdown.send(());
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let serve = tokio::spawn(shutdown::serve_until(
        listener,
        large_body_router(),
        workers,
        HTTP_DRAIN,
        async {
            let _ = shutdown_rx.await;
        },
    ));

    let mut client = connect_without_reading_body(address).await;
    let headers = read_http_headers(&mut client).await;
    assert!(
        headers.starts_with(b"HTTP/1.1 200"),
        "fixture must start sending a real response before shutdown"
    );

    let started = tokio::time::Instant::now();
    shutdown_tx.send(()).expect("shutdown trigger");

    tokio::time::timeout(Duration::from_millis(50), worker_notified)
        .await
        .expect("worker drain must start with HTTP, not after unbounded server.await")
        .expect("cooperative worker must observe shutdown");

    tokio::time::timeout(HTTP_DRAIN + Duration::from_millis(300), serve)
        .await
        .expect("process shutdown must finish within the HTTP drain deadline")
        .expect("serve task")
        .expect("bounded shutdown is success after leftover connections are aborted");

    assert!(
        started.elapsed() < HTTP_DRAIN + Duration::from_millis(300),
        "unread body must not keep the process past the HTTP drain deadline"
    );
}

fn large_body_router() -> Router {
    Router::new().route(
        "/slow",
        get(|| async { axum::body::Body::from(vec![0_u8; BODY_BYTES]) }),
    )
}

async fn connect_without_reading_body(address: std::net::SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().expect("client socket");
    socket
        .set_recv_buffer_size(512)
        .expect("shrink client receive window so the large body cannot drain");
    let mut stream = socket.connect(address).await.expect("connect to fixture");
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");
    stream
}

async fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .expect("response header byte");
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            return headers;
        }
        assert!(
            headers.len() < 16 * 1024,
            "response headers stayed within a reasonable bound"
        );
    }
}
