use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub type BoxedStream = Box<dyn AsyncStream>;

pub type UpgradeFuture = Pin<Box<dyn Future<Output = io::Result<(BoxedStream, String)>> + Send>>;

#[derive(Clone)]
pub struct TlsUpgrader {
    inner: Arc<dyn Fn(BoxedStream) -> UpgradeFuture + Send + Sync>,
}

impl TlsUpgrader {
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(BoxedStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<(BoxedStream, String)>> + Send + 'static,
    {
        TlsUpgrader {
            inner: Arc::new(move |stream| Box::pin(f(stream))),
        }
    }

    pub async fn upgrade(&self, stream: BoxedStream) -> io::Result<(BoxedStream, String)> {
        (self.inner)(stream).await
    }
}
