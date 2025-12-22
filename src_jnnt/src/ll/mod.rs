#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "linux")]
pub mod io_uring;
#[cfg(target_os = "macos")]
mod bpf;
#[cfg(target_os = "windows")]
mod windows;

use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(target_os = "linux")]
use linux::LinuxRawSocket;
#[cfg(target_os = "macos")]
use bpf::BpfRawSocket;
#[cfg(target_os = "windows")]
use windows::WindowsRawSocket;

#[cfg(target_os = "linux")]
pub enum RawSocketImpl {
    Linux(LinuxRawSocket),
}

#[cfg(target_os = "macos")]
pub enum RawSocketImpl {
    Bpf(BpfRawSocket),
}

#[cfg(target_os = "windows")]
pub enum RawSocketImpl {
    Windows(WindowsRawSocket),
}

pub struct RawSocket {
    inner: RawSocketImpl,
}

impl RawSocket {
    #[cfg(target_os = "linux")]
    pub async fn new() -> io::Result<Self> {
        let inner = LinuxRawSocket::new().await?;
        Ok(Self {
            inner: RawSocketImpl::Linux(inner),
        })
    }

    #[cfg(target_os = "macos")]
    pub async fn new() -> io::Result<Self> {
        let inner = BpfRawSocket::new().await?;
        Ok(Self {
            inner: RawSocketImpl::Bpf(inner),
        })
    }

    #[cfg(target_os = "windows")]
    pub async fn new() -> io::Result<Self> {
        let inner = WindowsRawSocket::new().await?;
        Ok(Self {
            inner: RawSocketImpl::Windows(inner),
        })
    }

    pub async fn bind(&mut self, interface: &str) -> io::Result<()> {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            RawSocketImpl::Linux(socket) => socket.bind(interface).await,
            #[cfg(target_os = "macos")]
            RawSocketImpl::Bpf(socket) => socket.bind(interface).await,
            #[cfg(target_os = "windows")]
            RawSocketImpl::Windows(socket) => socket.bind(interface).await,
        }
    }

    pub async fn set_filter(&mut self, filter: &str) -> io::Result<()> {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            RawSocketImpl::Linux(socket) => socket.set_filter(filter).await,
            #[cfg(target_os = "macos")]
            RawSocketImpl::Bpf(socket) => socket.set_filter(filter).await,
            #[cfg(target_os = "windows")]
            RawSocketImpl::Windows(socket) => socket.set_filter(filter).await,
        }
    }
}

impl AsyncRead for RawSocket {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            #[cfg(target_os = "linux")]
            RawSocketImpl::Linux(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncRead::poll_read(pin, cx, buf)
            }
            #[cfg(target_os = "macos")]
            RawSocketImpl::Bpf(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncRead::poll_read(pin, cx, buf)
            }
            #[cfg(target_os = "windows")]
            RawSocketImpl::Windows(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncRead::poll_read(pin, cx, buf)
            }
        }
    }
}

impl AsyncWrite for RawSocket {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match &mut self.get_mut().inner {
            #[cfg(target_os = "linux")]
            RawSocketImpl::Linux(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncWrite::poll_write(pin, cx, buf)
            }
            #[cfg(target_os = "macos")]
            RawSocketImpl::Bpf(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncWrite::poll_write(pin, cx, buf)
            }
            #[cfg(target_os = "windows")]
            RawSocketImpl::Windows(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncWrite::poll_write(pin, cx, buf)
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match &mut self.get_mut().inner {
            #[cfg(target_os = "linux")]
            RawSocketImpl::Linux(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncWrite::poll_flush(pin, cx)
            }
            #[cfg(target_os = "macos")]
            RawSocketImpl::Bpf(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncWrite::poll_flush(pin, cx)
            }
            #[cfg(target_os = "windows")]
            RawSocketImpl::Windows(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncWrite::poll_flush(pin, cx)
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match &mut self.get_mut().inner {
            #[cfg(target_os = "linux")]
            RawSocketImpl::Linux(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncWrite::poll_shutdown(pin, cx)
            }
            #[cfg(target_os = "macos")]
            RawSocketImpl::Bpf(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncWrite::poll_shutdown(pin, cx)
            }
            #[cfg(target_os = "windows")]
            RawSocketImpl::Windows(socket) => {
                let pin = unsafe { std::pin::Pin::new_unchecked(socket) };
                AsyncWrite::poll_shutdown(pin, cx)
            }
        }
    }
}

