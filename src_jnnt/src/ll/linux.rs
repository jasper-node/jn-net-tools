use libc;
use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// Linux constants
const ETH_P_ALL: u16 = 0x0003;

pub struct LinuxRawSocket {
    lower: i32,
    async_fd: AsyncFd<RawFd>,
}

unsafe impl Send for LinuxRawSocket {}
unsafe impl Sync for LinuxRawSocket {}

impl LinuxRawSocket {
    pub async fn new() -> io::Result<Self> {
        let protocol = (ETH_P_ALL as u16).to_be() as i32;

        let lower = unsafe {
            let lower = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                protocol,
            );
            if lower == -1 {
                return Err(io::Error::last_os_error());
            }
            lower
        };

        match AsyncFd::new(lower) {
            Ok(async_fd) => Ok(Self {
                lower,
                async_fd,
            }),
            Err(e) => {
                unsafe { libc::close(lower) };
                Err(e)
            }
        }
    }

    pub async fn bind(&mut self, interface: &str) -> io::Result<()> {
        let c_str = std::ffi::CString::new(interface)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Get interface index using if_nametoindex (more portable)
        let ifindex = unsafe {
            let index = libc::if_nametoindex(c_str.as_ptr() as *const _);
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            index as i32
        };

        let protocol = (ETH_P_ALL as u16).to_be();

        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: protocol,
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        unsafe {
            let res = libc::bind(
                self.lower,
                &sockaddr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
            if res == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    pub async fn set_filter(&mut self, _filter: &str) -> io::Result<()> {
        // sniff::capture::matches_filter applies the filter in userspace on every
        // platform, so compiling it to BPF here only narrowed what userspace
        // narrows anyway — and cost a libpcap.so.0.8 DT_NEEDED that every field
        // device had to satisfy. macOS has always run without a kernel filter.
        Ok(())
    }
}

impl AsyncRead for LinuxRawSocket {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            let mut guard = match me.async_fd.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(g)) => g,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            let fd = me.lower as RawFd;
            // Use unfilled buffer space directly
            let result = unsafe {
                libc::read(
                    fd,
                    buf.unfilled_mut().as_mut_ptr() as *mut libc::c_void,
                    buf.remaining(),
                )
            };

            guard.clear_ready();

            if result < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                return std::task::Poll::Ready(Err(err));
            } else {
                unsafe { buf.assume_init(result as usize) };
                buf.advance(result as usize);
                return std::task::Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for LinuxRawSocket {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        let me = self.get_mut();
        loop {
            let mut guard = match me.async_fd.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(g)) => g,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            let fd = me.lower as RawFd;
            let result = unsafe {
                libc::write(
                    fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                )
            };

            guard.clear_ready();

            if result < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                return std::task::Poll::Ready(Err(err));
            } else {
                return std::task::Poll::Ready(Ok(result as usize));
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsRawFd for LinuxRawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}
