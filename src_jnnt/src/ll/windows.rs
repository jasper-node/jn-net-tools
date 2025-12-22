use std::io;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[cfg(target_os = "windows")]
use pcap::{Active, Capture, Device, sendqueue::SendQueue};

pub struct WindowsRawSocket {
    capture: Arc<Mutex<Capture<Active>>>,
    send_queue: Arc<SendQueue>,
    rx_channel: mpsc::UnboundedReceiver<Vec<u8>>,
    _rx_task: JoinHandle<()>,
}

impl WindowsRawSocket {
    pub async fn new() -> io::Result<Self> {
        // Use pnet_datalink to find the default or first available interface
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces.iter()
            .find(|i| !i.is_loopback() && !i.ips.is_empty())
            .or_else(|| interfaces.iter().next())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No network interface found"))?;

        let cap = Capture::from_device(interface.name.as_str())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open device {}: {}", interface.name, e)))?
            .immediate_mode(true)
            .open()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open capture: {}", e)))?
            .setnonblock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set non-blocking: {}", e)))?;

        let send_queue = Arc::new(
            SendQueue::new(1024 * 1024)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create send queue: {}", e)))?,
        );

        let capture = Arc::new(Mutex::new(cap));
        let (tx, rx) = mpsc::unbounded_channel();

        // Spawn background task to read packets
        let capture_clone = capture.clone();
        let rx_task = tokio::task::spawn_blocking(move || {
            loop {
                let packet_result = {
                    let mut cap_guard = match capture_clone.lock() {
                        Ok(guard) => guard,
                        Err(_) => break, // Mutex poisoned, exit
                    };
                    cap_guard.next_packet()
                };

                match packet_result {
                    Ok(packet) => {
                        let data = packet.data.to_vec();
                        if tx.send(data).is_err() {
                            // Receiver dropped, exit
                            break;
                        }
                    }
                    Err(pcap::Error::NoMorePackets) => {
                        // No packets available, yield to avoid busy-waiting
                        std::thread::yield_now();
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Timeout, continue
                        continue;
                    }
                    Err(e) => {
                        // Error occurred, log and continue or break
                        eprintln!("Packet receive error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(Self {
            capture,
            send_queue,
            rx_channel: rx,
            _rx_task: rx_task,
        })
    }

    pub async fn bind(&mut self, _interface: &str) -> io::Result<()> {
        // On Windows, the device is already bound when we open it
        // We could verify the interface name matches, but for now just return OK
        Ok(())
    }

    pub async fn set_filter(&mut self, filter: &str) -> io::Result<()> {
        let mut cap_guard = self.capture.lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Capture mutex poisoned"))?;
        
        cap_guard.filter(filter, true)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set filter: {}", e)))?;
        
        Ok(())
    }
}

impl AsyncRead for WindowsRawSocket {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.rx_channel.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let to_copy = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_copy]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                // Channel closed
                std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Packet receive channel closed",
                )))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for WindowsRawSocket {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        let me = self.get_mut();
        
        // Queue the packet
        match me.send_queue.queue(None, buf) {
            Ok(_) => {
                // Transmit immediately (synchronous for now)
                // In a more sophisticated implementation, we might batch packets
                let mut cap_guard = match me.capture.lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        return std::task::Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Capture mutex poisoned",
                        )));
                    }
                };
                match me.send_queue.transmit(&mut *cap_guard, pcap::sendqueue::SendSync::Off) {
                    Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
                    Err(e) => std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to transmit packet: {}", e),
                    ))),
                }
            }
            Err(e) => std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to queue packet: {}", e),
            ))),
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

