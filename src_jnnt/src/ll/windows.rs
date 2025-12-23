use std::io;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[cfg(target_os = "windows")]
use pcap::{Active, Capture, sendqueue::SendQueue};

pub struct WindowsRawSocket {
    capture: Arc<Mutex<Capture<Active>>>,
    send_queue: Arc<Mutex<SendQueue>>,
    rx_channel: mpsc::UnboundedReceiver<Vec<u8>>,
    _rx_task: JoinHandle<()>,
    bound_interface: Arc<Mutex<Option<String>>>,
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
            Mutex::new(
                SendQueue::new(1024 * 1024)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create send queue: {}", e)))?
            ),
        );

        let capture = Arc::new(Mutex::new(cap));
        let (tx, rx) = mpsc::unbounded_channel();

        // Spawn background task to read packets
        let capture_clone = capture.clone();
        let rx_task = tokio::task::spawn_blocking(move || {
            loop {
                let packet_data = {
                    let mut cap_guard = match capture_clone.lock() {
                        Ok(guard) => guard,
                        Err(_) => break, // Mutex poisoned, exit
                    };
                    
                    // Extract data while guard is alive, since Packet borrows from Capture
                    match cap_guard.next_packet() {
                        Ok(packet) => {
                            // Reduced debug output - only log every 100th packet
                            Some(packet.data.to_vec())
                        },
                        Err(e) => {
                            // Drop guard before handling error
                            drop(cap_guard);
                            match e {
                                pcap::Error::NoMorePackets => {
                                    // No packets available, yield to avoid busy-waiting
                                    std::thread::yield_now();
                                    continue;
                                }
                                pcap::Error::TimeoutExpired => {
                                    // Timeout, continue
                                    continue;
                                }
                                _e => {
                                    // Error occurred, break
                                    break;
                                }
                            }
                        }
                    }
                };

                // Now we can use the packet data (owned Vec) without the guard
                if let Some(data) = packet_data {
                    if tx.send(data).is_err() {
                        // Receiver dropped, exit
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
            bound_interface: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn bind(&mut self, interface: &str) -> io::Result<()> {
        // Check if we're already bound to this interface
        {
            let bound = self.bound_interface.lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Mutex poisoned"))?;
            if let Some(ref bound_name) = *bound {
                if bound_name == interface {
                    return Ok(());
                }
            }
        }
        
        // Close old capture by dropping it (the Arc will handle cleanup)
        // Create new capture on the specified interface
        let new_cap = Capture::from_device(interface)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open device {}: {}", interface, e)))?
            .immediate_mode(true)
            .open()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open capture: {}", e)))?
            .setnonblock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set non-blocking: {}", e)))?;
        
        // Replace the old capture with the new one
        {
            let mut cap_guard = self.capture.lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Capture mutex poisoned"))?;
            *cap_guard = new_cap;
        }
        
        // Update bound interface
        {
            let mut bound = self.bound_interface.lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Mutex poisoned"))?;
            *bound = Some(interface.to_string());
        }
        
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
        let mut send_queue_guard = match me.send_queue.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Send queue mutex poisoned",
                )));
            }
        };
        
        match send_queue_guard.queue(None, buf) {
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
                match send_queue_guard.transmit(&mut *cap_guard, pcap::sendqueue::SendSync::Off) {
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

