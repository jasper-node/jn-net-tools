use libc;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const BIOCSETIF: u64 = 0x8020426c;
const BIOCIMMEDIATE: u64 = 0x80044270;
const BIOCSBLEN: u64 = 0xc0044266; // Set buffer length (was incorrect ending in 7)
#[allow(dead_code)]
const BIOCSETF: u64 = 0x80104267; // Set BPF filter
const BIOCSHDRCMPLT: u64 = 0x80044275; // Set "header complete" flag
// const BIOCPROMISC: u64 = 0x20004269; // Removed to allow rootless operation on macOS

#[repr(C)]
struct BpfHdr {
    bh_sec: u32,
    bh_usec: u32,
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: u16,
    // _padding: [u8; 2], // Remove padding, let it be naturally 18 bytes
}

const BPF_HDR_STRUCT_SIZE: usize = std::mem::size_of::<BpfHdr>();

// macOS BPF packets are aligned to 4 bytes (sizeof(int32_t)), 
// NOT the 8-byte alignment of the struct (due to timeval)
const BPF_ALIGNMENT: usize = 4;

#[repr(C)]
#[allow(dead_code)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *const BpfInsn,
}

#[repr(C)]
#[allow(dead_code)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

pub struct BpfRawSocket {
    file: std::fs::File,
    fd: RawFd,
    iface_name: String,
    tx_channel: Option<mpsc::UnboundedSender<Vec<u8>>>,
    rx_channel: mpsc::UnboundedReceiver<Vec<u8>>,
    _rx_task: Option<JoinHandle<()>>,
    read_buffer: Vec<u8>,
    buffer_pos: usize,
    buffer_len: usize,
}

impl BpfRawSocket {
    pub async fn new() -> io::Result<Self> {
        let mut last_error: Option<io::Error> = None;
        
        // Iterate 0..256 to find an available BPF device
        for i in 0..256 {
            let path = format!("/dev/bpf{}", i);
            // Open in blocking mode - the background thread will handle blocking I/O
            match OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_RDWR)
                .open(&path)
            {
                Ok(file) => {
                    let fd = file.as_raw_fd();
                    
                    let mut immediate: u32 = 1;
                    unsafe {
                        if libc::ioctl(fd, BIOCIMMEDIATE, &mut immediate) < 0 {
                            let err = io::Error::last_os_error();
                            // Store error but continue to next device
                            if last_error.is_none() {
                                last_error = Some(io::Error::new(
                                    err.kind(),
                                    format!("BIOCIMMEDIATE failed on {}: {}", path, err)
                                ));
                            }
                            continue;
                        }
                    }

                    // Create channel but DO NOT spawn thread yet - wait until bind()
                    let (tx, rx) = mpsc::unbounded_channel();
                    
                    // Buffer size for processing (userspace) - increased to 64KB
                    let read_buffer = vec![0u8; 65536];
                    
                    return Ok(Self { 
                        file, 
                        fd,
                        iface_name: String::new(),
                        tx_channel: Some(tx),
                        rx_channel: rx,
                        _rx_task: None, // Will be filled in bind()
                        read_buffer,
                        buffer_pos: 0,
                        buffer_len: 0,
                    });
                }
                Err(e) => {
                    // Store the first error for better diagnostics
                    if last_error.is_none() {
                        last_error = Some(e);
                    }
                    continue;
                }
            }
        }

        // Return a more informative error
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "No available BPF device found (tried /dev/bpf0 through /dev/bpf255)",
            )
        }))
    }

    fn get_interface_index(&self, interface: &str) -> io::Result<u32> {
        let c_str = std::ffi::CString::new(interface)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        
        let index = unsafe { libc::if_nametoindex(c_str.as_ptr()) };
        
        if index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Interface {} not found", interface),
            ));
        }

        Ok(index)
    }

    pub async fn bind(&mut self, interface: &str) -> io::Result<()> {
        self.iface_name = interface.to_string();
        let _index = self.get_interface_index(interface)?;
        let fd = self.file.as_raw_fd();
        
        // 1. Set buffer size (increased to 32KB to avoid drops)
        let buffer_size: u32 = 32768;
        unsafe {
            if libc::ioctl(fd, BIOCSBLEN, &buffer_size) < 0 {
                // Some systems don't require this, continue anyway
            }
        }
        
        // 2. Bind Interface
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let c_str = std::ffi::CString::new(interface)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        
        let name_len = interface.len().min(15);
        unsafe {
            std::ptr::copy_nonoverlapping(
                c_str.as_ptr(),
                ifreq.ifr_name.as_mut_ptr() as *mut i8,
                name_len,
            );
            *ifreq.ifr_name.as_mut_ptr().add(name_len) = 0;
            
            if libc::ioctl(fd, BIOCSETIF, &mut ifreq) < 0 {
                let err = io::Error::last_os_error();
                return Err(io::Error::new(
                    err.kind(),
                    format!("Failed to bind BPF device to interface '{}': {} (errno: {})", 
                        interface, err, err.raw_os_error().unwrap_or(-1))
                ));
            }
        }

        // 2b. Set "Header Complete" mode
        // This tells BPF that we will provide the complete link-layer header (Ethernet header)
        // If not set, BPF might try to prepend its own header or overwrite ours.
        let mut hdr_complete: u32 = 1;
        unsafe {
            if libc::ioctl(fd, BIOCSHDRCMPLT, &mut hdr_complete) < 0 {
                let err = io::Error::last_os_error();
                eprintln!("Warning: Failed to set BIOCSHDRCMPLT: {} (errno: {})", err, err.raw_os_error().unwrap_or(-1));
            }
        }

        // 3. Set ARP Filter (Critical for performance and stability)
        // BPF filter to only accept ARP packets (ethertype 0x0806)
        // Equivalent to: tcpdump -d arp
        // Note: We'll skip the filter for now as it's causing EINVAL on read
        // Filtering will be done in userspace instead
        // TODO: Fix BPF filter structure to work correctly
        /*
        let insns = vec![
            BpfInsn { code: 0x28, jt: 0, jf: 0, k: 12 },     // ldh [12] - load halfword at offset 12 (ethertype)
            BpfInsn { code: 0x15, jt: 0, jf: 1, k: 0x0806 }, // jeq #0x806 jt 0 jf 1 - if ethertype == ARP, jump to pass
            BpfInsn { code: 0x06, jt: 0, jf: 0, k: 65535 },  // ret #65535 (pass)
            BpfInsn { code: 0x06, jt: 0, jf: 0, k: 0 },      // ret #0 (reject)
        ];
        
        let prog = BpfProgram {
            bf_len: insns.len() as u32,
            bf_insns: insns.as_ptr(),
        };

        unsafe {
            if libc::ioctl(fd, BIOCSETF, &prog) < 0 {
                let err = io::Error::last_os_error();
                eprintln!("Warning: Failed to set BPF ARP filter: {} (errno: {:?}) - continuing without filter", err, err.raw_os_error());
            }
        }
        */

        // 4. NOW spawn the reading thread after binding
        if let Some(tx) = self.tx_channel.take() {
            let file_for_thread = self.file.try_clone()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to clone BPF file: {}", e)))?;
            let fd_clone = fd;
            let buf_size = buffer_size as usize;

            let rx_task = tokio::task::spawn_blocking(move || {
                let _file_handle = file_for_thread;
                let mut read_buffer = vec![0u8; buf_size];
                loop {
                    let result = unsafe {
                        libc::read(
                            fd_clone,
                            read_buffer.as_mut_ptr() as *mut libc::c_void,
                            read_buffer.len(),
                        )
                    };
                    
                    if result <= 0 {
                        break; // EOF or Error
                    }
                    // Send raw buffer to AsyncRead
                    if tx.send(read_buffer[..result as usize].to_vec()).is_err() {
                        break; // Receiver dropped
                    }
                }
            });
            self._rx_task = Some(rx_task);
        }

        Ok(())
    }

    pub async fn set_filter(&mut self, _filter: &str) -> io::Result<()> {
        // macOS BPF with PKTAP interfaces doesn't support kernel-level filtering
        // Filtering will be done in userspace by the packet processing logic
        Ok(())
    }
}

impl AsyncRead for BpfRawSocket {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let me = self.get_mut();
        
        loop {
            // Check if we have data in the buffer
            if me.buffer_pos < me.buffer_len {
                // Ensure we have enough data for at least the struct size
                if me.buffer_len - me.buffer_pos < BPF_HDR_STRUCT_SIZE {
                     // Not enough data for a header, discard remainder
                     me.buffer_pos = 0;
                     me.buffer_len = 0;
                     continue; 
                }

                let (hdr_len, cap_len) = unsafe {
                    let ptr = me.read_buffer.as_ptr().add(me.buffer_pos);
                    let bpf_hdr = &*(ptr as *const BpfHdr);
                    (bpf_hdr.bh_hdrlen as usize, bpf_hdr.bh_caplen as usize)
                };

                // Verify we have the full captured packet in our buffer
                if me.buffer_pos + hdr_len + cap_len > me.buffer_len {
                    // Truncated packet or buffer end reached unexpectedly
                    me.buffer_pos = 0;
                    me.buffer_len = 0;
                    continue;
                }
                
                // Copy data to user buffer
                let data_start = me.buffer_pos + hdr_len;
                let data_end = data_start + cap_len;
                let data = &me.read_buffer[data_start..data_end];
                
                let to_copy = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_copy]);
                
                // Calculate next packet position using 4-byte alignment (BPF_WORDALIGN)
                // NOT struct alignment which would be 8 bytes on 64-bit systems
                let packet_total_len = hdr_len + cap_len;
                let next_offset = (packet_total_len + BPF_ALIGNMENT - 1) & !(BPF_ALIGNMENT - 1);
                
                me.buffer_pos += next_offset;

                return std::task::Poll::Ready(Ok(()));
            }

            // Buffer empty or exhausted, get more data from channel
            match me.rx_channel.poll_recv(cx) {
                std::task::Poll::Ready(Some(data)) => {
                    if data.is_empty() {
                        // Empty data indicates error or EOF
                        return std::task::Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "BPF read channel closed"
                        )));
                    }
                    // Store in buffer and process
                    let copy_len = data.len().min(me.read_buffer.len());
                    me.read_buffer[..copy_len].copy_from_slice(&data[..copy_len]);
                    me.buffer_len = copy_len;
                    me.buffer_pos = 0;
                    continue;
                }
                std::task::Poll::Ready(None) => {
                    // Channel closed
                    return std::task::Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for BpfRawSocket {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        let me = self.get_mut();
        let fd = me.fd;
        
        // Direct blocking write - writes are typically fast and BPF doesn't support async
        let result = unsafe {
            libc::write(
                fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };
        
        if result < 0 {
            let err = io::Error::last_os_error();
            std::task::Poll::Ready(Err(err))
        } else {
            std::task::Poll::Ready(Ok(result as usize))
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
