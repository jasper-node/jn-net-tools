# Layer 2 Packet Capture Implementation

This document describes how ethercrab implements layer 2 (Ethernet) packet capture on macOS, Linux, and Windows platforms.

## Overview

Ethercrab requires raw access to Ethernet frames to communicate with EtherCAT devices. Each operating system provides different mechanisms for this, with varying privilege requirements:

| Platform    | Method                    | Privileges Required   | Library/API                    |
| ----------- | ------------------------- | --------------------- | ------------------------------ |
| **macOS**   | BPF devices (`/dev/bpf*`) | None                  | Direct `libc` calls            |
| **Linux**   | `AF_PACKET` raw sockets   | Root or `CAP_NET_RAW` | Direct `libc` calls            |
| **Windows** | Npcap/WinPcap driver      | Driver installation   | `pcap` crate + `pnet_datalink` |

All three implementations provide the same interface (`io::Read`/`io::Write`) to the upper layers, abstracting platform differences.

---

## macOS Implementation: BPF Devices

### Overview

macOS uses **BPF (Berkeley Packet Filter) devices** for raw packet access. Unlike Linux, macOS allows regular users to access BPF devices without root privileges, making it the most user-friendly platform for development.

### BPF Device Access

BPF devices are located at `/dev/bpf0` through `/dev/bpf255`. The implementation iterates through these devices to find an available one:

```rust
fn open_device() -> io::Result<libc::c_int> {
    unsafe {
        for i in 0..256 {
            let dev = format!("/dev/bpf{}\0", i);
            match libc::open(
                dev.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK,
            ) {
                -1 => continue,
                fd => return Ok(fd),
            };
        }
    }
    Err(io::Error::last_os_error())
}
```

### Interface Binding

Once a BPF device is opened, it's bound to the network interface using `ioctl` calls:

```rust
pub fn bind_interface(&mut self) -> io::Result<()> {
    let mut bufsize: libc::c_int = 1;
    
    // Set immediate mode (return packets as soon as they arrive)
    try_ioctl!(self.fd, BIOCIMMEDIATE, &mut bufsize as *mut libc::c_int);
    
    // Bind to the network interface
    try_ioctl!(self.fd, BIOCSETIF, &mut self.ifreq);
    
    Ok(())
}
```

### Packet Reading

BPF prepends a `bpf_hdr` structure to each packet. The implementation must:

1. Read the BPF header to determine the actual Ethernet frame length
2. Strip the BPF header from the buffer
3. Handle multiple packets that may be returned in a single read operation

```rust
impl io::Read for BpfDevice {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // Read from BPF device
        let len = unsafe {
            libc::read(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };
        
        // Extract frame length from BPF header
        let bpf_header = unsafe {
            core::ptr::NonNull::new(buffer.as_ptr() as *mut bpf_hdr)
                .ok_or(io::Error::other("no BPF header"))?
                .as_ref()
        };
        
        let frame_len = bpf_header.bh_datalen as usize;
        
        // Strip BPF header by moving frame data to start of buffer
        unsafe {
            libc::memmove(
                buffer.as_mut_ptr() as *mut libc::c_void,
                &buffer[BPF_HDRLEN] as *const u8 as *const libc::c_void,
                frame_len,
            )
        };
        
        Ok(frame_len)
    }
}
```

### Packet Writing

Writing is straightforward - Ethernet frames are written directly to the BPF device:

```rust
impl io::Write for BpfDevice {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::write(
                self.fd,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
            );
            
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            
            Ok(len as usize)
        }
    }
}
```

### macOS-Specific Behavior

macOS forcibly sets the source MAC address to the NIC's MAC address when sending packets. Therefore, the implementation must set the expected source MAC for filtering received packets:

```rust
// macOS forcibly sets the source address to the NIC's MAC, so instead of using `MASTER_ADDR`
// for filtering returned packets, we must set the address to compare to the NIC MAC.
#[cfg(all(not(target_os = "linux"), unix))]
if let Some(mac) = socket.mac().ok().flatten() {
    fmt::debug!("Setting source MAC to {}", mac);
    pdu_rx.set_source_mac(mac);
}
```

### Why No Root Required

macOS allows regular users to open and use BPF devices by default. This is a design decision by Apple that makes development easier, though it does mean any user can capture network traffic on their machine.

---

## Linux Implementation: AF_PACKET Raw Sockets

### Overview

Linux uses `AF_PACKET` raw sockets for direct access to Ethernet frames. This requires root privileges or the `CAP_NET_RAW` capability.

### Socket Creation

A raw socket is created with the EtherCAT ethertype (0x88A4) as the protocol filter:

```rust
pub fn new(name: &str) -> io::Result<Self> {
    let protocol = ETHERCAT_ETHERTYPE as i16;
    
    let lower = unsafe {
        let lower = libc::socket(
            libc::AF_PACKET,              // Ethernet II frames
            libc::SOCK_RAW | libc::SOCK_NONBLOCK,
            protocol.to_be() as i32,     // Filter for EtherCAT frames
        );
        if lower == -1 {
            return Err(io::Error::last_os_error());
        }
        lower
    };
    
    // ... bind to interface ...
}
```

### Interface Binding

The socket is bound to a specific network interface using `sockaddr_ll`:

```rust
fn bind_interface(&mut self) -> io::Result<()> {
    let protocol = ETHERCAT_ETHERTYPE as i16;
    
    let sockaddr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: protocol.to_be() as u16,
        sll_ifindex: ifreq_ioctl(self.lower, &mut self.ifreq, libc::SIOCGIFINDEX)?,
        sll_hatype: 1,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0; 8],
    };
    
    unsafe {
        let res = libc::bind(
            self.lower,
            addr_of!(sockaddr).cast(),
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    
    Ok(())
}
```

### Packet I/O

Reading and writing are straightforward - data is read/written directly to the raw socket file descriptor:

```rust
impl io::Read for RawSocketDesc {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = unsafe { 
            libc::read(self.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) 
        };
        if len == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }
}

impl io::Write for RawSocketDesc {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = unsafe { 
            libc::write(self.as_raw_fd(), buf.as_ptr().cast(), buf.len()) 
        };
        if len == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }
}
```

### Privilege Requirements

Linux requires either:

- **Root privileges**: Run the application with `sudo`
- **CAP_NET_RAW capability**: Set using `setcap cap_net_raw=pe /path/to/binary`

The availability check confirms this:

```rust
#[cfg(target_os = "linux")]
unsafe {
    let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0);
    if fd >= 0 { 
        libc::close(fd); 
        return 1; 
    }
    return 0;
}
```

---

## Windows Implementation: Npcap/WinPcap

### Overview

Windows doesn't provide native raw socket support for layer 2 access. Instead, ethercrab uses the **Npcap** or **WinPcap** driver via the `pcap` library. This requires installing the driver separately.

### Driver Requirements

- **Npcap** (recommended) or **WinPcap** must be installed
- "WinPcap compatibility mode" must be enabled during installation
- Download from: https://npcap.com/#download

### Device Setup

The implementation uses `pnet_datalink` to find the network interface, then opens a `pcap::Capture`:

```rust
fn get_tx_rx(device: &str) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>), std::io::Error> {
    let interfaces = pnet_datalink::interfaces();
    
    let interface = interfaces.iter()
        .find(|interface| interface.name == device)
        .expect("Interface not found");
    
    let config = pnet_datalink::Config {
        write_buffer_size: 16384,
        read_buffer_size: 16384,
        ..Default::default()
    };
    
    let (tx, rx) = match channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => return Err(e),
    };
    
    Ok((tx, rx))
}
```

### Packet Capture Setup

A `pcap::Capture` is opened in immediate, non-blocking mode:

```rust
let mut cap = pcap::Capture::from_device(device)
    .expect("Device")
    .immediate_mode(true)      // Return packets immediately
    .open()
    .expect("Open device")
    .setnonblock()              // Non-blocking mode
    .expect("Can't set non-blocking");
```

### Packet Transmission

Windows uses a send queue for batching packet transmissions:

```rust
// 1MB send queue
let mut sq = pcap::sendqueue::SendQueue::new(1024 * 1024)
    .expect("Failed to create send queue");

// Queue packets
while let Some(frame) = pdu_tx.next_sendable_frame() {
    sq.queue(None, frame_bytes).expect("Enqueue");
    sent_this_iter += 1;
}

// Transmit all queued packets at once
if sent_this_iter > 0 {
    sq.transmit(&mut cap, pcap::sendqueue::SendSync::Off)
        .expect("Transmit");
}
```

### Packet Reception

Packets are received using `cap.next_packet()`:

```rust
loop {
    match cap.next_packet() {
        Ok(packet) => {
            let frame_buf = packet.data;
            
            // Process the frame
            let res = pdu_rx.receive_frame(&frame_buf)?;
            
            if res == ReceiveAction::Processed {
                in_flight = in_flight.checked_sub(1).expect("More frames processed than in flight");
            }
        }
        Err(pcap::Error::NoMorePackets) => {
            // Nothing to read yet
            break;
        }
        Err(pcap::Error::TimeoutExpired) => {
            // Timeout (non-blocking mode)
            break;
        }
        Err(e) => {
            return Err(io::Error::other(e));
        }
    }
}
```

### Blocking vs Async

**Important**: Windows uses a **blocking** implementation (`tx_rx_task_blocking`) rather than async. This is because `libpnet` and the pcap library aren't conducive to async operations on Windows. The blocking task must be run in a separate thread.

---

## Platform Detection

The FFI layer includes a function to check if raw socket access is available:

```rust
pub extern "C" fn is_raw_socket_available() -> c_int {
    #[cfg(target_os = "linux")]
    unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0);
        if fd >= 0 { 
            libc::close(fd); 
            return 1; 
        }
        return 0;
    }

    #[cfg(target_os = "macos")]
    unsafe {
        for i in 0..256 {
            let dev = format!("/dev/bpf{}\0", i);
            match libc::open(dev.as_ptr() as *const libc::c_char, libc::O_RDWR | libc::O_NONBLOCK) {
                -1 => continue,
                fd => {
                    libc::close(fd);
                    return 1;
                }
            }
        }
        return 0;
    }
    
    #[cfg(target_os = "windows")]
    {
        use pnet_datalink;
        let interfaces = pnet_datalink::interfaces();
        if interfaces.is_empty() { return 0; }
        if let Some(interface) = interfaces.first() {
             if let Ok(mut cap_builder) = pcap::Capture::from_device(interface.name.as_str()) {
                 if cap_builder.open().is_ok() { return 1; }
             }
        }
        return 0;
    }
}
```

---

## Unified Interface

Despite the different underlying implementations, all three platforms provide the same interface to the upper layers:

- `io::Read` trait for receiving packets
- `io::Write` trait for sending packets
- Async I/O support (except Windows, which uses blocking)

This abstraction allows the same EtherCAT master code to work across all platforms, with only the low-level packet capture implementation differing.

---

## References

- **macOS BPF**: [Apple's BPF documentation](https://developer.apple.com/library/archive/documentation/Darwin/Reference/ManPages/man4/bpf.4.html)
- **Linux AF_PACKET**: [Linux packet(7) man page](https://man7.org/linux/man-pages/man7/packet.7.html)
- **Npcap**: [Npcap documentation](https://npcap.com/)
- **Ethercrab source**: `ethercrab/src/std/unix/bpf.rs` (macOS), `ethercrab/src/std/unix/linux.rs` (Linux), `ethercrab/src/std/windows.rs` (Windows)
