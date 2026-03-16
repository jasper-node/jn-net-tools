use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub mod core;
pub mod l2;
pub mod ll;
pub mod prereq;
pub mod runtime;
pub mod sniff;
pub mod transport;

#[unsafe(no_mangle)]
pub extern "C" fn net_ping(target: *const c_char, count: i32, timeout_ms: u32) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let target_str = unsafe {
            match CStr::from_ptr(target).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid target string"}"#.to_string();
                }
            }
        };

        core::ping::ping(target_str, count as u32, timeout_ms)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_ping"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_trace_route(target: *const c_char, max_hops: i32, timeout_ms: u32) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let target_str = unsafe {
            match CStr::from_ptr(target).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid target string"}"#.to_string();
                }
            }
        };

        core::trace::trace_route(target_str, max_hops, timeout_ms)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_trace_route"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_mtr(target: *const c_char, duration_ms: u32) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let target_str = unsafe {
            match CStr::from_ptr(target).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid target string"}"#.to_string();
                }
            }
        };

        core::mtr::mtr(target_str, duration_ms)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_mtr"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_get_interfaces() -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        l2::interfaces::get_interfaces()
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_get_interfaces"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_get_interface_details() -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        l2::interfaces::get_interface_details()
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_get_interface_details"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_get_default_local_ip() -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        l2::interfaces::get_default_local_ip()
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_get_default_local_ip"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_arp_scan(iface: *const c_char, timeout_ms: u32) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let iface_str = unsafe {
            match CStr::from_ptr(iface).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid interface string"}"#.to_string();
                }
            }
        };

        l2::arp::arp_scan(iface_str, timeout_ms)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_arp_scan"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_lldp_discover(iface: *const c_char, timeout_ms: u32) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let iface_str = unsafe {
            match CStr::from_ptr(iface).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid interface string"}"#.to_string();
                }
            }
        };

        l2::lldp::lldp_discover(iface_str, timeout_ms)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_lldp_discover"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_lldp_send(iface: *const c_char, ttl: u16) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let iface_str = unsafe {
            match CStr::from_ptr(iface).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid interface string"}"#.to_string();
                }
            }
        };

        l2::lldp::lldp_send(iface_str, ttl)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_lldp_send"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_dcp_identify(iface: *const c_char, timeout_ms: u32) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let iface_str = unsafe {
            match CStr::from_ptr(iface).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid interface string"}"#.to_string();
                }
            }
        };

        l2::dcp::dcp_identify(iface_str, timeout_ms)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_dcp_identify"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_dcp_get(iface: *const c_char, target_mac: *const c_char, timeout_ms: u32) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let iface_str = unsafe {
            match CStr::from_ptr(iface).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid interface string"}"#.to_string();
                }
            }
        };

        let target_mac_str = unsafe {
            match CStr::from_ptr(target_mac).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid target MAC string"}"#.to_string();
                }
            }
        };

        l2::dcp::dcp_get(iface_str, target_mac_str, timeout_ms)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_dcp_get"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_sniff(iface: *const c_char, filter: *const c_char, duration_ms: u32, max_packets: i32, include_data: u8) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let iface_str = unsafe {
            match CStr::from_ptr(iface).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid interface string"}"#.to_string();
                }
            }
        };

        let filter_str = if filter.is_null() {
            ""
        } else {
            unsafe {
                match CStr::from_ptr(filter).to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        return r#"{"error":"Invalid filter string"}"#.to_string();
                    }
                }
            }
        };

        let include_data_bool = include_data != 0;
        sniff::capture::sniff_packets(iface_str, filter_str, duration_ms, max_packets, include_data_bool)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_sniff"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_check_port(target: *const c_char, port: u16, proto: *const c_char, timeout_ms: u32) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let target_str = unsafe {
            match CStr::from_ptr(target).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid target string"}"#.to_string();
                }
            }
        };

        let proto_str = unsafe {
            match CStr::from_ptr(proto).to_str() {
                Ok(s) => s,
                Err(_) => "tcp"
            }
        };

        transport::port::check_port(target_str, port, proto_str, timeout_ms)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_check_port"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_bandwidth_test(target: *const c_char, port: u16, proto: *const c_char, duration_ms: u32) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let target_str = unsafe {
            match CStr::from_ptr(target).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid target string"}"#.to_string();
                }
            }
        };

        let proto_str = unsafe {
            match CStr::from_ptr(proto).to_str() {
                Ok(s) => s,
                Err(_) => "tcp"
            }
        };

        transport::throughput::bandwidth_test(target_str, port, proto_str, duration_ms)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_bandwidth_test"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_dns_lookup(domain: *const c_char, server: *const c_char, record_type: *const c_char) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let domain_str = unsafe {
            match CStr::from_ptr(domain).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return r#"{"error":"Invalid domain string"}"#.to_string();
                }
            }
        };

        let server_str = if server.is_null() {
            None
        } else {
             unsafe {
                CStr::from_ptr(server).to_str().ok()
            }
        };

        let record_type_str = if record_type.is_null() {
            None
        } else {
             unsafe {
                CStr::from_ptr(record_type).to_str().ok()
            }
        };

        core::dns::dns_lookup(domain_str, server_str, record_type_str)
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"error":"Panic occurred in net_dns_lookup"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_check_prerequisites() -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        prereq::check_prerequisites()
    }));

    match result {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    let err = CString::new(r#"{"status":"Error","error":"Failed to create result string"}"#).unwrap();
                    err.into_raw()
                }
            }
        }
        Err(_) => {
            let err = CString::new(r#"{"status":"Error","error":"Panic occurred in net_check_prerequisites"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(ptr: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !ptr.is_null() {
            unsafe {
                let _ = CString::from_raw(ptr);
            }
        }
    }));
}
