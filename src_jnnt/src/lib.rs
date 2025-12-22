use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub mod core;
pub mod l2;
pub mod ll;
pub mod prereq;
pub mod runtime;
pub mod sniff;
pub mod transport;

#[unsafe(no_mangle)]
pub extern "C" fn net_ping(target: *const c_char, count: i32, timeout_ms: u32) -> *mut c_char {
    let target_str = unsafe {
        match CStr::from_ptr(target).to_str() {
            Ok(s) => s,
            Err(_) => {
                let err = CString::new(r#"{"error":"Invalid target string"}"#).unwrap();
                return err.into_raw();
            }
        }
    };

    let result = core::ping::ping(target_str, count as u32, timeout_ms);
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_trace_route(target: *const c_char, max_hops: i32, timeout_ms: u32) -> *mut c_char {
    let target_str = unsafe {
        match CStr::from_ptr(target).to_str() {
            Ok(s) => s,
            Err(_) => {
                let err = CString::new(r#"{"error":"Invalid target string"}"#).unwrap();
                return err.into_raw();
            }
        }
    };

    let result = core::trace::trace_route(target_str, max_hops, timeout_ms);
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_mtr(target: *const c_char, duration_ms: u32) -> *mut c_char {
    let target_str = unsafe {
        match CStr::from_ptr(target).to_str() {
            Ok(s) => s,
            Err(_) => {
                let err = CString::new(r#"{"error":"Invalid target string"}"#).unwrap();
                return err.into_raw();
            }
        }
    };

    let result = core::mtr::mtr(target_str, duration_ms);
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_get_interfaces() -> *mut c_char {
    let result = l2::interfaces::get_interfaces();
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_arp_scan(iface: *const c_char, timeout_ms: u32) -> *mut c_char {
    let iface_str = unsafe {
        match CStr::from_ptr(iface).to_str() {
            Ok(s) => s,
            Err(_) => {
                let err = CString::new(r#"{"error":"Invalid interface string"}"#).unwrap();
                return err.into_raw();
            }
        }
    };

    let result = l2::arp::arp_scan(iface_str, timeout_ms);
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_sniff(iface: *const c_char, filter: *const c_char, duration_ms: u32, max_packets: i32) -> *mut c_char {
    let iface_str = unsafe {
        match CStr::from_ptr(iface).to_str() {
            Ok(s) => s,
            Err(_) => {
                let err = CString::new(r#"{"error":"Invalid interface string"}"#).unwrap();
                return err.into_raw();
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
                    let err = CString::new(r#"{"error":"Invalid filter string"}"#).unwrap();
                    return err.into_raw();
                }
            }
        }
    };

    let result = sniff::capture::sniff_packets(iface_str, filter_str, duration_ms, max_packets);
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_check_port(target: *const c_char, port: u16, proto: *const c_char, timeout_ms: u32) -> *mut c_char {
    let target_str = unsafe {
        match CStr::from_ptr(target).to_str() {
            Ok(s) => s,
            Err(_) => {
                let err = CString::new(r#"{"error":"Invalid target string"}"#).unwrap();
                return err.into_raw();
            }
        }
    };

    let proto_str = unsafe {
        match CStr::from_ptr(proto).to_str() {
            Ok(s) => s,
            Err(_) => "tcp"
        }
    };

    let result = transport::port::check_port(target_str, port, proto_str, timeout_ms);
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_bandwidth_test(target: *const c_char, port: u16, proto: *const c_char, duration_ms: u32) -> *mut c_char {
    let target_str = unsafe {
        match CStr::from_ptr(target).to_str() {
            Ok(s) => s,
            Err(_) => {
                let err = CString::new(r#"{"error":"Invalid target string"}"#).unwrap();
                return err.into_raw();
            }
        }
    };

    let proto_str = unsafe {
        match CStr::from_ptr(proto).to_str() {
            Ok(s) => s,
            Err(_) => "tcp"
        }
    };

    let result = transport::throughput::bandwidth_test(target_str, port, proto_str, duration_ms);
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_dns_lookup(domain: *const c_char, server: *const c_char, record_type: *const c_char) -> *mut c_char {
    let domain_str = unsafe {
        match CStr::from_ptr(domain).to_str() {
            Ok(s) => s,
            Err(_) => {
                let err = CString::new(r#"{"error":"Invalid domain string"}"#).unwrap();
                return err.into_raw();
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

    let result = core::dns::dns_lookup(domain_str, server_str, record_type_str);
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_check_prerequisites() -> *mut c_char {
    let result = prereq::check_prerequisites();
    match CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => {
            let err = CString::new(r#"{"status":"Error","error":"Failed to create result string"}"#).unwrap();
            err.into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}
