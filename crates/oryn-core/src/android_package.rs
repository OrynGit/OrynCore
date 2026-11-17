//! Android 上按连接五元组查出应用包名。其它平台没有这项信息，`PROCESS-NAME` 规则不会命中。

use oryn_router::FlowContext;

pub fn lookup(flow: &FlowContext) -> Option<String> {
    #[cfg(target_os = "android")]
    {
        native(flow)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = flow;
        None
    }
}

#[cfg(target_os = "android")]
fn native(flow: &FlowContext) -> Option<String> {
    use std::ffi::{CStr, CString};
    use std::sync::OnceLock;

    type Lookup = unsafe extern "C" fn(i32, *const i8, i32, *const i8, i32, *mut u8, usize) -> i32;
    static FUNC: OnceLock<Option<Lookup>> = OnceLock::new();
    let function = (*FUNC.get_or_init(|| {
        let name = CString::new("oryn_android_owner_package").ok()?;
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
        if symbol.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<_, Lookup>(symbol) })
        }
    }))?;
    let protocol = match flow.network {
        oryn_router::Network::Tcp => 6,
        oryn_router::Network::Udp => 17,
    };
    let source = CString::new(flow.source.ip().to_string()).ok()?;
    let destination = CString::new(flow.destination.ip().to_string()).ok()?;
    let mut buffer = [0u8; 256];
    let found = unsafe {
        function(
            protocol,
            source.as_ptr() as *const i8,
            flow.source.port() as i32,
            destination.as_ptr() as *const i8,
            flow.destination.port() as i32,
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    if found != 1 {
        return None;
    }
    let text = CStr::from_bytes_until_nul(&buffer).ok()?.to_str().ok()?;
    (!text.is_empty()).then(|| text.to_string())
}
