use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

pub type SocketProtectFn = unsafe extern "C" fn(context: *mut c_void, fd: i32) -> i32;

#[derive(Clone, Copy)]
struct Callback {
    function: SocketProtectFn,
    context: usize,
}

unsafe impl Send for Callback {}
unsafe impl Sync for Callback {}

static CALLBACK: OnceLock<Mutex<Option<Callback>>> = OnceLock::new();

pub fn set_socket_protect_callback(function: Option<SocketProtectFn>, context: *mut c_void) {
    let slot = CALLBACK.get_or_init(|| Mutex::new(None));
    *slot.lock().expect("socket protect callback lock poisoned") =
        function.map(|function| Callback { function, context: context as usize });
}

pub fn protect_fd(fd: i32) -> std::io::Result<()> {
    let callback = CALLBACK
        .get()
        .and_then(|slot| slot.lock().ok().and_then(|callback| *callback));
    let Some(callback) = callback else {
        return Ok(());
    };
    let status = unsafe { (callback.function)(callback.context as *mut c_void, fd) };
    if status == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Android VpnService.protect rejected the socket",
        ));
    }
    Ok(())
}
