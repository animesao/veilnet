#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

pub fn ensure_dir(path: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}
