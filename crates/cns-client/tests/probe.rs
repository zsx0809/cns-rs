#[tokio::test]
async fn probe() {
    use std::os::unix::io::AsRawFd;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let a = tokio::net::TcpStream::connect(addr).await.unwrap();
    let fd = a.as_raw_fd();
    let ret = unsafe {
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let r = libc::getsockopt(
            fd,
            libc::SOL_IP,
            80,
            &mut sa as *mut _ as *mut libc::c_void,
            &mut len,
        );
        let err = std::io::Error::last_os_error();
        (r, err, sa.sin_port, sa.sin_addr.s_addr)
    };
    eprintln!(
        "[probe] listen={} getsockopt ret={} err={} port={:#06x} addr={:08x} local={:?} peer={:?}",
        addr.port(),
        ret.0,
        ret.1,
        u16::from_be(ret.2),
        ret.3,
        a.local_addr(),
        a.peer_addr()
    );
    eprintln!("[probe] iptables nat OUTPUT: ");
    let _ = std::process::Command::new("iptables")
        .args(["-t", "nat", "-L", "OUTPUT", "-n"])
        .stdout(std::process::Stdio::piped())
        .status();
}
