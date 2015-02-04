#![feature(io,collections,core,std_misc)]

extern crate time;

use std::thread::Thread;

use std::old_io::{IoResult,IoError};
use std::old_io::net::ip::{SocketAddr, IpAddr, Ipv4Addr};
use std::old_io::net::udp::{UdpSocket};

use std::collections::HashMap;
use std::sync::{ Arc, Mutex };

use std::error::FromError;

use std::time::duration::Duration;

static PORT:u16 = 1900;
static INADDR_ANY:IpAddr = Ipv4Addr(0, 0, 0, 0);
static INADDR_SSDP:IpAddr = Ipv4Addr(239, 255, 255, 250);

#[derive(Clone)]
struct SSDPQuery {
    a: usize,
}

#[derive(Clone)]
pub struct SSDPCacheEntry {
    message: String
}

impl SSDPCacheEntry {
    pub fn get(&self, name:&str) -> Option<&str> {
        for ref line in self.message[].split_str("\r\n") {
            if line.len() > name.len()+1 && &line[0..name.len()] == name
                && &line[name.len()..name.len()+1] == ":" {
                let result = line[name.len() + 1..].trim_left();
                return Some(result)
            }
        }
        None
    }

    #[allow(non_snake_case)]
    pub fn USN(&self) -> Option<&str> { self.get("USN") }
}

#[derive(Clone)]
pub struct SSDPAgent {
    socket:Option<UdpSocket>,
    pub cache:Arc<Mutex<HashMap<String,SSDPCacheEntry>>>
}

pub enum SsdpError {
    IoError(IoError),
    StateError(String),
}

impl FromError<IoError> for SsdpError {
    fn from_error(err: IoError) -> SsdpError {
        SsdpError::IoError(err)
    }
}

pub type SsdpResult<T> = Result<T,SsdpError>;

impl SSDPAgent {

    pub fn new() -> SSDPAgent {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        SSDPAgent{ socket:None, cache:cache }
    }

    pub fn start(&mut self) -> IoResult<()> {

        let mut socket : UdpSocket = try!(UdpSocket::bind(SocketAddr{ ip:INADDR_ANY, port:PORT }));
        try!(socket.join_multicast(INADDR_SSDP));
        try!(socket.set_multicast_ttl(2));
        self.socket = Some(socket);

        let mut agent = self.clone();
        Thread::spawn(move || { agent.run() });
        Ok(())
    }

    fn process_entry(&mut self, buf:&[u8]) {
        let entry = SSDPCacheEntry {
            message: String::from_utf8_lossy(&buf).into_owned()
        };
        match entry.USN() {
            Some(name) => match self.cache.lock() {
                Ok(ref mut h) => { h.insert(name.to_string(), entry.clone()); () },
                Err(e) => println!("error: {}", e),
            },
            None => {
                println!("entry with no USN: {}", entry.message)
            }
        }
    }

    fn run(&mut self) {
        let ok_header = "HTTP/1.1 200 OK".as_bytes();
        loop {
            let mut buf = [0; 1024];
            let dg:Option<usize> = match self.socket {
                Some(ref mut s) => match s.recv_from(&mut buf) {
                    Ok((amt, _)) => Some(amt),
                    Err(e) => {
                        println!("UDP error in SsdpAgent: {:?}", e);
                        None
                    }
                },
                None => {
                    panic!("SsdpAgent with no socket");
                }
            };
            match dg {
                Some(amt) => {
                    println!("{}", String::from_utf8_lossy(&buf[0..amt]));
                    if buf.len() >= ok_header.len() && &buf[0..ok_header.len()] == ok_header {
                        self.process_entry(&buf[0..amt])
                    }
                }
                None => ()
            }
        }
    }

    pub fn query_search(&mut self, what:&str) -> SsdpResult<()> {
        let discover_message = format!(concat!(
            "M-SEARCH * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "ST: {}\r\n",
            "MAN: \"ssdp:discover\"\r\n",
            "MX: 3\r\n"
        ), what);
        match self.socket {
            Some(ref mut socket) => {
                try!(socket.send_to(discover_message.as_bytes(), SocketAddr{ip:INADDR_SSDP, port:1900}));
                Ok(())
            },
            None => Err(SsdpError::StateError("no agent found".to_string()))
        }
    }

    pub fn query_search_all(&mut self) -> SsdpResult<()> {
        self.query_search("ssdp:all")
    }

}

#[cfg(test)]
fn assert_eventually<F: Fn()->bool>(max:Duration, pause:Duration, what:F) {
    let start = time::get_time();
    while time::get_time() - start < max {
        if what() {
            return ();
        }
        std::old_io::timer::sleep(pause);
    }
}

#[test]
fn it_works() {
    let mut agent = SSDPAgent::new();
    let _ = agent.query_search_all();

    assert_eventually(Duration::seconds(5), Duration::milliseconds(50), || {
        let h = agent.cache.lock().unwrap();
        h.len() > 0
    });
    assert_eventually(Duration::seconds(5), Duration::milliseconds(50), || {
        let h = agent.cache.lock().unwrap();
        h.values().find( |e|
            e.get("SERVER").map( |s| s.contains("IpBridge")).unwrap_or(false)
        ).is_some()
    });
}

#[test]
fn entry_does_parse() {
    let entry = SSDPCacheEntry{ message:concat!(
        "HTTP/1.1 200 OK\r\n",
        "CACHE-CONTROL: max-age=100\r\n",
        "EXT:\r\n",
        "LOCATION: http://192.168.1.139:80/description.xml\r\n",
        "SERVER: FreeRTOS/6.0.5, UPnP/1.0, IpBridge/0.1\r\n",
        "ST: uuid:2f402f80-da50-11e1-9b23-0017880a8911\r\n",
        "USN: uuid:2f402f80-da50-11e1-9b23-0017880a8911\r\n\r\n").to_string(), };

    assert_eq!(Some("uuid:2f402f80-da50-11e1-9b23-0017880a8911"), entry.get("USN"));
    assert_eq!(Some("uuid:2f402f80-da50-11e1-9b23-0017880a8911"), entry.USN());
    assert_eq!(None, entry.get("nope"));
}
