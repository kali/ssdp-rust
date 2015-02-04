#![feature(io)]

use std::thread::Thread;

use std::old_io::net::ip::{SocketAddr, IpAddr, Ipv4Addr};
use std::old_io::net::udp::{UdpSocket};

use std::sync::mpsc::{Sender, Receiver};

use std::collections::HashMap;
use std::sync::{ Arc, Mutex };

static PORT:u16 = 1900;
static INADDR_ANY:IpAddr = Ipv4Addr(0, 0, 0, 0);
static INADDR_SSDP:IpAddr = Ipv4Addr(239, 255, 255, 250);

#[derive(Clone)]
struct SSDPQuery {
    a: usize,
}

#[derive(Clone)]
struct SSDPCacheEntry {
    message: String
}

impl SSDPCacheEntry {
    fn get(&self, name:&str) -> Option<&str> {
        for ref line in self.message.as_slice().split_str("\r\n") {
            if(line.len() > name.len()+1 && &line[0..name.len()] == name
                && &line[name.len()..name.len()+1] == ":") {
                let result = line.slice_from(name.len() + 1).trim_left();
                return Some(result)
            }
        }
        None
    }

    fn USN(&self) -> Option<&str> { self.get("USN") }
}

pub struct SSDPAgent {
    socket:UdpSocket,
    cache:Arc<Mutex<HashMap<String,SSDPCacheEntry>>>
}

impl SSDPAgent {

    pub fn new() -> SSDPAgent {
        let mut socket : UdpSocket = UdpSocket::bind(SocketAddr{ ip:INADDR_ANY, port:PORT }).unwrap();
        socket.join_multicast(INADDR_SSDP);
        socket.set_multicast_ttl(2);

        let mut socket2 = socket.clone();
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let cache2 = cache.clone();

        Thread::spawn(move || { SSDPAgent::run(socket2,cache2) });

        SSDPAgent{ socket:socket, cache:cache }
    }

    fn process_entry(buf:&[u8], cache:&Arc<Mutex<HashMap<String,SSDPCacheEntry>>>) {
        let entry = SSDPCacheEntry {
            message: String::from_utf8_lossy(&buf).into_owned()
        };
        match entry.USN() {
            Some(name) => match cache.lock() {
                Ok(ref mut h) => { h.insert(name.to_string(), entry.clone()); () },
                Err(e) => println!("error: {}", e),
            },
            None => {
                println!("entry with no USN: {}", entry.message)
            }
        }
    }

    fn run(mut socket:UdpSocket, cache:Arc<Mutex<HashMap<String,SSDPCacheEntry>>>) {
        let ok_header = "HTTP/1.1 200 OK".as_bytes();
        while true {
            let mut buf = [0; 1024];
            match socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    println!("{}", String::from_utf8_lossy(&buf[0..amt]));
                    if(buf.len() >= ok_header.len() && &buf[0..ok_header.len()] == ok_header) {
                        SSDPAgent::process_entry(&buf[0..amt], &cache);
                    }
                }
                Err(e) => println!("couldn't receive a datagram: {}", e)
            }
        }
    }

    pub fn query_search(&mut self, what:&str) {
        let discover_message = format!(concat!(
            "M-SEARCH * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "ST: {}\r\n",
            "MAN: \"ssdp:discover\"\r\n",
            "MX: 3\r\n"
        ), what);
        self.socket.send_to(discover_message.as_bytes(), SocketAddr{ip:INADDR_SSDP, port:1900});
    }

    pub fn query_search_all(&mut self) {
        self.query_search("ssdp:all")
    }

}

#[test]
fn it_works() {
    let mut agent = SSDPAgent::new();
    agent.query_search_all();
    std::old_io::timer::sleep(std::time::duration::Duration::seconds(5));

    println!("YYY");
    let h = agent.cache.lock().unwrap();
    assert!(h.len() > 0);
    println!("XXX {:?}", (*h).len());
    assert!(h.values().find( |e|
        e.get("SERVER").map( |s| s.contains("IpBridge")).unwrap_or(false)
    ).is_some());
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
