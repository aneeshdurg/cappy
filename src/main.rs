use clap::Parser;
use memmap::MmapOptions;
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use tqdm::tqdm;
use pnet::packet::{ethernet::EthernetPacket, ipv4::Ipv4Packet, Packet};

// pub mod driver;
pub mod reader;

#[derive(Parser)]
struct Args {
    fname: String,

    #[arg(long)]
    ip_src: String,

    #[arg(short = 'Y', long)]
    display_filter: Option<String>,

    #[arg(short, long)]
    count: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let filtersrc: Ipv4Addr = args.ip_src.parse().expect("invalid ipv4 addr");
    let f = std::fs::File::open(args.fname)?;
    let mmap = Arc::new(unsafe { MmapOptions::new().map(&f)? });

    let nthreads = 16;

    reader::read_header(&mmap);
    let packets = Arc::new(reader::build_packet_index(&mmap));
    println!("n_packets = {}", packets.len());

    let npackets = packets.len();
    let npackets_per_thread = 1 + npackets / nthreads;

    let pcap_pkt_header = 16;
    let ethernet_header = 14;
    let header_offset = pcap_pkt_header + ethernet_header;

    let mut children = vec![];
    for i in 0..nthreads {
        let mmap = mmap.clone();
        let start = i * npackets_per_thread;
        let end = std::cmp::min(start + npackets_per_thread, npackets);
        let packets = packets.clone();
        children.push(thread::spawn(move || {
            let mut map: HashMap<Ipv4Addr, HashMap<Ipv4Addr, usize>> = HashMap::new();
            for pkt in tqdm(&packets[start..end]) {
                let ip_src = Ipv4Addr::from(
                    reader::read_u32(&mmap, pkt.offset + header_offset + 12).to_be(),
                );
                let ip_dst = Ipv4Addr::from(
                    reader::read_u32(&mmap, pkt.offset + header_offset + 16).to_be(),
                );
                if !map.contains_key(&ip_src) {
                    map.insert(ip_src, HashMap::new());
                }
                if let Some(m) = map.get_mut(&ip_src) {
                    let count = m.get(&ip_dst).map(|x| *x).unwrap_or(0);
                    m.insert(ip_dst, count + 1);
                } else {
                    panic!("???")
                }
            }
            map
        }));
    }

    let mut map: HashMap<Ipv4Addr, HashMap<Ipv4Addr, usize>> = HashMap::new();
    for c in tqdm(children) {
        let res = c.join().expect("thread failed");
        for (k, v) in &res {
            if !map.contains_key(&k) {
                map.insert(*k, HashMap::new());
            }
            map.get_mut(&k).map(|m| {
                for (dst, cnt) in v {
                    let count = m.get(&dst).map(|x| *x).unwrap_or(0);
                    m.insert(*dst, count + cnt);
                }
            });
        }
    }
    println!("{:?}", map);

    // GPU version:
    //   Create GPU devices/buffers
    //   copy portion of pcap into a buffer (stop on packet boundry)
    //   copy packet offsets into a buffer
    //   compile filter into a WGSL expression
    //   compile wgsl program
    //   create output buffer for each thread (write packets offsets of passing packets)
    //   create output buffer for n packet/thread
    //   on device, evaluate filter per packet and write offset into output if filter passes
    //   on host, collect results/display passing packets

    Ok(())
}
