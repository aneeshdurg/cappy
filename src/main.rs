use clap::Parser;
use memmap::MmapOptions;
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;

// pub mod driver;
pub mod reader;

#[link(name = "cappy_kernel", kind = "static")]
extern "C" {
    fn cappy_main(
        n_pkts: usize,
        pkt_offsets: *const u64,
        pcap: *const u8,
        pcap_size: usize,
    ) -> *mut u32;
}

#[derive(Parser)]
struct Args {
    fname: String,

    #[arg(short = 'Y', long)]
    display_filter: Option<String>,

    #[arg(short, long)]
    count: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let f = std::fs::File::open(args.fname)?;
    let mmap = Arc::new(unsafe { MmapOptions::new().map(&f)? });

    let nthreads = 16;

    reader::read_header(&mmap);
    let packets = reader::build_packet_index(&mmap);
    let npackets = packets.len();

    let offsets: Vec<u64> = (&packets).into_iter().map(|x| x.offset as u64).collect();
    println!("n_packets = {}", packets.len());

    let timer = std::time::Instant::now();
    let res = unsafe {
        let res = cappy_main(npackets, offsets.as_ptr(), (&mmap).as_ptr(), mmap.len());
        std::slice::from_raw_parts(res, npackets)
    };
    println!("npassed = {}", res.iter().map(|x| *x as u64).sum::<u64>());
    println!("  elapsed = {:?}", timer.elapsed());

    let packets = Arc::new(packets);
    let npackets_per_thread = 1 + npackets / nthreads;

    let pcap_pkt_header = 16;
    let ethernet_header = 14;
    let header_offset = pcap_pkt_header + ethernet_header;

    // let ref_ip: Ipv4Addr = "192.168.68.110".parse().unwrap();
    // for pkt in &(*packets) {
    //     let ip_src =
    //         Ipv4Addr::from(reader::read_u32(&mmap, pkt.offset + header_offset + 12).to_be());
    //     println!("cpu res = {:?}", ip_src);
    // }

    let timer = std::time::Instant::now();
    let mut children = vec![];
    for i in 0..nthreads {
        let mmap = mmap.clone();
        let start = i * npackets_per_thread;
        let end = std::cmp::min(start + npackets_per_thread, npackets);
        let packets = packets.clone();
        children.push(thread::spawn(move || {
            let mut map: HashMap<Ipv4Addr, HashMap<Ipv4Addr, usize>> = HashMap::new();
            for pkt in &packets[start..end] {
                let ip_src = Ipv4Addr::from(
                    reader::read_u32(&mmap, pkt.offset + header_offset + 12).to_be(),
                );
                let ip_dst = Ipv4Addr::from(
                    reader::read_u32(&mmap, pkt.offset + header_offset + 16).to_be(),
                );
                if !map.contains_key(&ip_src) {
                    map.insert(ip_src, HashMap::new());
                }
                map.get_mut(&ip_src).map(|m| {
                    let count = m.get(&ip_dst).map(|x| *x).unwrap_or(0);
                    m.insert(ip_dst, count + 1);
                });
            }
            map
        }));
    }

    let mut map: HashMap<Ipv4Addr, HashMap<Ipv4Addr, usize>> = HashMap::new();
    for c in children {
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
    // println!("{:?}", map);

    let tgt_ip = "192.168.68.110".parse().unwrap();
    println!("cpu res = {:?}", map.get(&tgt_ip).unwrap().values().sum::<usize>());
    println!("  elapsed = {:?}", timer.elapsed());

    Ok(())
}
