use clap::Parser;
use memmap::MmapOptions;
use std::io;

#[derive(Parser)]
struct Args {
    fname: String,
}

#[derive(Debug)]
struct PacketDescriptor {
    offset: usize,
    ts_sec: u32,
    ts_subsec: u32,
    cap_len: u32,
    orig_len: u32,
}

fn read_u32(pcap: &[u8], offset: usize) -> u32 {
    let mut u32bytes = [0u8; 4];
    u32bytes.copy_from_slice(&pcap[offset..offset + 4]);
    return u32::from_ne_bytes(u32bytes);
}

fn read_u16(pcap: &[u8], offset: usize) -> u16 {
    let mut u16bytes = [0u8; 2];
    u16bytes.copy_from_slice(&pcap[offset..offset + 2]);
    return u16::from_ne_bytes(u16bytes);
}

fn read_packet(pcap: &[u8], offset: usize) -> (PacketDescriptor, usize) {
    let ts_sec = read_u32(pcap, offset);
    let ts_subsec = read_u32(pcap, offset + 4);
    let cap_len = read_u32(pcap, offset + 8);
    let orig_len = read_u32(pcap, offset + 12);

    (
        PacketDescriptor {
            offset,
            ts_sec,
            ts_subsec,
            cap_len,
            orig_len,
        },
        offset + 16 + cap_len as usize,
    )
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let f = std::fs::File::open(args.fname)?;
    let flen = f.metadata()?.len();
    let mmap = unsafe { MmapOptions::new().map(&f)? };

    let magic = read_u32(&mmap, 0);
    assert!(magic == 0xA1B2C3D4);

    let major = read_u16(&mmap, 4);
    let minor = read_u16(&mmap, 6);
    println!("pcap ver: {}.{}", major, minor);

    // reserved - mmap[8..12]
    // reserved - mmap[12..16]
    // snaplen - mmap[16..20]
    let fcs_f = mmap[20] / (1 << 4);
    // 0.. - mmap[21]
    // linktype - mmap[22..24]
    println!("fcs_f={:b}", fcs_f);
    // For now let's assume that the fcs is always absent
    assert!(fcs_f == 0);

    let mut n_packets = 0;
    // first packet starts at byte 24
    let mut offset = 24;
    while offset < flen as usize {
        let (_packet, new_offset) = read_packet(&mmap, offset);
        offset = new_offset;
        // println!("packet={:?}", packet);
        n_packets += 1;
    }
    println!("n_packets = {}", n_packets);

    Ok(())
}
