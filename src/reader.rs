#[derive(Debug)]
pub struct PacketDescriptor {
    pub offset: usize,
    pub ts_sec: u32,
    pub ts_subsec: u32,
    pub cap_len: u32,
    pub orig_len: u32,
}

pub fn read_u32(pcap: &[u8], offset: usize) -> u32 {
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

pub fn read_header(pcap: &[u8]) {
    let magic = read_u32(&pcap, 0);
    assert!(magic == 0xA1B2C3D4);

    let major = read_u16(&pcap, 4);
    let minor = read_u16(&pcap, 6);
    println!("pcap ver: {}.{}", major, minor);

    // reserved - pcap[8..12]
    // reserved - pcap[12..16]
    // snaplen - pcap[16..20]
    let fcs_f = pcap[20] / (1 << 4);
    // 0.. - pcap[21]
    // linktype - pcap[22..24]
    println!("fcs_f={:b}", fcs_f);
    // For now let's assume that the fcs is always absent
    assert!(fcs_f == 0);
}

pub fn build_packet_index(pcap: &[u8]) -> Vec<PacketDescriptor> {
    let mut index = vec![];
    // first packet starts at byte 24
    let mut offset = 24;
    while offset < pcap.len() as usize {
        let (packet, new_offset) = read_packet(&pcap, offset);
        index.push(packet);
        offset = new_offset;
    }
    index
}
