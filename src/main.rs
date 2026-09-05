use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::Path;

use parser::layer::{parse_packet, parse_pcap};

fn main() {
    let path = Path::new("./data");
    let _ = list_data_files(path, &parse);
}

fn parse(path: &str) {
    println!("Parsing {}", path);
    let mut buf = BufReader::new(File::open(path).unwrap());
    let mut data = Vec::new();
    buf.read_to_end(&mut data).unwrap();
    let (header, packet_iter) = parse_pcap(&data);
    for packet in packet_iter {
        parse_packet(&header, packet);
    }
}

fn list_data_files<F>(dir: &Path, func: &F) -> io::Result<()>
where
    F: Fn(&str),
{
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                list_data_files(&path, func)?;
            } else {
                if (path.to_str().unwrap().contains("pcap")
                    && !path.to_str().unwrap().contains("zip"))
                    || path.parent().unwrap().to_str().unwrap().contains("2015")
                {
                    func(path.to_str().unwrap());
                }
            }
        }
    }
    Ok(())
}
