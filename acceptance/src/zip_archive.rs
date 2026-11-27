use std::io::Write as _;

use flate2::Compression;
use flate2::write::DeflateEncoder;

const LOCAL_HEADER: u32 = 0x0403_4b50;
const CENTRAL_HEADER: u32 = 0x0201_4b50;
const END_OF_CENTRAL_DIRECTORY: u32 = 0x0605_4b50;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const ENCRYPTED_FLAG: u16 = 1;
const VERSION: u16 = 20;
const MODIFIED_DATE: u16 = 0x21;
const CRC_POLYNOMIAL: u32 = 0xedb8_8320;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflated,
}

#[derive(Debug, Clone)]
pub struct Member {
    pub name: Vec<u8>,
    pub contents: Vec<u8>,
    pub method: Method,
    pub encrypted: bool,
}

impl Member {
    #[must_use]
    pub fn stored(name: &str, contents: &[u8]) -> Self {
        Self::new(name, contents, Method::Stored)
    }

    #[must_use]
    pub fn deflated(name: &str, contents: &[u8]) -> Self {
        Self::new(name, contents, Method::Deflated)
    }

    #[must_use]
    pub const fn flagged_encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    fn new(name: &str, contents: &[u8], method: Method) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            contents: contents.to_vec(),
            method,
            encrypted: false,
        }
    }

    #[must_use]
    pub fn stored_data(&self) -> Vec<u8> {
        match self.method {
            Method::Stored => self.contents.clone(),
            Method::Deflated => deflate(&self.contents),
        }
    }

    #[must_use]
    pub fn local_record(&self) -> Vec<u8> {
        let data = self.stored_data();
        let mut record = Vec::new();
        record.extend_from_slice(&LOCAL_HEADER.to_le_bytes());
        for value in [VERSION, self.flags(), self.method_code(), 0, MODIFIED_DATE] {
            record.extend_from_slice(&value.to_le_bytes());
        }
        for value in [
            crc32(&self.contents),
            length_u32(&data),
            length_u32(&self.contents),
        ] {
            record.extend_from_slice(&value.to_le_bytes());
        }
        for value in [length_u16(&self.name), 0] {
            record.extend_from_slice(&value.to_le_bytes());
        }
        record.extend_from_slice(&self.name);
        record.extend_from_slice(&data);
        record
    }

    #[must_use]
    pub fn central_record(&self, local_offset: u32) -> Vec<u8> {
        let data = self.stored_data();
        let mut record = Vec::new();
        record.extend_from_slice(&CENTRAL_HEADER.to_le_bytes());
        for value in [
            VERSION,
            VERSION,
            self.flags(),
            self.method_code(),
            0,
            MODIFIED_DATE,
        ] {
            record.extend_from_slice(&value.to_le_bytes());
        }
        for value in [
            crc32(&self.contents),
            length_u32(&data),
            length_u32(&self.contents),
        ] {
            record.extend_from_slice(&value.to_le_bytes());
        }
        for value in [length_u16(&self.name), 0, 0, 0, 0] {
            record.extend_from_slice(&value.to_le_bytes());
        }
        for value in [0u32, local_offset] {
            record.extend_from_slice(&value.to_le_bytes());
        }
        record.extend_from_slice(&self.name);
        record
    }

    const fn flags(&self) -> u16 {
        if self.encrypted { ENCRYPTED_FLAG } else { 0 }
    }

    const fn method_code(&self) -> u16 {
        match self.method {
            Method::Stored => STORED,
            Method::Deflated => DEFLATED,
        }
    }
}

#[must_use]
pub fn zip_archive(members: &[Member]) -> Vec<u8> {
    let listed: Vec<usize> = (0..members.len()).collect();
    zip_archive_listing(members, &listed)
}

#[must_use]
pub fn zip_archive_listing(members: &[Member], listed: &[usize]) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut offsets = Vec::new();
    for member in members {
        offsets.push(length_u32(&archive));
        archive.extend_from_slice(&member.local_record());
    }
    let mut central = Vec::new();
    for index in listed {
        if let (Some(member), Some(offset)) = (members.get(*index), offsets.get(*index)) {
            central.extend_from_slice(&member.central_record(*offset));
        }
    }
    let central_offset = length_u32(&archive);
    archive.extend_from_slice(&central);
    archive.extend_from_slice(&end_record(listed.len(), &central, central_offset));
    archive
}

#[must_use]
pub fn end_record(listed: usize, central: &[u8], central_offset: u32) -> Vec<u8> {
    let count = u16::try_from(listed).unwrap_or(u16::MAX);
    let mut record = END_OF_CENTRAL_DIRECTORY.to_le_bytes().to_vec();
    for value in [0u16, 0, count, count] {
        record.extend_from_slice(&value.to_le_bytes());
    }
    for value in [length_u32(central), central_offset] {
        record.extend_from_slice(&value.to_le_bytes());
    }
    record.extend_from_slice(&0u16.to_le_bytes());
    record
}

#[must_use]
pub fn deflate(contents: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    if encoder.write_all(contents).is_err() {
        return Vec::new();
    }
    encoder.finish().unwrap_or_default()
}

fn length_u32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).unwrap_or(u32::MAX)
}

fn length_u16(bytes: &[u8]) -> u16 {
    u16::try_from(bytes.len()).unwrap_or(u16::MAX)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let low_bit_set = crc & 1 == 1;
            crc >>= 1;
            if low_bit_set {
                crc ^= CRC_POLYNOMIAL;
            }
        }
    }
    !crc
}
