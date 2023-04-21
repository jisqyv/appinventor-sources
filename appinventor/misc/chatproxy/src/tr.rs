// Automatically generated rust module for 'tr.proto' file

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![cfg_attr(rustfmt, rustfmt_skip)]


use quick_protobuf::{MessageRead, MessageWrite, BytesReader, Writer, WriterBackend, Result};
use quick_protobuf::sizeofs::*;
use super::*;

#[derive(Debug, Default, PartialEq, Clone)]
pub struct unsigned {
    pub huuid: Option<String>,
    pub version: u64,
    pub generation: u64,
}

impl<'a> MessageRead<'a> for unsigned {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.huuid = Some(r.read_string(bytes)?.to_owned()),
                Ok(16) => msg.version = r.read_uint64(bytes)?,
                Ok(24) => msg.generation = r.read_uint64(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for unsigned {
    fn get_size(&self) -> usize {
        0
        + self.huuid.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + if self.version == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.version) as u64) }
        + if self.generation == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.generation) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.huuid { w.write_with_tag(10, |w| w.write_string(&**s))?; }
        if self.version != 0u64 { w.write_with_tag(16, |w| w.write_uint64(*&self.version))?; }
        if self.generation != 0u64 { w.write_with_tag(24, |w| w.write_uint64(*&self.generation))?; }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct token {
    pub version: u64,
    pub keyid: u64,
    pub generation: u64,
    pub unsigned: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

impl<'a> MessageRead<'a> for token {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = token {
            version: 1u64,
            keyid: 1u64,
            ..Self::default()
        };
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.version = r.read_uint64(bytes)?,
                Ok(16) => msg.keyid = r.read_uint64(bytes)?,
                Ok(24) => msg.generation = r.read_uint64(bytes)?,
                Ok(34) => msg.unsigned = Some(r.read_bytes(bytes)?.to_owned()),
                Ok(42) => msg.signature = Some(r.read_bytes(bytes)?.to_owned()),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for token {
    fn get_size(&self) -> usize {
        0
        + if self.version == 1u64 { 0 } else { 1 + sizeof_varint(*(&self.version) as u64) }
        + if self.keyid == 1u64 { 0 } else { 1 + sizeof_varint(*(&self.keyid) as u64) }
        + if self.generation == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.generation) as u64) }
        + self.unsigned.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.signature.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.version != 1u64 { w.write_with_tag(8, |w| w.write_uint64(*&self.version))?; }
        if self.keyid != 1u64 { w.write_with_tag(16, |w| w.write_uint64(*&self.keyid))?; }
        if self.generation != 0u64 { w.write_with_tag(24, |w| w.write_uint64(*&self.generation))?; }
        if let Some(ref s) = self.unsigned { w.write_with_tag(34, |w| w.write_bytes(&**s))?; }
        if let Some(ref s) = self.signature { w.write_with_tag(42, |w| w.write_bytes(&**s))?; }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct request {
    pub version: u64,
    pub token: Option<token>,
    pub uuid: Option<String>,
    pub question: Option<String>,
    pub system: Option<String>,
}

impl<'a> MessageRead<'a> for request {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = request {
            version: 1u64,
            ..Self::default()
        };
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.version = r.read_uint64(bytes)?,
                Ok(18) => msg.token = Some(r.read_message::<token>(bytes)?),
                Ok(26) => msg.uuid = Some(r.read_string(bytes)?.to_owned()),
                Ok(34) => msg.question = Some(r.read_string(bytes)?.to_owned()),
                Ok(42) => msg.system = Some(r.read_string(bytes)?.to_owned()),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for request {
    fn get_size(&self) -> usize {
        0
        + if self.version == 1u64 { 0 } else { 1 + sizeof_varint(*(&self.version) as u64) }
        + self.token.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.uuid.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.question.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.system.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.version != 1u64 { w.write_with_tag(8, |w| w.write_uint64(*&self.version))?; }
        if let Some(ref s) = self.token { w.write_with_tag(18, |w| w.write_message(s))?; }
        if let Some(ref s) = self.uuid { w.write_with_tag(26, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.question { w.write_with_tag(34, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.system { w.write_with_tag(42, |w| w.write_string(&**s))?; }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct response {
    pub version: u64,
    pub status: u64,
    pub uuid: Option<String>,
    pub answer: Option<String>,
}

impl<'a> MessageRead<'a> for response {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = response {
            version: 1u64,
            ..Self::default()
        };
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.version = r.read_uint64(bytes)?,
                Ok(16) => msg.status = r.read_uint64(bytes)?,
                Ok(26) => msg.uuid = Some(r.read_string(bytes)?.to_owned()),
                Ok(34) => msg.answer = Some(r.read_string(bytes)?.to_owned()),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for response {
    fn get_size(&self) -> usize {
        0
        + if self.version == 1u64 { 0 } else { 1 + sizeof_varint(*(&self.version) as u64) }
        + if self.status == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.status) as u64) }
        + self.uuid.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.answer.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.version != 1u64 { w.write_with_tag(8, |w| w.write_uint64(*&self.version))?; }
        if self.status != 0u64 { w.write_with_tag(16, |w| w.write_uint64(*&self.status))?; }
        if let Some(ref s) = self.uuid { w.write_with_tag(26, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.answer { w.write_with_tag(34, |w| w.write_string(&**s))?; }
        Ok(())
    }
}

