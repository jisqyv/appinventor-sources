// Automatically generated rust module for 'chat.proto' file

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![cfg_attr(rustfmt, rustfmt_skip)]


use std::borrow::Cow;
use quick_protobuf::{MessageRead, MessageWrite, BytesReader, Writer, WriterBackend, Result};
use quick_protobuf::sizeofs::*;
use super::*;

#[derive(Debug, Default, PartialEq, Clone)]
pub struct unsigned<'a> {
    pub huuid: Option<Cow<'a, str>>,
    pub version: u64,
    pub generation: u64,
}

impl<'a> MessageRead<'a> for unsigned<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.huuid = Some(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(16) => msg.version = r.read_uint64(bytes)?,
                Ok(24) => msg.generation = r.read_uint64(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for unsigned<'a> {
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
pub struct token<'a> {
    pub version: u64,
    pub keyid: u64,
    pub generation: u64,
    pub unsigned: Option<Cow<'a, [u8]>>,
    pub signature: Option<Cow<'a, [u8]>>,
}

impl<'a> MessageRead<'a> for token<'a> {
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
                Ok(34) => msg.unsigned = Some(r.read_bytes(bytes).map(Cow::Borrowed)?),
                Ok(42) => msg.signature = Some(r.read_bytes(bytes).map(Cow::Borrowed)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for token<'a> {
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
pub struct request<'a> {
    pub version: u64,
    pub token: Option<token<'a>>,
    pub uuid: Option<Cow<'a, str>>,
    pub question: Option<Cow<'a, str>>,
    pub system: Option<Cow<'a, str>>,
    pub apikey: Option<Cow<'a, str>>,
    pub provider: Cow<'a, str>,
    pub model: Option<Cow<'a, str>>,
    pub inputimage: Option<Cow<'a, [u8]>>,
    pub doimage: Option<bool>,
}

impl<'a> MessageRead<'a> for request<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = request {
            version: 1u64,
            provider: Cow::Borrowed("chatgpt"),
            ..Self::default()
        };
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.version = r.read_uint64(bytes)?,
                Ok(18) => msg.token = Some(r.read_message::<token>(bytes)?),
                Ok(26) => msg.uuid = Some(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(34) => msg.question = Some(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(42) => msg.system = Some(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(50) => msg.apikey = Some(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(58) => msg.provider = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(66) => msg.model = Some(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(74) => msg.inputimage = Some(r.read_bytes(bytes).map(Cow::Borrowed)?),
                Ok(160) => msg.doimage = Some(r.read_bool(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for request<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.version == 1u64 { 0 } else { 1 + sizeof_varint(*(&self.version) as u64) }
        + self.token.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.uuid.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.question.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.system.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.apikey.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + if self.provider == Cow::Borrowed("chatgpt") { 0 } else { 1 + sizeof_len((&self.provider).len()) }
        + self.model.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.inputimage.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.doimage.as_ref().map_or(0, |m| 2 + sizeof_varint(*(m) as u64))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.version != 1u64 { w.write_with_tag(8, |w| w.write_uint64(*&self.version))?; }
        if let Some(ref s) = self.token { w.write_with_tag(18, |w| w.write_message(s))?; }
        if let Some(ref s) = self.uuid { w.write_with_tag(26, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.question { w.write_with_tag(34, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.system { w.write_with_tag(42, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.apikey { w.write_with_tag(50, |w| w.write_string(&**s))?; }
        if self.provider != Cow::Borrowed("chatgpt") { w.write_with_tag(58, |w| w.write_string(&**&self.provider))?; }
        if let Some(ref s) = self.model { w.write_with_tag(66, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.inputimage { w.write_with_tag(74, |w| w.write_bytes(&**s))?; }
        if let Some(ref s) = self.doimage { w.write_with_tag(160, |w| w.write_bool(*s))?; }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct response<'a> {
    pub version: u64,
    pub status: u64,
    pub uuid: Option<Cow<'a, str>>,
    pub answer: Option<Cow<'a, str>>,
    pub outputimage: Option<Cow<'a, [u8]>>,
}

impl<'a> MessageRead<'a> for response<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = response {
            version: 1u64,
            ..Self::default()
        };
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.version = r.read_uint64(bytes)?,
                Ok(16) => msg.status = r.read_uint64(bytes)?,
                Ok(26) => msg.uuid = Some(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(34) => msg.answer = Some(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(42) => msg.outputimage = Some(r.read_bytes(bytes).map(Cow::Borrowed)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for response<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.version == 1u64 { 0 } else { 1 + sizeof_varint(*(&self.version) as u64) }
        + if self.status == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.status) as u64) }
        + self.uuid.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.answer.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.outputimage.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.version != 1u64 { w.write_with_tag(8, |w| w.write_uint64(*&self.version))?; }
        if self.status != 0u64 { w.write_with_tag(16, |w| w.write_uint64(*&self.status))?; }
        if let Some(ref s) = self.uuid { w.write_with_tag(26, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.answer { w.write_with_tag(34, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.outputimage { w.write_with_tag(42, |w| w.write_bytes(&**s))?; }
        Ok(())
    }
}

