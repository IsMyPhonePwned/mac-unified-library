// SPDX-License-Identifier: GPL-3.0-only

//! Tracev3 chunk tag constants (community-documented; verified against fixtures).

pub const TAG_HEADER: u32 = 0x1000;
pub const TAG_CATALOG: u32 = 0x600B;
pub const TAG_CHUNKSET: u32 = 0x600D;
pub const TAG_FIREHOSE: u32 = 0x6001;
pub const TAG_OVERSIZE: u32 = 0x6002;
pub const TAG_STATEDUMP: u32 = 0x6003;
pub const TAG_SIMPLEDUMP: u32 = 0x6004;

pub const SUB_CONT_TIME: u32 = 0x6100;
pub const SUB_BUILD: u32 = 0x6101;
pub const SUB_BOOT_UUID: u32 = 0x6102;
pub const SUB_TIMEZONE: u32 = 0x6103;

pub const COMPRESSION_LZ4: u32 = 0x100;
