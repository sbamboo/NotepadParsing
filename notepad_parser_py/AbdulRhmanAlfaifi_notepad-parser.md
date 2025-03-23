# Source: https://github.com/AbdulRhmanAlfaifi/notepad_parser/tree/main/src

## /src/bin/notepad_parser.rs
```rs
use clap::{value_parser, Arg, Command};
use csv::WriterBuilder;
use glob::glob;
use notepad_parser::{
    enums::{CRType, Encoding},
    errors::NotepadErrors,
    NotepadTabStat,
};
use serde::Serialize;
use serde_json;
use std::{
    convert::From,
    fs::File,
    io::{self, Write},
    process::exit,
};

use log::*;
use log4rs::{
    append::console::{ConsoleAppender, Target},
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
    Config,
};

use winparsingtools::date_time::FileTime;

enum OutputFormat {
    JSONL,
    CSV,
}

impl From<&str> for OutputFormat {
    fn from(value: &str) -> Self {
        match value {
            "jsonl" => OutputFormat::JSONL,
            "csv" => OutputFormat::CSV,
            _ => OutputFormat::JSONL,
        }
    }
}

#[derive(Debug, Serialize)]
struct CsvRecord {
    tabstate_path: Option<String>,
    is_saved_file: bool,
    path_size: u64,
    path: Option<String>,
    file_size: Option<u64>,
    encoding: Option<Encoding>,
    cr_type: Option<CRType>,
    last_write_time: Option<FileTime>,
    file_hash: Option<String>,
    cursor_start: Option<u64>,
    cursor_end: Option<u64>,
    word_wrap: bool,
    rtl: bool,
    show_unicode: bool,
    version: u64,
    file_content_size: u64,
    file_content: String,
    contain_unsaved_data: bool,
    checksum: String,
    unsaved_chunks_str: Option<String>,
    raw: String,
}

impl From<NotepadTabStat> for CsvRecord {
    fn from(value: NotepadTabStat) -> Self {
        let json_data = match serde_json::to_string(&value) {
            Ok(data) => data,
            Err(e) => e.to_string(),
        };
        Self {
            tabstate_path: value.tabstate_path,
            is_saved_file: value.is_saved_file,
            path_size: value.path_size,
            path: value.path,
            file_size: value.file_size,
            encoding: value.encoding,
            cr_type: value.cr_type,
            last_write_time: value.last_write_time,
            file_hash: value.file_hash,
            cursor_start: value.cursor_start,
            cursor_end: value.cursor_end,
            word_wrap: value.config_block.word_wrap,
            rtl: value.config_block.rtl,
            show_unicode: value.config_block.show_unicode,
            version: value.config_block.version,
            file_content_size: value.file_content_size,
            file_content: value.file_content,
            contain_unsaved_data: value.contain_unsaved_data,
            checksum: value.checksum,
            unsaved_chunks_str: value.unsaved_chunks_str,
            raw: json_data,
        }
    }
}

fn init_logger(level: log::LevelFilter) -> log4rs::Handle {
    let log_format = "{d(%Y-%m-%d %H:%M:%S)(utc)} [{t}:{L:<3}] {h({l:<5})} {m}\n";

    let stderr = ConsoleAppender::builder()
        .target(Target::Stderr)
        .encoder(Box::new(PatternEncoder::new(log_format)))
        .build();

    // Log Trace level output to file where trace is the default level
    // and the programmatically specified level to stderr

    let config_builder =
        Config::builder().appender(Appender::builder().build("stderr", Box::new(stderr)));

    let root_builder = Root::builder().appender("stderr");

    let config = config_builder.build(root_builder.build(level)).unwrap();

    log4rs::init_config(config).unwrap()
}

fn main() {
    let cli = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AbdulRhman Alfaifi <aalfaifi@u0041.co>")
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .help_template("\
{before-help}

Created By: {author}
Version: v{version}
Reference: https://u0041.co/posts/articals/exploring-windows-artifacts-notepad-files/

{about}

{usage-heading} {usage}

{all-args}{after-help}
")
        .arg(
            Arg::new("input-file")
                .value_name("FILE")
                .help("Path the files to parse. Accepts glob.")
                .default_value("C:\\Users\\*\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\????????-????-????-????-????????????.bin")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("output-format")
                .short('f')
                .long("output-format")
                .value_name("FORMAT")
                .help("Specifiy the output format")
                .value_parser(["jsonl", "csv"])
                .default_value("jsonl"),
        )
        .arg(
            Arg::new("output-path")
                .short('o')
                .long("output-path")
                .value_name("FILE")
                .help("Specifiy the output file")
                .value_parser(value_parser!(String))
                .default_value("stdout"),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Level for logs")
                .value_parser(["trace", "debug", "info", "error", "quiet"])
                .default_value("quiet"),
        )
        .get_matches();

    let path = match cli.get_one::<String>("input-file") {
        Some(path) => path,
        None => "C:\\Users\\*\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\*.bin"
    };
    let output_format = match cli.get_one::<String>("output-format") {
        Some(format) => OutputFormat::from(format.to_owned().as_str()),
        None => OutputFormat::from("jsonl"),
    };

    let mut output_path = "stdout".to_string();
    let mut output: Box<dyn Write> = match cli.get_one::<String>("output-path") {
        Some(path) => {
            output_path = path.to_owned();
            match output_path.as_str() {
                "stdout" => Box::new(io::stdout()),
                path => match File::create(path) {
                    Ok(f) => Box::new(f),
                    Err(e) => {
                        error!(
                            "Unable create the output file '{}', ERROR: {}. Exiting...",
                            path, e
                        );
                        exit(1);
                    }
                },
            }
        }
        None => Box::new(io::stdout()),
    };

    let log_level = match cli
        .get_one::<String>("log-level")
        .unwrap()
        .to_owned()
        .as_str()
    {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Off,
    };

    init_logger(log_level);

    let mut csv_headers_printed = false;
    // if let OutputFormat::CSV = output_format {}

    for entry in glob(path).expect("Failed to read glob pattern") {
        match entry {
            Ok(path_match) => {
                let path_str = match path_match.to_str() {
                    Some(p) => p,
                    None => {
                        error!(
                            "Unable to convert from String to &str for '{}'",
                            path_match.to_string_lossy()
                        );
                        continue;
                    }
                };
                match NotepadTabStat::from_path(path_str) {
                    Ok(data) => match output_format {
                        OutputFormat::JSONL => match serde_json::to_string(&data) {
                            Ok(json) => match write!(output, "{}\n", json) {
                                Ok(_) => debug!(
                                    "Successfully writen JSON data for the file '{}'",
                                    path_str
                                ),
                                Err(e) => error!(
                                    "Error while writing the JSON data for the file '{}', ERROR: {}",
                                    path_str,
                                    e
                                ),
                            },
                            Err(e) => {
                                error!(
                                    "{}",
                                    NotepadErrors::CLIError(
                                        e.to_string(),
                                        format!(
                                            "Unable to convert results to JSON for the file '{}'",
                                            path_str
                                        )
                                    )
                                );
                            }
                        },
                        OutputFormat::CSV => {
                            let mut csv_writer = WriterBuilder::new();
                            let mut csv_writer_builder;
                            if csv_headers_printed {
                                csv_writer_builder =
                                    csv_writer.has_headers(false).from_writer(vec![]);
                            } else {
                                csv_writer_builder =
                                    csv_writer.has_headers(true).from_writer(vec![]);
                                csv_headers_printed = true;
                            }

                            let csv_record = CsvRecord::from(data);
                            match csv_writer_builder.serialize(csv_record) {
                                Ok(_) => debug!(
                                    "Successfuly serilized CSV row for the file '{}'",
                                    path_str
                                ),
                                Err(e) => error!(
                                    "Unable to write CSV row, ERROR: {}, PATH: '{}'",
                                    e, path_str
                                ),
                            }
                            match csv_writer_builder.flush() {
                                Ok(_) => trace!(
                                    "Susseccfuly flushed the CSV record for the file '{}'",
                                    path_str
                                ),
                                Err(e) => error!(
                                    "Unable to flush CSV record, ERROR: {}, PATH: '{}'",
                                    e, path_str
                                ),
                            }

                            let row = match csv_writer_builder.into_inner() {
                                Ok(bytes) => match String::from_utf8(bytes) {
                                    Ok(r) => r,
                                    Err(e) => {
                                        error!("Unable to convert CSV writer buffer to String, ERROR: {}", e);
                                        continue;
                                    }
                                },
                                Err(e) => {
                                    error!("Unable to convert CSV writer to String, ERROR: {}", e);
                                    continue;
                                }
                            };
                            match write!(output, "{}", row) {
                                Ok(_) => debug!(
                                    "Successfully writen the CSV row for file '{}' to '{}'",
                                    path_str, output_path
                                ),
                                Err(e) => error!(
                                    "Unable to write the CSV row for file '{}' to '{}', ERROR: {}",
                                    path_str, output_path, e
                                ),
                            }
                        }
                    },
                    Err(e) => {
                        error!(
                            "{}",
                            NotepadErrors::CLIError(
                                e.to_string(),
                                format!("Unable to parse the file '{}'", path_str)
                            )
                        );
                    }
                }
            }
            Err(e) => eprintln!("{:?}", e),
        }
    }
}
```

## /src/enums.rs
```rs
use serde::Serialize;

#[derive(Serialize, Debug)]
#[repr(u8)]
pub enum Encoding {
    ANSI = 0x01,
    UTF16LE = 0x02,
    UTF16BE = 0x03,
    UTF8BOM = 0x04,
    UTF8 = 0x05,
    UNKNOWN(u8),
}

impl From<u8> for Encoding {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Encoding::ANSI,
            0x02 => Encoding::UTF16LE,
            0x03 => Encoding::UTF16BE,
            0x04 => Encoding::UTF8BOM,
            0x05 => Encoding::UTF8,
            x => Encoding::UNKNOWN(x),
        }
    }
}

#[derive(Serialize, Debug)]
#[repr(u8)]
pub enum CRType {
    CRLF = 0x1,
    CR = 0x2,
    LF = 0x3,
    UNKNOWN(u8),
}

impl From<u8> for CRType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => CRType::CRLF,
            0x02 => CRType::CR,
            0x03 => CRType::LF,
            x => CRType::UNKNOWN(x),
        }
    }
}
```

## /src/errors.rs
```rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NotepadErrors {
    #[error("Encountered an error. Error: '{0}', Function: '{1}', Additinal: '{2}'")]
    Generic(String, String, String),
    #[error(
        "File signature does't match the correct TabState file format. Expected 'NP', found '{0}'"
    )]
    Signature(String),
    #[error("Unable to read data. Error: '{0}', Field: '{1}'")]
    ReadError(String, String),
    #[error("Unable to read data. Error: '{0}', Field: '{1}', Size: '{2}'")]
    ReadErrorWithSize(String, String, String),
    #[error("Unexpected value found. Expected: '{0}', Found: '{1}', Field: '{2}'")]
    UnexpectedValue(String, String, String),
    #[error("EoF Reached")]
    EoF,
    #[error("No data to parse")]
    NA,
    #[error("Error while opening a file. ERROR: '{0}', PATH: '{1}'")]
    FileOpen(String, String),
    #[error("CLI error. ERROR: '{0}', MSG: '{1}'")]
    CLIError(String, String),
}
```

## /src/lib.rs
```rs
/// A Library to parse Windows Notepad `TabState` artifacts
pub mod enums;
pub mod errors;
#[cfg(test)]
mod tests;
pub mod traits;
pub mod unsaved_chunks;

use byteorder::ReadBytesExt;
use enums::{CRType, Encoding};
use errors::NotepadErrors;
use serde::Serialize;
use std::convert::From;
use std::io::Read;
use unsaved_chunks::UnsavedChunks;
use winparsingtools::{
    date_time::FileTime, utils::bytes_to_hex, utils::read_uleb128, utils::read_utf16_string,
};

use std::fs::File;
use traits::ReadBool;

#[derive(Serialize, Debug)]
pub struct ConfigBlock {
    pub word_wrap: bool,
    pub rtl: bool,
    pub show_unicode: bool,
    pub version: u64,
    unknown0: u8,
    unknown1: u8,
}

impl ConfigBlock {
    pub fn from_reader<R: Read>(reader: &mut R) -> std::result::Result<Self, NotepadErrors> {
        // Read `word_wrap` feild
        let word_wrap = match reader.read_bool() {
            Ok(flag) => flag,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "ConfigBlock::word_wrap".to_string(),
                ))
            }
        };
        let rtl = match reader.read_bool() {
            Ok(flag) => flag,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "ConfigBlock::rtl".to_string(),
                ))
            }
        };
        let show_unicode = match reader.read_bool() {
            Ok(flag) => flag,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "ConfigBlock::show_unicode".to_string(),
                ))
            }
        };

        let version = match read_uleb128(reader) {
            Ok(data) => data,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "ConfigBlock::version".to_string(),
                ))
            }
        };

        let unknown0 = match reader.read_u8() {
            Ok(data) => data,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "ConfigBlock::unknown0".to_string(),
                ))
            }
        };

        let unknown1 = match reader.read_u8() {
            Ok(data) => data,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "ConfigBlock::unknown1".to_string(),
                ))
            }
        };

        Ok(Self {
            word_wrap,
            rtl,
            show_unicode,
            version,
            unknown0,
            unknown1,
        })
    }
}

impl Default for ConfigBlock {
    fn default() -> Self {
        Self {
            word_wrap: false,
            rtl: false,
            show_unicode: false,
            version: 0,
            unknown0: 0,
            unknown1: 0,
        }
    }
}
/// Represents the structure for `TabState` files
#[derive(Serialize, Debug)]
#[allow(dead_code)]
pub struct NotepadTabStat {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tabstate_path: Option<String>,
    #[serde(skip_serializing)]
    pub signature: [u8; 2],
    // #[serde(skip_serializing)]
    pub seq_number: u64,
    pub is_saved_file: bool,
    pub path_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<Encoding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cr_type: Option<CRType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_write_time: Option<FileTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_hash: Option<String>,
    #[serde(skip_serializing)]
    pub unknown1: Option<[u8; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_start: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_end: Option<u64>,
    pub config_block: ConfigBlock,
    pub file_content_size: u64,
    pub file_content: String,
    pub contain_unsaved_data: bool,
    pub checksum: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsaved_chunks: Option<UnsavedChunks>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsaved_chunks_str: Option<String>,
}

impl Default for NotepadTabStat {
    fn default() -> Self {
        Self {
            tabstate_path: Option::None,
            signature: [0x4E, 0x50],
            seq_number: 0x00,
            is_saved_file: false,
            path_size: 0x01,
            path: Option::None,
            file_size: Option::None,
            encoding: Option::None,
            cr_type: Option::None,
            last_write_time: Option::None,
            file_hash: Option::None,
            unknown1: Option::None,
            cursor_start: Option::None,
            cursor_end: Option::None,
            config_block: ConfigBlock::default(),
            file_content_size: 0,
            file_content: String::from("Hello :D"),
            contain_unsaved_data: false,
            checksum: String::from("41414141"),
            unsaved_chunks: Option::None,
            unsaved_chunks_str: Option::None,
        }
    }
}

impl NotepadTabStat {
    /// Read the file from `path` and use `from_reader` to parse it
    pub fn from_path(path: &str) -> std::result::Result<Self, NotepadErrors> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) => return Err(NotepadErrors::FileOpen(e.to_string(), format!("{}", path))),
        };

        let mut parsed = match NotepadTabStat::from_reader(&mut file) {
            Ok(data) => data,
            Err(e) => {
                return Err(NotepadErrors::Generic(
                    e.to_string(),
                    "NotepadTabStat::from_path".to_string(),
                    "Error during parsing".to_string(),
                ));
            }
        };

        parsed.tabstate_path = Some(String::from(path));

        Ok(parsed)
    }

    /// Parse data from reader
    pub fn from_reader<R: Read>(reader: &mut R) -> std::result::Result<Self, NotepadErrors> {
        // Read first two bytes as `signature`
        let mut signature = [0u8; 2];
        if let Err(e) = reader.read_exact(&mut signature) {
            return Err(NotepadErrors::ReadError(
                e.to_string(),
                "signature".to_string(),
            ));
        }
        if signature != [0x4E, 0x50] {
            return Err(NotepadErrors::Signature(
                String::from_utf8_lossy(&signature).to_string(),
            ));
        }

        // Read unknown byte
        let seq_number = match read_uleb128(reader) {
            Ok(num) => num,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "unknown0".to_string(),
                ))
            }
        };

        // Read the flag `is_saved_file`
        let is_saved_file = match reader.read_u8() {
            Ok(flag) => match flag {
                0x0 => false,
                0x1 => true,
                x => {
                    return Err(NotepadErrors::UnexpectedValue(
                        "bool <0x1|0x0>".to_string(),
                        format!("{}", x),
                        "is_saved_file".to_string(),
                    ))
                }
            },
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "is_saved_file".to_string(),
                ))
            }
        };

        // Read `path_size`
        let path_size = match read_uleb128(reader) {
            Ok(size) => size,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "path_size".to_string(),
                ))
            }
        };

        // If the TabState file is for a saved file, extract the additinal data
        if is_saved_file {
            // Read the `path`
            let path = match read_utf16_string(reader, Option::Some(path_size as usize)) {
                Ok(path) => path,
                Err(e) => {
                    return Err(NotepadErrors::ReadErrorWithSize(
                        e.to_string(),
                        "path".to_string(),
                        path_size.to_string(),
                    ))
                }
            };

            // Read `file_size`. File size on the disk
            let file_size = match read_uleb128(reader) {
                Ok(size) => size,
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "file_size".to_string(),
                    ))
                }
            };

            // Read `encoding`. The encoding used to be used by notepad to view the file
            let encoding = match reader.read_u8() {
                Ok(encoding) => Encoding::from(encoding),
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "encoding".to_string(),
                    ))
                }
            };

            // Read `cr_type` field.
            let cr_type = match reader.read_u8() {
                Ok(cr_type) => CRType::from(cr_type),
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "cr_type".to_string(),
                    ))
                }
            };

            // Read `last_write_time`. This is the last write timestamp for the file
            let last_write_time = match read_uleb128(reader) {
                Ok(timestamp) => FileTime::new(timestamp),
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "last_write_time".to_string(),
                    ));
                }
            };

            // Read `file_hash`. This is the SHA256 hash of the file content on disk
            let mut file_hash = [0u8; 32];
            if let Err(e) = reader.read_exact(&mut file_hash) {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "file_hash".to_string(),
                ));
            }

            // Read `unknown1`
            let mut unknown1 = [0u8; 2];
            if let Err(e) = reader.read_exact(&mut unknown1) {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "unknown1".to_string(),
                ));
            }

            // Read `cursor_start`. This is starting point of the text selection
            let cursor_start = match read_uleb128(reader) {
                Ok(cs) => cs,
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "cursor_start".to_string(),
                    ));
                }
            };

            // Read `cursor_end`
            let cursor_end = match read_uleb128(reader) {
                Ok(ce) => ce,
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "cursor_end".to_string(),
                    ));
                }
            };

            // Read unknown2
            //TODO: Change to config block
            let config_block = ConfigBlock::from_reader(reader)?;
            // let mut unknown2 = [0u8; 6];
            // if let Err(e) = reader.read_exact(&mut unknown2) {
            //     return Err(NotepadErrors::ReadError(
            //         e.to_string(),
            //         "unknown2".to_string(),
            //     ));
            // }

            // Read `file_content_size`. This is the size of the content in the TabState in chars not bytes
            let file_content_size = match read_uleb128(reader) {
                Ok(size) => size,
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "file_content_size".to_string(),
                    ));
                }
            };

            // Read `file_content`. This is the file contant inside the TabState file
            let file_content =
                match read_utf16_string(reader, Option::Some(file_content_size as usize)) {
                    Ok(data) => data,
                    Err(e) => {
                        return Err(NotepadErrors::ReadError(
                            e.to_string(),
                            "file_content".to_string(),
                        ));
                    }
                };

            // Read `contain_unsaved_data`
            let contain_unsaved_data = match reader.read_u8() {
                Ok(flag) => match flag {
                    0x0 => false,
                    0x1 => true,
                    x => {
                        return Err(NotepadErrors::UnexpectedValue(
                            "bool <0x0|0x1>".to_string(),
                            x.to_string(),
                            "contain_unsaved_data".to_string(),
                        ));
                    }
                },
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "contain_unsaved_data".to_string(),
                    ));
                }
            };

            // Read `checksum`. CRC32 checksum for the previous data starting from offset 0x3
            let mut checksum = [0u8; 4];
            if let Err(e) = reader.read_exact(&mut checksum) {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "checksum".to_string(),
                ));
            }

            let unsaved_chunks = match UnsavedChunks::from_reader(reader) {
                Ok(data) => Option::Some(data),
                Err(e) => match e {
                    NotepadErrors::NA => Option::None,
                    _ => {
                        return Err(e);
                    }
                },
            };

            let unsaved_chunks_str = match &unsaved_chunks {
                Some(data) => Option::Some(data.to_string()),
                None => Option::None,
            };

            Ok(Self {
                tabstate_path: Option::None,
                signature,
                seq_number,
                is_saved_file,
                path_size,
                path: Option::Some(path),
                file_size: Option::Some(file_size),
                encoding: Option::Some(encoding),
                cr_type: Option::Some(cr_type),
                last_write_time: Option::Some(last_write_time),
                file_hash: Option::Some(bytes_to_hex(&file_hash.to_vec())),
                unknown1: Option::Some(unknown1),
                cursor_start: Option::Some(cursor_start),
                cursor_end: Option::Some(cursor_end),
                config_block,
                file_content_size,
                file_content,
                contain_unsaved_data,
                checksum: bytes_to_hex(&checksum.to_vec()),
                unsaved_chunks,
                unsaved_chunks_str,
            })
        }
        // File isn't saved to file
        else {
            // Read `cursor_start`. This is starting point of the text selection
            let cursor_start = match read_uleb128(reader) {
                Ok(cs) => cs,
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "cursor_start".to_string(),
                    ));
                }
            };

            // Read `cursor_end`
            let cursor_end = match read_uleb128(reader) {
                Ok(ce) => ce,
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "cursor_end".to_string(),
                    ));
                }
            };
            // Read `unknown3`
            let config_block = ConfigBlock::from_reader(reader)?;

            // Read `file_content_size`. This is the size of the content in the TabState in chars not bytes
            let file_content_size = match read_uleb128(reader) {
                Ok(size) => size,
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "file_content_size".to_string(),
                    ));
                }
            };

            let file_content =
                match read_utf16_string(reader, Option::Some(file_content_size as usize)) {
                    Ok(data) => data,
                    Err(e) => {
                        return Err(NotepadErrors::ReadError(
                            e.to_string(),
                            "file_content".to_string(),
                        ));
                    }
                };

            // Read `contain_unsaved_data`
            let contain_unsaved_data = match reader.read_u8() {
                Ok(flag) => match flag {
                    0x0 => false,
                    0x1 => true,
                    x => {
                        return Err(NotepadErrors::UnexpectedValue(
                            "bool <0x0|0x1>".to_string(),
                            x.to_string(),
                            "contain_unsaved_data".to_string(),
                        ));
                    }
                },
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "contain_unsaved_data".to_string(),
                    ));
                }
            };

            // Read `checksum`. CRC32 checksum for the previous data starting from offset 0x3
            let mut checksum = [0u8; 4];
            if let Err(e) = reader.read_exact(&mut checksum) {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "checksum".to_string(),
                ));
            }

            let unsaved_chunks = match UnsavedChunks::from_reader(reader) {
                Ok(data) => Option::Some(data),
                Err(e) => match e {
                    NotepadErrors::NA => Option::None,
                    _ => {
                        return Err(e);
                    }
                },
            };

            let unsaved_chunks_str = match &unsaved_chunks {
                Some(data) => Option::Some(data.to_string()),
                None => Option::None,
            };

            Ok(Self {
                tabstate_path: Option::None,
                signature,
                seq_number,
                is_saved_file,
                path_size,
                path: Option::None,
                file_size: Option::None,
                encoding: Option::None,
                cr_type: Option::None,
                last_write_time: Option::None,
                file_hash: Option::None,
                unknown1: Option::None,
                cursor_start: Some(cursor_start),
                cursor_end: Some(cursor_end),
                file_content_size,
                config_block,
                file_content,
                contain_unsaved_data,
                checksum: bytes_to_hex(&checksum.to_vec()),
                unsaved_chunks,
                unsaved_chunks_str,
            })
        }
    }
}
```

## /src/tests.rs
```rs
use crate::unsaved_chunks::UnsavedChunks;
use crate::NotepadTabStat;
use glob::glob;
use serde_json;

const SAMPLES_DIR_NAME: &str = "samples";

//Start: Utils
fn get_paths_from_glob(glob_path: &str) -> Vec<String> {
    let res = glob(glob_path)
        .unwrap()
        .into_iter()
        .map(|x| x.unwrap().to_string_lossy().to_string())
        .collect::<Vec<String>>();

    if res.len() == 0 {
        panic!("Glob list is empty!");
    }

    res
}

fn check_rtl(data: &NotepadTabStat) -> bool {
    data.config_block.rtl
}

fn check_word_wrap(data: &NotepadTabStat) -> bool {
    data.config_block.word_wrap
}

fn check_unsaved_chunks(data: &NotepadTabStat) -> bool {
    match data.unsaved_chunks {
        Some(_) => true,
        None => false,
    }
}

fn check_is_saved(data: &NotepadTabStat) -> bool {
    data.is_saved_file
}

#[allow(dead_code)]
fn check_contain_unsaved_data(data: &NotepadTabStat) -> bool {
    data.contain_unsaved_data
}

// End: Utils

#[cfg(test)]
#[test]
fn tabstate_no_path() {
    let data: [u8; 0x3D] = [
        0x4E, 0x50, 0x00, 0x00, 0x01, 0x15, 0x15, 0x01, 0x00, 0x00, 0x02, 0x01, 0x01, 0x15, 0x50,
        0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x77, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x64, 0x00,
        0x20, 0x00, 0x69, 0x00, 0x73, 0x00, 0x20, 0x00, 0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x64,
        0x00, 0x20, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x00, 0x01, 0xDD, 0xBD, 0x91,
        0xE1,
    ];
    let mut reader = &data[..];
    let res = NotepadTabStat::from_reader(&mut reader).unwrap();
    let json = serde_json::to_string_pretty(&res).unwrap();
    println!("{}", json);
}

#[cfg(test)]
#[test]
fn tabstate_has_path_arabic_test() {
    let data: [u8; 0xB6] = [
        0x4E, 0x50, 0x00, 0x01, 0x19, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x69, 0x00,
        0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x54, 0x00, 0x65,
        0x00, 0x6D, 0x00, 0x70, 0x00, 0x5C, 0x00, 0x2A, 0x06, 0x2C, 0x06, 0x31, 0x06, 0x28, 0x06,
        0x29, 0x06, 0x2E, 0x00, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x2C, 0x02, 0x01, 0x97, 0x83,
        0x84, 0x89, 0xDE, 0xB8, 0xB9, 0xED, 0x01, 0xA0, 0x41, 0x6E, 0xAD, 0x5D, 0xC8, 0x6E, 0xDD,
        0xFD, 0x52, 0x8D, 0x13, 0x72, 0x36, 0x1A, 0x8D, 0xEA, 0xC6, 0x5D, 0x32, 0x92, 0x83, 0x6B,
        0x0E, 0x51, 0x5D, 0x1D, 0x31, 0x1C, 0x0F, 0xCA, 0x8A, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x02, 0x01, 0x01, 0x15, 0x47, 0x06, 0x30, 0x06, 0x4A, 0x06, 0x20, 0x00, 0x2A, 0x06,
        0x2C, 0x06, 0x31, 0x06, 0x28, 0x06, 0x29, 0x06, 0x2C, 0x00, 0x20, 0x00, 0x27, 0x06, 0x44,
        0x06, 0x45, 0x06, 0x44, 0x06, 0x41, 0x06, 0x20, 0x00, 0x45, 0x06, 0x2D, 0x06, 0x41, 0x06,
        0x48, 0x06, 0x00, 0x22, 0x1F, 0x14, 0x5E, 0x00, 0x00, 0x01, 0x37, 0x06, 0xBE, 0x84, 0x98,
        0x2B, 0x00, 0x01, 0x00, 0xE6, 0x5A, 0xE8, 0x53, 0x15, 0x00, 0x01, 0x38, 0x06, 0x91, 0x1C,
        0x9C, 0x16,
    ];
    let mut reader = &data[..];
    let res = NotepadTabStat::from_reader(&mut reader).unwrap();
    let json = serde_json::to_string_pretty(&res).unwrap();
    println!("{}", json);
}

#[cfg(test)]
#[test]
fn tabstate_has_path_english_contain_unsaved_chunks_test() {
    let data: [u8; 0x15F] = [
        0x4E, 0x50, 0x00, 0x01, 0x18, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x69, 0x00,
        0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x54, 0x00, 0x65,
        0x00, 0x6D, 0x00, 0x70, 0x00, 0x5C, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00,
        0x2E, 0x00, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x20, 0x05, 0x01, 0xE1, 0x8F, 0xA1, 0xB4,
        0x8F, 0xBC, 0xBA, 0xED, 0x01, 0xC6, 0x0D, 0x8F, 0xFB, 0xD2, 0xFF, 0x96, 0x9A, 0x36, 0xBF,
        0xFC, 0xA3, 0x1F, 0x60, 0x9E, 0x80, 0x1E, 0x8E, 0x0B, 0x8D, 0xE4, 0x15, 0x68, 0xE9, 0x48,
        0xDB, 0xEB, 0xAC, 0x1B, 0xD9, 0xB2, 0xE4, 0x00, 0x01, 0x1F, 0x1F, 0x01, 0x00, 0x00, 0x02,
        0x01, 0x01, 0x1F, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x20, 0x00, 0x73, 0x00,
        0x61, 0x00, 0x76, 0x00, 0x65, 0x00, 0x64, 0x00, 0x20, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73,
        0x00, 0x74, 0x00, 0x0D, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x20, 0x00,
        0x73, 0x00, 0x61, 0x00, 0x76, 0x00, 0x65, 0x00, 0x64, 0x00, 0x20, 0x00, 0x74, 0x00, 0x65,
        0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0xF4, 0x4C, 0x93, 0xE7, 0x1F, 0x00, 0x01, 0x0D, 0x00,
        0x90, 0xFE, 0xE3, 0x34, 0x20, 0x00, 0x01, 0x74, 0x00, 0x4D, 0x72, 0x0E, 0xDC, 0x21, 0x00,
        0x01, 0x68, 0x00, 0x96, 0x65, 0x7A, 0x31, 0x22, 0x00, 0x01, 0x69, 0x00, 0xC8, 0xDE, 0x31,
        0xA0, 0x23, 0x00, 0x01, 0x73, 0x00, 0x45, 0x93, 0xE2, 0xCB, 0x24, 0x00, 0x01, 0x20, 0x00,
        0x66, 0x25, 0x30, 0x4C, 0x25, 0x00, 0x01, 0x61, 0x00, 0xB2, 0x27, 0x67, 0xB8, 0x26, 0x00,
        0x01, 0x20, 0x00, 0x1C, 0xE5, 0x63, 0x2C, 0x26, 0x01, 0x00, 0xDA, 0x9A, 0xD2, 0x01, 0x25,
        0x01, 0x00, 0xD8, 0xDC, 0x6C, 0x58, 0x25, 0x00, 0x01, 0x69, 0x00, 0x7A, 0xFE, 0xED, 0xB0,
        0x26, 0x00, 0x01, 0x73, 0x00, 0x8D, 0x73, 0x6D, 0xBB, 0x27, 0x00, 0x01, 0x20, 0x00, 0x21,
        0x85, 0x4A, 0x9C, 0x28, 0x00, 0x01, 0x75, 0x00, 0x64, 0x19, 0x74, 0x5C, 0x29, 0x00, 0x01,
        0x6E, 0x00, 0xF0, 0x4F, 0x96, 0x76, 0x2A, 0x00, 0x01, 0x73, 0x00, 0x48, 0x83, 0x80, 0xBA,
        0x2B, 0x00, 0x01, 0x61, 0x00, 0x0D, 0x17, 0xD9, 0xD9, 0x2C, 0x00, 0x01, 0x76, 0x00, 0xBA,
        0xB4, 0x81, 0x5F, 0x2D, 0x00, 0x01, 0x65, 0x00, 0xE6, 0x3B, 0xE9, 0x7D, 0x2E, 0x00, 0x01,
        0x64, 0x00, 0xB8, 0x80, 0xA2, 0xEC,
    ];
    let mut reader = &data[..];
    let res = NotepadTabStat::from_reader(&mut reader).unwrap();
    let json = serde_json::to_string_pretty(&res).unwrap();
    println!("{}", json);
}

#[cfg(test)]
#[test]
fn tabstate_has_path_english_test() {
    let data: [u8; 0xAF] = [
        0x4E, 0x50, 0x00, 0x01, 0x18, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x69, 0x00,
        0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x54, 0x00, 0x65,
        0x00, 0x6D, 0x00, 0x70, 0x00, 0x5C, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00,
        0x2E, 0x00, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x20, 0x05, 0x01, 0xE1, 0x8F, 0xA1, 0xB4,
        0x8F, 0xBC, 0xBA, 0xED, 0x01, 0xC6, 0x0D, 0x8F, 0xFB, 0xD2, 0xFF, 0x96, 0x9A, 0x36, 0xBF,
        0xFC, 0xA3, 0x1F, 0x60, 0x9E, 0x80, 0x1E, 0x8E, 0x0B, 0x8D, 0xE4, 0x15, 0x68, 0xE9, 0x48,
        0xDB, 0xEB, 0xAC, 0x1B, 0xD9, 0xB2, 0xE4, 0x00, 0x01, 0x1F, 0x1F, 0x01, 0x00, 0x00, 0x02,
        0x01, 0x01, 0x1F, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x20, 0x00, 0x73, 0x00,
        0x61, 0x00, 0x76, 0x00, 0x65, 0x00, 0x64, 0x00, 0x20, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73,
        0x00, 0x74, 0x00, 0x0D, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x20, 0x00,
        0x73, 0x00, 0x61, 0x00, 0x76, 0x00, 0x65, 0x00, 0x64, 0x00, 0x20, 0x00, 0x74, 0x00, 0x65,
        0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0xF4, 0x4C, 0x93, 0xE7,
    ];
    let mut reader = &data[..];
    let res = NotepadTabStat::from_reader(&mut reader).unwrap();
    let json = serde_json::to_string_pretty(&res).unwrap();
    println!("{}", json);
}

#[cfg(test)]
#[test]
fn error_test() {
    let data: [u8; 0xAF] = [
        0x41, 0x50, 0x00, 0x01, 0x18, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x69, 0x00,
        0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x54, 0x00, 0x65,
        0x00, 0x6D, 0x00, 0x70, 0x00, 0x5C, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00,
        0x2E, 0x00, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x20, 0x05, 0x01, 0xE1, 0x8F, 0xA1, 0xB4,
        0x8F, 0xBC, 0xBA, 0xED, 0x01, 0xC6, 0x0D, 0x8F, 0xFB, 0xD2, 0xFF, 0x96, 0x9A, 0x36, 0xBF,
        0xFC, 0xA3, 0x1F, 0x60, 0x9E, 0x80, 0x1E, 0x8E, 0x0B, 0x8D, 0xE4, 0x15, 0x68, 0xE9, 0x48,
        0xDB, 0xEB, 0xAC, 0x1B, 0xD9, 0xB2, 0xE4, 0x00, 0x01, 0x1F, 0x1F, 0x01, 0x00, 0x00, 0x02,
        0x01, 0x01, 0x1F, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x20, 0x00, 0x73, 0x00,
        0x61, 0x00, 0x76, 0x00, 0x65, 0x00, 0x64, 0x00, 0x20, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73,
        0x00, 0x74, 0x00, 0x0D, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x20, 0x00,
        0x73, 0x00, 0x61, 0x00, 0x76, 0x00, 0x65, 0x00, 0x64, 0x00, 0x20, 0x00, 0x74, 0x00, 0x65,
        0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0xF4, 0x4C, 0x93, 0xE7,
    ];
    let mut reader = &data[..];
    match NotepadTabStat::from_reader(&mut reader) {
        Ok(_) => panic!("You shouldn't see this!"),
        Err(e) => println!("{}", e),
    }
}

#[cfg(test)]
#[test]
fn tabstat_unsaved_chunks() {
    // Addition at random positions
    let data: [u8; 0x12A] = [
        0x1F, 0x00, 0x01, 0x0D, 0x00, 0x90, 0xFE, 0xE3, 0x34, 0x20, 0x00, 0x01, 0x74, 0x00, 0x4D,
        0x72, 0x0E, 0xDC, 0x21, 0x00, 0x01, 0x68, 0x00, 0x96, 0x65, 0x7A, 0x31, 0x22, 0x00, 0x01,
        0x69, 0x00, 0xC8, 0xDE, 0x31, 0xA0, 0x23, 0x00, 0x01, 0x73, 0x00, 0x45, 0x93, 0xE2, 0xCB,
        0x24, 0x00, 0x01, 0x20, 0x00, 0x66, 0x25, 0x30, 0x4C, 0x25, 0x00, 0x01, 0x61, 0x00, 0xB2,
        0x27, 0x67, 0xB8, 0x26, 0x00, 0x01, 0x20, 0x00, 0x1C, 0xE5, 0x63, 0x2C, 0x26, 0x01, 0x00,
        0xDA, 0x9A, 0xD2, 0x01, 0x25, 0x01, 0x00, 0xD8, 0xDC, 0x6C, 0x58, 0x25, 0x00, 0x01, 0x69,
        0x00, 0x7A, 0xFE, 0xED, 0xB0, 0x26, 0x00, 0x01, 0x73, 0x00, 0x8D, 0x73, 0x6D, 0xBB, 0x27,
        0x00, 0x01, 0x20, 0x00, 0x21, 0x85, 0x4A, 0x9C, 0x28, 0x00, 0x01, 0x75, 0x00, 0x64, 0x19,
        0x74, 0x5C, 0x29, 0x00, 0x01, 0x6E, 0x00, 0xF0, 0x4F, 0x96, 0x76, 0x2A, 0x00, 0x01, 0x73,
        0x00, 0x48, 0x83, 0x80, 0xBA, 0x2B, 0x00, 0x01, 0x61, 0x00, 0x0D, 0x17, 0xD9, 0xD9, 0x2C,
        0x00, 0x01, 0x76, 0x00, 0xBA, 0xB4, 0x81, 0x5F, 0x2D, 0x00, 0x01, 0x65, 0x00, 0xE6, 0x3B,
        0xE9, 0x7D, 0x2E, 0x00, 0x01, 0x64, 0x00, 0xB8, 0x80, 0xA2, 0xEC, 0x16, 0x01, 0x00, 0xFE,
        0xF1, 0x37, 0x91, 0x01, 0x01, 0x00, 0xE7, 0x98, 0x82, 0x64, 0x1B, 0x00, 0x01, 0x61, 0x00,
        0xAC, 0x36, 0x61, 0x5F, 0x1C, 0x00, 0x01, 0x61, 0x00, 0x1E, 0x16, 0xBD, 0x4F, 0x1D, 0x00,
        0x01, 0x61, 0x00, 0x23, 0x76, 0x94, 0xFF, 0x1E, 0x00, 0x01, 0x62, 0x00, 0x4F, 0xFB, 0xBD,
        0xEC, 0x1F, 0x00, 0x01, 0x62, 0x00, 0x72, 0x9B, 0x94, 0x5C, 0x0C, 0x00, 0x01, 0x73, 0x00,
        0x06, 0x02, 0x5A, 0x1E, 0x0D, 0x00, 0x01, 0x73, 0x00, 0x3B, 0x62, 0x73, 0xAE, 0x0E, 0x00,
        0x01, 0x73, 0x00, 0x7C, 0xC2, 0x09, 0x7E, 0x14, 0x00, 0x01, 0x63, 0x00, 0x1C, 0x50, 0x94,
        0x0C, 0x15, 0x00, 0x01, 0x63, 0x00, 0x21, 0x30, 0xBD, 0xBC, 0x16, 0x00, 0x01, 0x63, 0x00,
        0x66, 0x90, 0xC7, 0x6C, 0x17, 0x00, 0x01, 0x63, 0x00, 0x5B, 0xF0, 0xEE, 0xDC,
    ];
    let mut reader = &data[..];
    let res = UnsavedChunks::from_reader(&mut reader).unwrap();
    let json = serde_json::to_string_pretty(&res).unwrap();
    // println!("{}", res);
    println!("{}", json);
}

// Start: English language tests

#[cfg(test)]
#[test]
fn tabstat_sample_saved_english_unsaved_mod() {
    let path = format!("./{}/saved/english/unsaved_mod/*.bin", SAMPLES_DIR_NAME);
    println!("AAAA");
    println!("{}", SAMPLES_DIR_NAME);
    for path in get_paths_from_glob(&path) {
        let data = NotepadTabStat::from_path(&path).unwrap();

        assert!(
            check_unsaved_chunks(&data),
            "Didn't extract unsaved data chunck. DATA: {:?}",
            data
        );
        assert!(
            check_is_saved(&data),
            "is_saved_file is reported to be unset, but it should be"
        );
    }
}

#[cfg(test)]
#[test]
fn tabstat_sample_saved_english_rtl_unset() {
    let path = format!("./{}/saved/english/rtl_unset/*.bin", SAMPLES_DIR_NAME);
    for path in get_paths_from_glob(&path) {
        let data = NotepadTabStat::from_path(&path).unwrap();
        assert!(
            !check_rtl(&data),
            "RTL is reported to be set, but it should't"
        );
        assert!(
            check_word_wrap(&data),
            "WordWrap is reported to be unset, but it should be"
        );
        assert!(
            check_is_saved(&data),
            "is_saved_file is reported to be unset, but it should be"
        );
    }
}

#[cfg(test)]
#[test]
fn tabstat_sample_saved_english_rtl_unset_big_file() {
    let path = format!(
        "./{}/saved/english/rtl_unset/big_file/*.bin",
        SAMPLES_DIR_NAME
    );
    for path in get_paths_from_glob(&path) {
        let data = NotepadTabStat::from_path(&path).unwrap();
        assert!(
            !check_rtl(&data),
            "RTL is reported to be set, but it should't"
        );
        assert!(
            check_word_wrap(&data),
            "WordWrap is reported to be unset, but it should be"
        );
        assert!(
            check_is_saved(&data),
            "is_saved_file is reported to be unset, but it should be"
        );
    }
}

#[cfg(test)]
#[test]
fn tabstat_sample_not_saved_english_rtl_unset() {
    let path = format!("./{}/not_saved/english/rtl_unset/*.bin", SAMPLES_DIR_NAME);
    for path in get_paths_from_glob(&path) {
        let data = NotepadTabStat::from_path(&path).unwrap();
        assert!(
            !check_rtl(&data),
            "RTL is reported to be set, but it should't"
        );
        assert!(
            !check_is_saved(&data),
            "is_saved_file is reported to be set, but it should't"
        );
        assert!(
            check_word_wrap(&data),
            "WordWrap is reported to be unset, but it should be"
        );
    }
}

// End: English language tests
// Start: Arabic language test

#[cfg(test)]
#[test]
fn tabstat_sample_not_saved_arabic_rtl_set() {
    let path = format!("./{}/not_saved/arabic/rtl_set/*.bin", SAMPLES_DIR_NAME);
    for path in get_paths_from_glob(&path) {
        let data = NotepadTabStat::from_path(&path).unwrap();
        // RTL is ignored here, it is set to `true` in notepad. but it is not writen to the tabstate file. Writen after closing the window?
        // assert!(
        //     check_rtl(&data),
        //     "RTL is reported to be set, but it should't"
        // );
        assert!(
            !check_is_saved(&data),
            "is_saved_file is reported to be set, but it should't"
        );
        assert!(
            check_word_wrap(&data),
            "WordWrap is reported to be unset, but it should be"
        );
    }
}

#[cfg(test)]
#[test]
fn tabstat_sample_saved_arabic_rtl_set() {
    let path = format!("./{}/saved/arabic/rtl_set/*.bin", SAMPLES_DIR_NAME);
    for path in get_paths_from_glob(&path) {
        let data = NotepadTabStat::from_path(&path).unwrap();
        // RTL is ignored here, it is set to `true` in notepad. but it is not writen to the tabstate file. Writen after closing the window?
        // assert!(
        //     check_rtl(&data),
        //     "RTL is reported to be set, but it should't"
        // );
        assert!(
            check_is_saved(&data),
            "is_saved_file is reported to be set, but it should't"
        );
        assert!(
            check_word_wrap(&data),
            "WordWrap is reported to be unset, but it should be"
        );
    }
}

#[cfg(test)]
#[test]
fn tabstat_sample_saved_arabic_rtl_set_big_file() {
    let path = format!("./{}/saved/arabic/rtl_set/big_file/*.bin", SAMPLES_DIR_NAME);
    for path in get_paths_from_glob(&path) {
        let data = NotepadTabStat::from_path(&path).unwrap();
        // RTL is ignored here, it is set to `true` in notepad. but it is not writen to the tabstate file. Writen after closing the window?
        // assert!(
        //     check_rtl(&data),
        //     "RTL is reported to be set, but it should't"
        // );
        assert!(
            check_is_saved(&data),
            "is_saved_file is reported to be set, but it should't"
        );
        assert!(
            check_word_wrap(&data),
            "WordWrap is reported to be unset, but it should be"
        );
    }
}

#[cfg(test)]
#[test]
fn tabstat_sample_saved_arabic_unsaved_mod() {
    let path = format!("./{}/saved/arabic/unsaved_mod/*.bin", SAMPLES_DIR_NAME);
    for path in get_paths_from_glob(&path) {
        let data = NotepadTabStat::from_path(&path).unwrap();
        let json = serde_json::to_string_pretty(&data).unwrap();
        println!("{}", json);
        // RTL is ignored here, it is set to `true` in notepad. but it is not writen to the tabstate file. Writen after closing the window?
        // assert!(
        //     check_rtl(&data),
        //     "RTL is reported to be set, but it should't"
        // );

        assert!(
            check_is_saved(&data),
            "is_saved_file is reported to be set, but it should't"
        );
        // Not updated if the window still open?
        // assert!(
        //     check_contain_unsaved_data(&data),
        //     "contain_unsaved_data is reported to be unset, but it should be"
        // );
        assert!(
            check_word_wrap(&data),
            "WordWrap is reported to be unset, but it should be"
        );
    }
}

// End: Arabic language test
```

## /src/traits.rs
```rs
use crate::errors::NotepadErrors;

pub trait ReadBool: std::io::Read {
    /// Read a `u8` and return `true` if it is `0x1` or `false` if it is `0x0`, otherwise return Error
    fn read_bool(&mut self) -> std::result::Result<bool, NotepadErrors>;
}

impl<T: std::io::Read> ReadBool for T {
    fn read_bool(&mut self) -> std::result::Result<bool, NotepadErrors> {
        let mut data = [0u8; 1];
        if let Err(e) = self.read_exact(&mut data) {
            return Err(NotepadErrors::ReadError(
                e.to_string(),
                "traits::ReadBool".to_string(),
            ));
        }
        match data[0] {
            0x0 => Ok(false),
            0x1 => Ok(true),
            x => Err(NotepadErrors::UnexpectedValue(
                "bool <0x0|0x1>".to_string(),
                format!("{}", x),
                "traits::ReadBool".to_string(),
            )),
        }
    }
}
```

## /src/unsaved_chunks.rs
```rs
use crate::NotepadErrors;
use serde::Serialize;
use std::{
    fmt::Display,
    io::{self, Read},
};
use winparsingtools::utils::{bytes_to_hex, read_uleb128, read_utf16_string};

#[derive(Debug, Serialize)]
pub struct UnsavedChunk {
    position: u64,
    num_of_deletion: u64,
    num_of_addition: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    checksum: String,
}

impl UnsavedChunk {
    pub fn from_reader<R: Read>(reader: &mut R) -> std::result::Result<Self, NotepadErrors> {
        // Read `position`. This is the cursor position where the data will be deleted from or added to
        let position = match read_uleb128(reader) {
            Ok(pos) => pos,
            Err(e) => match e.kind() {
                io::ErrorKind::UnexpectedEof => {
                    return Err(NotepadErrors::EoF);
                }
                _ => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "UnsavedChunk::position".to_string(),
                    ));
                }
            },
        };

        // Read `num_of_deletion`. This is the number of characters to delete.
        let num_of_deletion = match read_uleb128(reader) {
            Ok(num_of_deletion) => num_of_deletion,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "UnsavedChunk::num_of_deletion".to_string(),
                ));
            }
        };

        // Read `num_of_addition`. This is the number of characters to add.
        let num_of_addition = match read_uleb128(reader) {
            Ok(num_of_addition) => num_of_addition,
            Err(e) => {
                return Err(NotepadErrors::ReadError(
                    e.to_string(),
                    "UnsavedChunk::num_of_addition".to_string(),
                ));
            }
        };

        // Read `data` if it is an addition
        let data = match num_of_addition {
            0 => Option::None,
            _ => match read_utf16_string(reader, Option::Some(num_of_addition as usize)) {
                Ok(data) => Option::Some(data),
                Err(e) => {
                    return Err(NotepadErrors::ReadError(
                        e.to_string(),
                        "UnsavedChunk::data".to_string(),
                    ));
                }
            },
        };

        let mut checksum = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut checksum) {
            return Err(NotepadErrors::ReadError(
                e.to_string(),
                "checksum".to_string(),
            ));
        }

        Ok(Self {
            position,
            num_of_deletion,
            num_of_addition,
            data,
            checksum: bytes_to_hex(&checksum.to_vec()),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct UnsavedChunks(Vec<UnsavedChunk>);

impl UnsavedChunks {
    pub fn from_reader<R: Read>(reader: &mut R) -> std::result::Result<Self, NotepadErrors> {
        let mut unsaved_chunks: Vec<UnsavedChunk> = vec![];

        loop {
            match UnsavedChunk::from_reader(reader) {
                Ok(chunk) => unsaved_chunks.push(chunk),
                Err(e) => match e {
                    NotepadErrors::EoF => break,
                    e => {
                        return Err(NotepadErrors::Generic(
                            e.to_string(),
                            "UnsavedChunks::from_reader".to_string(),
                            "Error during reading list of UnsavedChunk.".to_string(),
                        ));
                    }
                },
            }
        }

        if unsaved_chunks.len() > 0 {
            Ok(Self(unsaved_chunks))
        } else {
            return Err(NotepadErrors::NA);
        }
    }
}

impl Display for UnsavedChunks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut previous_addition = 0;
        let data = self
            .0
            .iter()
            .map(|x| {
                let mut chunk = String::from("");
                if x.num_of_addition > 0 {
                    if previous_addition == 0 {
                        previous_addition = x.position;
                        chunk.push_str(&format!("[{}]:{}", x.position, &x.data.clone().unwrap()));
                    } else if x.position == (previous_addition + 1) {
                        chunk.push_str(&x.data.clone().unwrap());
                        previous_addition = x.position;
                    } else {
                        chunk.push_str(&format!(",[{}]:{}", x.position, &x.data.clone().unwrap()));
                        previous_addition = x.position;
                    }
                } else {
                    if previous_addition > 0 {
                        previous_addition = previous_addition - 1;
                    }
                    chunk.push_str(&format!("<DEL:{}>", x.position));
                }
                format!("{}", chunk)
            })
            .collect::<Vec<String>>()
            .join("");

        write!(f, "{}", data)
    }
}
```