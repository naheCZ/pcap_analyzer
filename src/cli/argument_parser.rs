use clap::{Args, Parser, ValueEnum};
use regex::Regex;
use std::fmt;
use std::net::IpAddr;
use std::ops::RangeInclusive;

#[derive(Clone, Debug, PartialEq, ValueEnum)]
#[clap(rename_all = "lower")]
pub enum FilterType {
    MAC,
    IPv4,
    IPv6,
    TCP,
    UDP,
}

impl fmt::Display for FilterType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Args)]
#[group(required = true, multiple = true)]
pub struct SrcDstGroup {
    #[clap(short, long)]
    pub source: bool,
    #[clap(short, long)]
    pub dst: bool,
}

#[derive(Debug, Parser)]
pub struct Filter {
    #[arg(short, long)]
    pub filter_type: FilterType,
    #[arg[short, long]]
    pub value: String,
}

impl Filter {
    fn validate(&self) -> Result<(), String> {
        match self.filter_type {
            FilterType::MAC => self.check_mac(),
            FilterType::IPv4 | FilterType::IPv6 => self.check_ip(),
            FilterType::TCP | FilterType::UDP => self.check_port(),
        }
    }

    fn check_mac(&self) -> Result<(), String> {
        let re = Regex::new(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$").unwrap();
        if re.is_match(&self.value) {
            Ok(())
        } else {
            Err(String::from("Invalid MAC address"))
        }
    }

    fn check_ip(&self) -> Result<(), String> {
        match self.value.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) | Ok(IpAddr::V6(_)) => Ok(()),
            Err(_) => Err(String::from("Invalid IP address")),
        }
    }

    fn check_port(&self) -> Result<(), String> {
        const PORT_RANGE: RangeInclusive<usize> = 1..=65535;
        let port: usize = self
            .value
            .parse()
            .map_err(|_| format!("`{}` is not a port number!", self.value))?;

        if PORT_RANGE.contains(&port) {
            Ok(())
        } else {
            Err(format!(
                "port not in range {}-{}",
                PORT_RANGE.start(),
                PORT_RANGE.end()
            ))
        }
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct CliArguments {
    #[arg(short = 'i', long)]
    pub file: std::path::PathBuf,
    #[clap(flatten)]
    pub filter: Filter,
    #[clap(flatten)]
    pub direction: SrcDstGroup,
}

pub fn parse_args() -> Result<CliArguments, String> {
    let args = CliArguments::parse();
    match args.filter.validate() {
        Ok(()) => {
            if !args.file.is_file() {
                return Err(String::from("Given file path is not file"));
            }
            Ok(args)
        }
        Err(e) => Err(e),
    }
}
