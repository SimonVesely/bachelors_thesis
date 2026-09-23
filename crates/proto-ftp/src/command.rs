#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    User(String),
    Pass(String),
    Quit,
    Pwd,
    Cwd(String),
    Cdup,
    Type(String),
    Pasv,
    Port(String),
    List(Option<String>),
    Nlst(Option<String>),
    Mlsd(Option<String>),
    Mlst(Option<String>),
    Retr(String),
    Stor(String),
    Appe(String),
    Dele(String),
    Mkd(String),
    Rmd(String),
    Rnfr(String),
    Rnto(String),
    Size(String),
    Mdtm(String),
    Rest(u64),
    Feat,
    Opts(String),
    Syst,
    Noop,
    Help,
    Abor,
    Auth(String),
    Pbsz(String),
    Prot(String),
    Host(String),
    Unknown(String),
}

impl Command {
    pub fn parse(line: &str) -> Self {
        let line = line.trim_end_matches(['\r', '\n']);
        let mut parts = line.splitn(2, ' ');
        let verb = parts.next().unwrap_or_default().to_ascii_uppercase();
        let arg = parts.next().unwrap_or_default().trim().to_string();

        match verb.as_str() {
            "USER" => Command::User(arg),
            "PASS" => Command::Pass(arg),
            "QUIT" => Command::Quit,
            "PWD" | "XPWD" => Command::Pwd,
            "CWD" | "XCWD" => Command::Cwd(arg),
            "CDUP" | "XCUP" => Command::Cdup,
            "TYPE" => Command::Type(arg),
            "PASV" => Command::Pasv,
            "PORT" => Command::Port(arg),
            "LIST" => Command::List(non_empty(arg)),
            "NLST" => Command::Nlst(non_empty(arg)),
            "MLSD" => Command::Mlsd(non_empty(arg)),
            "MLST" => Command::Mlst(non_empty(arg)),
            "RETR" => Command::Retr(arg),
            "STOR" => Command::Stor(arg),
            "APPE" => Command::Appe(arg),
            "DELE" => Command::Dele(arg),
            "MKD" | "XMKD" => Command::Mkd(arg),
            "RMD" | "XRMD" => Command::Rmd(arg),
            "RNFR" => Command::Rnfr(arg),
            "RNTO" => Command::Rnto(arg),
            "SIZE" => Command::Size(arg),
            "MDTM" => Command::Mdtm(arg),
            "REST" => Command::Rest(arg.parse().unwrap_or(0)),
            "FEAT" => Command::Feat,
            "OPTS" => Command::Opts(arg),
            "SYST" => Command::Syst,
            "NOOP" => Command::Noop,
            "HELP" => Command::Help,
            "ABOR" => Command::Abor,
            "AUTH" => Command::Auth(arg),
            "PBSZ" => Command::Pbsz(arg),
            "PROT" => Command::Prot(arg),
            "HOST" => Command::Host(arg),
            other => Command::Unknown(other.to_string()),
        }
    }
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}
