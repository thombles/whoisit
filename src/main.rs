//! whoisit
//!
//! An identd implementation for Linux, built as an excuse to play with async/await.
//! It cheats somewhat by relying on `lsof` to locate the user who owns a given
//! connection.
//!
//! On the bright side, it should be compliant with RFC 1413 and it supports queries
//! from both IPv4 and IPv6 remote hosts.

use futures::{SinkExt, StreamExt};
use tokio::codec::{Framed, LinesCodec};
use tokio::net::process::Command;
use tokio::net::{TcpListener, TcpStream};

use std::error::Error;
use std::fmt;
use std::io::{BufRead, BufReader, Cursor};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let binding = ":::113";
    let mut listener = TcpListener::bind(&binding).await?;

    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = handle_client(socket).await;
        });
    }
}

async fn handle_client(socket: TcpStream) -> Result<(), Box<dyn Error + Send + Sync>> {
    let remote_ip = socket.peer_addr()?.ip();
    let mut client = Framed::new(socket, LinesCodec::new_with_max_length(1024));

    // Read one line of query
    // LinesCodec will accept either the required \r\n or a plain \n
    let query = match client.next().await {
        Some(Ok(q)) => q,
        _ => return Err(IdentError::NoQuery.into()),
    };

    // Parse the requested source and destination ports
    // Local = on the host running this identd
    let (local_port, remote_port) = match parse_query(&query) {
        Ok((l, p)) => (l, p),
        Err(e) => {
            let response = format!("{} : ERROR : INVALID-PORT\r", query);
            client.send(response).await?;
            return Err(e);
        }
    };

    // Use lsof to get all connections to that remote host and port
    let lsof_output = run_lsof(remote_port, remote_ip).await?;

    // Search within that for a user connecting from the specified local port
    match search_for_port(local_port, lsof_output) {
        Some(user) => {
            let response = format!("{} : USERID : UNIX : {}\r", query, user);
            client.send(response).await?;
        }
        None => {
            let response = format!("{} : ERROR : NO-USER\r", query);
            client.send(response).await?;
        }
    };
    Ok(())
}

/// Parse two comma-separated port numbers, ignoring whitespace
fn parse_query(query: &str) -> Result<(u16, u16), Box<dyn Error + Send + Sync>> {
    let ports: Vec<&str> = query.split(",").map(|s| s.trim()).collect();
    if ports.len() != 2 {
        return Err(IdentError::InvalidPort.into());
    }
    Ok((ports[0].parse()?, ports[1].parse()?))
}

/// Invoke `lsof` to find all connections to a host/port combination and return stdout
async fn run_lsof(remote_port: u16, remote_host: IpAddr) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Since we bind to IPv6, realistically `remote_host` will be either v6 or ipv6-mapped-v4
    // Use whatever address family the client used to contact the identd
    let lsof_target_arg = match remote_host {
        IpAddr::V4(ip) => format!("4TCP@{}:{}", ip, remote_port),
        IpAddr::V6(ip) => {
            match ip.to_ipv4() {
                Some(v4) if ip.segments()[0..6] == [0, 0, 0, 0, 0, 0xffff] => {
                    format!("4TCP@{}:{}", v4, remote_port)
                },
                _ => format!("6TCP@[{}]:{}", ip, remote_port)
            }
        }
    };
    Ok(Command::new("lsof")
        .arg("-i")
        .arg(lsof_target_arg)
        .arg("-F")
        .arg("Ln")
        .arg("-n")
        .output()
        .await?
        .stdout)
}

/// Parse `lsof` output and search for the given local port. If found, return the corresponding username.
fn search_for_port(local_port: u16, lsof_output: Vec<u8>) -> Option<String> {
    let mut reader = BufReader::new(Cursor::new(lsof_output));
    let mut current_user: Option<String> = None;
    let mut matching_user: Option<String> = None;
    let target = format!(":{}->", local_port);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(n) if n > 0 => (),
            _ => break,
        };
        let first = line.chars().next();
        match first {
            Some('L') => {
                current_user = Some(line[1..].trim().to_owned());
            }
            Some('n') => {
                if line.contains(&target) {
                    matching_user = current_user;
                    break;
                }
            }
            _ => (),
        };
    }
    matching_user
}

#[derive(Debug)]
enum IdentError {
    NoQuery,
    InvalidPort,
}

impl Error for IdentError {
    fn description(&self) -> &str {
        match *self {
            IdentError::NoQuery => "no query received from client",
            IdentError::InvalidPort => "invalid port specification in query",
        }
    }
}

impl fmt::Display for IdentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}
