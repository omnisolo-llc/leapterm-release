//! An inert official-client stand-in for owned localhost HTTP protocol tests.
//! This binary is never a workflow runtime dependency.
use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
};

fn main() {
    if let Err(()) = run() {
        std::process::exit(1);
    }
}
fn run() -> Result<(), ()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("api") {
        return Err(());
    }
    let mut method = "GET".to_owned();
    let mut endpoint = None;
    let mut body = Vec::new();
    let mut accept = "application/vnd.github+json".to_owned();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--hostname" => {
                i += 1;
                if args.get(i).map(String::as_str) != Some("github.com") {
                    return Err(());
                }
            }
            "--method" => {
                i += 1;
                method = args.get(i).ok_or(())?.clone();
            }
            "--input" => {
                i += 1;
                body = fs::read(args.get(i).ok_or(())?).map_err(|_| ())?;
            }
            "--header" => {
                i += 1;
                if let Some(value) = args.get(i).ok_or(())?.strip_prefix("Accept: ") {
                    accept = value.into();
                }
            }
            value if !value.starts_with('-') && endpoint.is_none() => {
                endpoint = Some(value.to_owned())
            }
            _ => return Err(()),
        }
        i += 1;
    }
    let endpoint = endpoint.ok_or(())?;
    let path = endpoint
        .strip_prefix("https://uploads.github.com/")
        .unwrap_or(&endpoint);
    if path.contains(['\r', '\n', ' ']) {
        return Err(());
    }
    let address = fs::read_to_string(
        std::env::current_exe()
            .map_err(|_| ())?
            .parent()
            .ok_or(())?
            .join("fixture-address"),
    )
    .map_err(|_| ())?;
    let mut stream = TcpStream::connect(address.trim()).map_err(|_| ())?;
    let token = std::env::var("GH_TOKEN").map_err(|_| ())?;
    write!(stream, "{method} /{path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nAccept: {accept}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).map_err(|_| ())?;
    stream.write_all(&body).map_err(|_| ())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|_| ())?;
    let end = response
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or(())?;
    if !response.starts_with(b"HTTP/1.1 200 ")
        && !response.starts_with(b"HTTP/1.1 201 ")
        && !response.starts_with(b"HTTP/1.1 204 ")
    {
        return Err(());
    }
    std::io::stdout()
        .write_all(&response[end + 4..])
        .map_err(|_| ())
}
