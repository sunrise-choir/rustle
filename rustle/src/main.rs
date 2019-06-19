#![feature(async_await)]

#![allow(unused_imports)]

use std::io::{self, BufRead, BufReader, Read};
use std::fs::File;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{decode_config_slice, STANDARD};
use clap::{Arg, App, SubCommand};

use futures::StreamExt;
use futures::executor::{self, ThreadPool};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::prelude::*;
use futures::sink::SinkExt;

use futures::task::{SpawnExt};
use romio::{TcpListener, TcpStream};

#[macro_use] extern crate serde_json;
#[macro_use] extern crate serde_derive;

use serde_json::json;

use ssb_crypto::{NetworkKey, PublicKey, SecretKey};
use ssb_handshake::client;
use ssb_boxstream::BoxStream;
use ssb_packetstream::*;

#[derive(Debug, Deserialize)]
struct SecretFile {
    public: String,
    private: String,
}

fn ms_since_1970() -> u128 {
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    since_epoch.as_millis()
}

fn log_packet(p: &Packet) {
    let s = str::from_utf8(&p.body).unwrap();
    eprintln!("In: {} strm:{:?} end:{:?} {:?} {}",
              p.id, p.is_stream, p.is_end, p.body_type, s);
}

fn decode_b64_key(s: &str) -> Vec<u8> {
    base64::decode_config(s.trim_end_matches(".ed25519"), base64::STANDARD).unwrap()
}

fn load_keys_from_path(path: &str) -> io::Result<(PublicKey, SecretKey)> {
    let f = BufReader::new(File::open(path)?);

    let sec_str = f.lines()
        .filter_map(|s| s.ok())
        .filter(|s| !s.starts_with('#'))
        .collect::<Vec<String>>().concat();

    let v = serde_json::from_str::<serde_json::Value>(&sec_str)?;
    dbg!(v);

    let sec = serde_json::from_str::<SecretFile>(&sec_str)?;

    dbg!(&sec);

    let p = PublicKey::from_slice(&decode_b64_key(&sec.public)).unwrap();
    let s = SecretKey::from_slice(&decode_b64_key(&sec.private)).unwrap();

    Ok((p, s))
}


fn main() -> io::Result<()> {
    let app_m = App::new("rustle")
        .version("0.1")
        .author("Sunrise Choir (sunrisechoir.com)")
        .about("")
        .arg(Arg::with_name("secret")
             .long("secret-file")
             .short("s")
             .required(true)
             .takes_value(true)
             .help("ssb secret (key) file"))
        .subcommand(SubCommand::with_name("getfeed")
                    .about("Send createHistoryStream request")
                    .arg(Arg::with_name("addr")
                         .long("addr")
                         .short("a")
                         .takes_value(true)
                         .default_value("127.0.0.1:8008")
                         .help("ip:port of peer"))
                    .arg(Arg::with_name("key")
                         .long("key")
                         .short("k")
                         .required(true)
                         .takes_value(true)
                         .help("base64-encoded public key of peer"))
                    .arg(Arg::with_name("feed")
                         .long("feed")
                         .short("f")
                         .required(true)
                         .takes_value(true)
                         .help("feed (user) id (eg. \"@N/vWpVVdD...\""))
                    .arg(Arg::with_name("limit")
                         .long("limit")
                         .short("n")
                         .takes_value(true)
                         .help(""))
        )
        .get_matches();

    match app_m.subcommand() {
        ("getfeed", Some(sub_m)) => {
            let secret_path = app_m.value_of("secret").unwrap();
            let feed_id = sub_m.value_of("feed").unwrap();
            let peer_key = sub_m.value_of("key").unwrap();
            let peer_addr = sub_m.value_of("addr").unwrap();

            let (pk, sk) = load_keys_from_path(&secret_path)?;

            let net_id = NetworkKey::SSB_MAIN_NET;

            // let key = "/1OZ3fUmzKcaKyuyw5ffFHcpStayDTco9zMN7R1ZE84=";
            // let addr = "134.209.164.64:8008";
            // let key = "Kpfvv1sVbLxx+u60qz57hIL6lvjs0/ICt0RNoNW835A=";
            // let addr = "127.0.0.1:9009";
            // let key = "U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=";
            // let addr = "127.0.0.1:8008";

            let server_pk = PublicKey::from_slice(&base64::decode(peer_key).unwrap()).unwrap();

            executor::block_on(async {
                let mut tcp = TcpStream::connect(&peer_addr.parse().unwrap()).await?;

                let o = client(&mut tcp, net_id, pk, sk, server_pk).await.unwrap();
                dbg!("client connected");

                // dbg!(o.c2s_key.as_slice());

                let (tcp_r, tcp_w) = tcp.split();

                let (box_r, box_w) = BoxStream::client_side(tcp_r, tcp_w, o).split();
                let pstream = PacketStream::new(box_r);
                let mut psink = PacketSink::new(box_w);

                let msg = serde_json::to_vec(&json!({
                    "name": ["createHistoryStream"],
                    "args": [{
                        "id": feed_id,
                        "limit": 10
                    }],
                    "type":"source"}))?;

                psink.send(Packet::new(IsStream::Yes, IsEnd::No, BodyType::Json, 1, msg)).await?;

                let done = pstream.for_each(|r| {
                    match r {
                        Ok(p) => {
                            log_packet(&p);
                        },
                        Err(e) => eprintln!("PacketStream error: {}", e),
                    };
                    future::ready(())
                });
                done.await;

                Ok(())
            })
        },

        _ => {
            println!("{}", app_m.usage());
            Ok(())
        }
    }

}
