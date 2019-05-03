#![feature(async_await, await_macro, futures_api)]

#![allow(unused_imports)]

use std::io::{self, BufRead, BufReader, Read};
use std::fs::File;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{decode_config_slice, STANDARD};
use clap::{Arg, App};

use futures::StreamExt;
use futures::executor::{self, ThreadPool};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::prelude::*;
use futures::sink::SinkExt;

use futures::task::{SpawnExt};
use romio::{TcpListener, TcpStream};

extern crate serde_json;
#[macro_use] extern crate serde_derive;

use ssb_crypto::{NetworkKey, PublicKey, SecretKey};
use shs_async::client;
use boxstream::BoxStream;
use packetstream::*;

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
        .get_matches();

    let secret_path = app_m.value_of("secret").unwrap();
    let (pk, sk) = load_keys_from_path(&secret_path)?;

    let net_id = NetworkKey::SSB_MAIN_NET;

    //let key = "/1OZ3fUmzKcaKyuyw5ffFHcpStayDTco9zMN7R1ZE84=";
    //let addr = "134.209.164.64:8008";
    // let key = "Kpfvv1sVbLxx+u60qz57hIL6lvjs0/ICt0RNoNW835A=";
    // let addr = "127.0.0.1:9009";
    let key = "U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=";
    let addr = "127.0.0.1:8008";

    let server_pk = PublicKey::from_slice(&base64::decode(key).unwrap()).unwrap();

    executor::block_on(async {
        let mut tcp = await!(TcpStream::connect(&addr.parse().unwrap()))?;

        let o = await!(client(&mut tcp, net_id, pk, sk, server_pk)).unwrap();
        dbg!("client connected");

        // dbg!(o.c2s_key.as_slice());

        let (tcp_r, tcp_w) = tcp.split();

        let (box_r, box_w) = BoxStream::client_side(tcp_r, tcp_w, o).split();
        let mut pstream = PacketStream::new(box_r);
        let mut psink = PacketSink::new(box_w);

        await!(psink.send(Packet::new(IsStream::Yes, IsEnd::No, BodyType::Json, 1, r#"{"name":["createUserStream"],"args": [{"id": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519", "limit": 10}], "type":"source"}"#.into())));

        let done = pstream.for_each(|r| {
            match r {
                Ok(p) => {
                    log_packet(&p);
                    eprintln!("{:?}", p.id);

                    let s = str::from_utf8(&p.body).unwrap();
                    if s.contains("createWants") {
                         psink.send(Packet::new(IsStream::Yes, IsEnd::No, BodyType::Json, -p.id, "{}".into()))
                             .map(|result| println!("{:?}", result));
                    }
                    // } else {
                    //     future::ready(())
                    // }
                },
                Err(e) => eprintln!("PacketStream error: {}", e),
            };
            future::ready(())
        });
        await!(done);

        // let m = "{ name: [ 'gossip', 'ping' ], args: [ { timeout: 300000 } ], type: 'duplex' }";
        // await!(psink.send(Packet::new(IsStream::Yes, IsEnd::No, BodyType::Json, 2, m.into()))).unwrap();

        // let m = format!("{}", ms_since_1970());
        // await!(psink.send(Packet::new(IsStream::No, IsEnd::No, BodyType::Json, 2, m.into()))).unwrap();

        // let p = await!(pstream.next()).unwrap()?;
        // log_packet(&p);

        // await!(psink.send(Packet::new(IsStream::Yes, IsEnd::Yes, BodyType::Json, -p.id,
        //                               "true".into()))).unwrap();


        Ok(())
    })
}
