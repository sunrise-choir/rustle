#![feature(async_await)]

#![allow(unused_imports)]

use std::io::{self, BufRead, BufReader, Read};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{decode_config_slice, STANDARD};
use clap::{Arg, App, SubCommand};

use flumedb::flume_log::{self, FlumeLog};
use flumedb::offset_log::{BidirIterator, OffsetLog, LogEntry};

use futures::StreamExt;
use futures::executor::{self, block_on, LocalPool, ThreadPool};
use futures::future::join;
use futures::task::LocalSpawnExt;
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
use ssb_packetstream::{mux, Packet, BodyType};
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to load secret file: {}", source))]
    ReadSecretFile { source: std::io::Error },

    // TODO: more context
    #[snafu(display("Failed to connect to remote host: {}", source))]
    TcpConnection { source: std::io::Error },

    #[snafu(display("Mux error: {}", source))]
    Mux { source: mux::SubError },

    #[snafu(display("Flume error: {}", source))]
    FlumeIo { source: std::io::Error },

}

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
              p.id, p.is_stream(), p.is_end(), p.body_type, s);
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

    // let v = serde_json::from_str::<serde_json::Value>(&sec_str)?;
    let sec = serde_json::from_str::<SecretFile>(&sec_str)?;

    let p = PublicKey::from_slice(&decode_b64_key(&sec.public)).unwrap();
    let s = SecretKey::from_slice(&decode_b64_key(&sec.private)).unwrap();

    Ok((p, s))
}

async fn bumrpc(p: Packet, _out: mux::SubSender, _inn: Option<mux::SubReceiver>)
                -> Result<(), Error> {
    log_packet(&p);
    Ok(())
}

fn create_hist_stream_msg(feed_id: &str, start: u32, limit: u32) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "name": ["createHistoryStream"],
        "args": [{
            "id": feed_id,
            "seq": start,
            "limit": limit,
            "live": false,
        }],
        "type":"source"})).unwrap()
}

fn temp_path() -> String {
    let p: PathBuf = ["/tmp", &Uuid::new_v4().to_string()].iter().collect();
    p.into_os_string().into_string().unwrap()
}

fn main() -> Result<(), Error> {

    let default_out_path = temp_path();

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
                    .arg(Arg::with_name("seq")
                         .long("seq")
                         .short("q")
                         .takes_value(true)
                         .default_value("0")
                         .help(""))
                    .arg(Arg::with_name("limit")
                         .long("limit")
                         .short("n")
                         .takes_value(true)
                         .default_value("10")
                         .help(""))
                    .arg(Arg::with_name("out")
                         .long("out")
                         .short("o")
                         .takes_value(true)
                         .default_value(&default_out_path)
                         .help(""))
                    .arg(Arg::with_name("overwrite")
                         .long("overwrite")
                         .help("Overwrite output file, if it exists."))
        )
        .get_matches();

    match app_m.subcommand() {
        ("getfeed", Some(sub_m)) => {
            let secret_path = app_m.value_of("secret").unwrap();
            let feed_id = sub_m.value_of("feed").unwrap();
            let feed_seq = u32::from_str_radix(sub_m.value_of("seq").unwrap(), 10).unwrap();
            let feed_limit = u32::from_str_radix(sub_m.value_of("limit").unwrap(), 10).unwrap();

            let peer_key = sub_m.value_of("key").unwrap();
            let peer_addr = sub_m.value_of("addr").unwrap();
            let out_path = sub_m.value_of("out").unwrap();
            let overwrite = sub_m.is_present("overwrite");

            if !overwrite && Path::new(out_path).exists() {
                eprintln!("Output path `{}` exists.", out_path);
                eprintln!("Use `--overwrite` option to overwrite.");
                return Ok(());
            }

            eprintln!("Writing to log: {}", out_path);

            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&out_path).context(FlumeIo)?;

            let mut out_log = OffsetLog::<u32>::from_file(file).unwrap();

            let (pk, sk) = load_keys_from_path(&secret_path).context(ReadSecretFile)?;

            let net_id = NetworkKey::SSB_MAIN_NET;

            // ./rustle --secret-file ~/.testnet/secret getfeed --feed "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519" --addr "134.209.164.64:8008" --key "/1OZ3fUmzKcaKyuyw5ffFHcpStayDTco9zMN7R1ZE84="

            // let key = "U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=";
            // let addr = "127.0.0.1:8008";

            let server_pk = PublicKey::from_slice(&base64::decode(peer_key).unwrap()).unwrap();
            let (box_r, box_w) = block_on(async {
                let mut tcp = TcpStream::connect(&peer_addr.parse().unwrap()).await.context(TcpConnection)?;
                let o = client(&mut tcp, net_id, pk, sk, server_pk).await.unwrap();

                let (tcp_r, tcp_w) = tcp.split();
                Ok(BoxStream::client_side(tcp_r, tcp_w, o).split())
            })?;
            eprintln!("client connected");

            let msg1 = create_hist_stream_msg(feed_id, feed_seq, feed_limit);

            let mut pool = LocalPool::new();
            let mut spawner = pool.spawner();

            let (mut out, done) = mux::mux(box_r, box_w, bumrpc);
            let done = spawner.spawn_local_with_handle(done).unwrap();

            let r1 = spawner.spawn_local_with_handle(async move {
                let (mut a_out, a_in) = out.send_duplex(BodyType::Json, msg1).await?;
                a_in.for_each(|p| {
                    // log_packet(&p);
                    out_log.append(&p.body).unwrap();
                    future::ready(())
                }).await;
                a_out.send_end(BodyType::Json, "true".bytes().collect()).await
            }).unwrap();

            let _r = spawner.spawn_local_with_handle(r1).unwrap();
            pool.run_until(done).unwrap();

            Ok(())
        },

        _ => {
            // println!("{}", app_m.usage());
            Ok(())
        }
    }

}
