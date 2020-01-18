use std::convert::TryInto;
use std::path::PathBuf;
use std::str;

use clap::{App, Arg, SubCommand};

use futures::executor::{block_on, LocalPool};
use futures::io::AsyncReadExt;
use futures::task::LocalSpawnExt;
use futures::StreamExt;

use async_std::net::TcpStream;

extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use serde_json::json;
use serde_json::Value;

use snafu::{ResultExt, Snafu};
use ssb_boxstream::BoxStream;
use ssb_crypto::{NetworkKey, PublicKey};
use ssb_db::{SqliteSsbDb, SsbDb};
use ssb_handshake::client;
use ssb_keyfile::load_keys_from_path;
use ssb_multiformats::multikey::Multikey;
use ssb_packetstream::{mux, BodyType};
use ssb_publish::{publish, Content};
use ssb_validate::{par_validate_message_hash_chain_of_feed, validate_message_hash_chain};
use ssb_verify_signatures::{par_verify_messages, verify_message};
use uuid::Uuid;

mod rpc;
use crate::rpc::*;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to load secret file: {}", source))]
    ReadSecretFile { source: ssb_keyfile::Error },

    // TODO: more context
    #[snafu(display("Failed to connect to remote host: {}", source))]
    TcpConnection { source: std::io::Error },

    #[snafu(display("Mux send error: {}", source))]
    Mux { source: mux::SendError },

    #[snafu(display("Flume error: {}", source))]
    FlumeIo { source: std::io::Error },
}

fn create_hist_stream_msg(feed_id: &str, start: u32, limit: Option<u32>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "name": ["createHistoryStream"],
        "args": [{
            "id": feed_id,
            "seq": start,
            "limit": limit,
            "live": false,
            "keys": true,
            "values": true
        }],
        "type":"source"}))
    .unwrap()
}

fn temp_path() -> String {
    let p: PathBuf = ["/tmp", &Uuid::new_v4().to_string()].iter().collect();
    p.into_os_string().into_string().unwrap()
}

fn main() -> Result<(), Error> {
    let _default_out_path = temp_path();

    let app_m = App::new("rustle")
        .version("0.1")
        .author("Sunrise Choir (sunrisechoir.com)")
        .about("")
        .arg(
            Arg::with_name("secret")
                .long("secret-file")
                .short("s")
                .required(true)
                .takes_value(true)
                .help("ssb secret (key) file"),
        )
        .subcommand(
            SubCommand::with_name("handleReplicationRequests")
                .about("Connect to a server and handle any replication requests it makes")
                .arg(
                    Arg::with_name("addr")
                        .long("addr")
                        .short("a")
                        .takes_value(true)
                        .default_value("127.0.0.1:8008")
                        .help("ip:port of peer"),
                )
                .arg(
                    Arg::with_name("key")
                        .long("key")
                        .short("k")
                        .required(true)
                        .takes_value(true)
                        .help("base64-encoded public key of peer"),
                )
                .arg(
                    Arg::with_name("offsetpath")
                        .long("offsetpath")
                        .short("o")
                        .required(true)
                        .takes_value(true)
                        .help("path to ssb_db offset file"),
                )
                .arg(
                    Arg::with_name("dbpath")
                        .long("dbpath")
                        .short("db")
                        .required(true)
                        .takes_value(true)
                        .help("path to ssb_db sqlite file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("replicatefeed")
                .about("Replicate a feed into a ssb_db")
                .arg(
                    Arg::with_name("addr")
                        .long("addr")
                        .short("a")
                        .takes_value(true)
                        .default_value("127.0.0.1:8008")
                        .help("ip:port of peer"),
                )
                .arg(
                    Arg::with_name("key")
                        .long("key")
                        .short("k")
                        .required(true)
                        .takes_value(true)
                        .help("base64-encoded public key of peer"),
                )
                .arg(
                    Arg::with_name("feed")
                        .long("feed")
                        .short("f")
                        .required(true)
                        .takes_value(true)
                        .help("feed (user) id (eg. \"@N/vWpVVdD...\""),
                )
                .arg(
                    Arg::with_name("offsetpath")
                        .long("offsetpath")
                        .short("o")
                        .required(true)
                        .takes_value(true)
                        .help("path to ssb_db offset file"),
                )
                .arg(
                    Arg::with_name("dbpath")
                        .long("dbpath")
                        .short("db")
                        .required(true)
                        .takes_value(true)
                        .help("path to ssb_db sqlite file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("createHistoryStream")
                .about("Get messages by a specific feed")
                .arg(
                    Arg::with_name("feed")
                        .long("feed")
                        .short("f")
                        .required(true)
                        .takes_value(true)
                        .help("feed (user) id (eg. \"@N/vWpVVdD...\""),
                )
                .arg(
                    Arg::with_name("seq")
                        .long("seq")
                        .short("s")
                        .takes_value(true)
                        .help("select values larger than seq"),
                )
                .arg(
                    Arg::with_name("limit")
                        .long("limit")
                        .short("n")
                        .takes_value(true)
                        .help("limit the number of results"),
                )
                .arg(
                    Arg::with_name("offsetpath")
                        .long("offsetpath")
                        .short("o")
                        .required(true)
                        .takes_value(true)
                        .help("path to ssb_db offset file"),
                )
                .arg(
                    Arg::with_name("dbpath")
                        .long("dbpath")
                        .short("db")
                        .required(true)
                        .takes_value(true)
                        .help("path to ssb_db sqlite file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("publish")
                .about("publish a new message of well formed json")
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .short("c")
                        .required(true)
                        .takes_value(true)
                        .help("valid json string with a `type`"),
                )
                .arg(
                    Arg::with_name("offsetpath")
                        .long("offsetpath")
                        .short("o")
                        .required(true)
                        .takes_value(true)
                        .help("path to ssb_db offset file"),
                )
                .arg(
                    Arg::with_name("dbpath")
                        .long("dbpath")
                        .short("db")
                        .required(true)
                        .takes_value(true)
                        .help("path to ssb_db sqlite file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("generateSecret").about("generate a new ssb secret (key) file"),
        )
        .get_matches();

    match app_m.subcommand() {
        ("handleReplicationRequests", Some(sub_m)) => {
            let secret_path = app_m.value_of("secret").unwrap();

            let peer_key = sub_m.value_of("key").unwrap();
            let peer_addr = sub_m.value_of("addr").unwrap();

            let offset_log_path = sub_m.value_of("offsetpath").unwrap().to_string();
            let db_path = sub_m.value_of("dbpath").unwrap().to_string();

            let (pk, sk) = load_keys_from_path(&secret_path).context(ReadSecretFile)?;

            let net_id = NetworkKey::SSB_MAIN_NET;

            let server_pk = PublicKey::from_slice(&base64::decode(peer_key).unwrap()).unwrap();
            let (box_r, box_w) = block_on(async {
                let mut tcp = TcpStream::connect(&peer_addr)
                    .await
                    .context(TcpConnection)?;
                let o = client(&mut tcp, net_id, pk, sk, server_pk).await.unwrap();

                let (tcp_r, tcp_w) = tcp.split();
                Ok(BoxStream::client_side(tcp_r, tcp_w, o).split())
            })?;
            eprintln!("client connected");

            let mut pool = LocalPool::new();
            let spawner = pool.spawner();

            let (_out, done) =
                mux::mux(box_r, box_w, SyncRpcHandler::new(db_path, offset_log_path));
            let done = spawner.spawn_local_with_handle(done).unwrap();

            pool.run_until(done).unwrap();

            Ok(())
        }

        ("replicatefeed", Some(sub_m)) => {
            let secret_path = app_m.value_of("secret").unwrap();
            let feed_id = sub_m.value_of("feed").unwrap();

            let peer_key = sub_m.value_of("key").unwrap();
            let peer_addr = sub_m.value_of("addr").unwrap();
            let offset_log_path = sub_m.value_of("offsetpath").unwrap();
            let db_path = sub_m.value_of("dbpath").unwrap();

            let db = SqliteSsbDb::new(db_path, offset_log_path);

            let author = Multikey::from_legacy(&feed_id.as_bytes()).unwrap().0;
            let latest_seq = db.get_feed_latest_sequence(&author).unwrap().unwrap_or(0);

            eprintln!("Latest sequence for feed is {}", latest_seq);

            let (pk, sk) = load_keys_from_path(&secret_path).context(ReadSecretFile)?;

            let net_id = NetworkKey::SSB_MAIN_NET;

            let server_pk = PublicKey::from_slice(&base64::decode(peer_key).unwrap()).unwrap();
            let (box_r, box_w) = block_on(async {
                let mut tcp = TcpStream::connect(&peer_addr)
                    .await
                    .context(TcpConnection)?;
                let o = client(&mut tcp, net_id, pk, sk, server_pk).await.unwrap();

                let (tcp_r, tcp_w) = tcp.split();
                Ok(BoxStream::client_side(tcp_r, tcp_w, o).split())
            })?;
            eprintln!("client connected");

            let mut pool = LocalPool::new();
            let spawner = pool.spawner();

            let (mut out, done) = mux::mux(box_r, box_w, PacketLogger {});
            let done = spawner.spawn_local_with_handle(done).unwrap();

            // I _thought_ that createHistoryStream would get messages greater than latests_seq,
            // but maybe not?
            let msg = create_hist_stream_msg(feed_id, latest_seq as u32 + 1, Some(10000));

            let r = async move {
                let (mut a_out, a_in) = out.send_duplex(BodyType::Json, msg).await?;

                // We're potentially collecting an entire feed here. My ~6000 message feed is ~4mb
                // so it's not a huge deal. Later it could be good to `batch` chunks up for
                // verification + validation and appending to the db.
                let packets = a_in.map(|p| p.body).collect::<Vec<_>>().await;

                if !packets.is_empty() {
                    eprintln!("got {} new messages from server", packets.len());

                    let previous: Option<Vec<u8>> =
                        db.get_entry_by_seq(&author, latest_seq).unwrap();

                    // Later, we should add stuff to store into about broken feeds in the db.
                    // We should store why they broke and even store the offending message.
                    // Then we can do a avoid trying to replicate broken feeds over and over.
                    par_validate_message_hash_chain_of_feed(&packets, previous.as_ref()).unwrap();
                    eprintln!("validated messages");

                    par_verify_messages(&packets, None).unwrap();
                    eprintln!("verified messages");

                    db.append_batch(&author, &packets).unwrap();

                    eprintln!("appended {} new messages to db", packets.len());
                } else {
                    eprintln!("no new messages to append");
                }

                a_out
                    .send_end(BodyType::Json, "true".bytes().collect())
                    .await
            };

            let r = spawner.spawn_local_with_handle(r).unwrap();
            pool.run_until(r).unwrap();
            pool.run_until(done).unwrap();

            Ok(())
        }

        ("createHistoryStream", Some(sub_m)) => {
            let feed_id = sub_m.value_of("feed").unwrap();
            let limit = sub_m
                .value_of("limit")
                .map(|l| str::parse::<i64>(l).unwrap());
            let seq = sub_m.value_of("seq").map(|l| str::parse::<i32>(l).unwrap());

            let offset_log_path = sub_m.value_of("offsetpath").unwrap();
            let db_path = sub_m.value_of("dbpath").unwrap();

            let author = Multikey::from_legacy(&feed_id.as_bytes()).unwrap().0;

            let db = SqliteSsbDb::new(db_path, offset_log_path);

            //TODO add keys and values switches to args. For now they're both true.
            let entries = db
                .get_entries_newer_than_sequence(&author, seq.unwrap_or(0), limit, true, true)
                .unwrap();

            entries
                .iter()
                .for_each(|entry| println!("{}", std::str::from_utf8(entry).unwrap()));

            Ok(())
        }

        ("publish", Some(sub_m)) => {
            let secret_path = app_m.value_of("secret").unwrap();
            let (pk, sk) = load_keys_from_path(&secret_path).context(ReadSecretFile)?;

            let author = Multikey::from_ed25519(pk.as_ref().try_into().unwrap());

            let content = sub_m
                .value_of("content")
                .map(|content| {
                    serde_json::from_str::<Value>(content).expect("content must be valid json")
                })
                .unwrap();

            assert!(content.get("type").is_some(), "content must have a `type`");

            let offset_log_path = sub_m.value_of("offsetpath").unwrap();
            let db_path = sub_m.value_of("dbpath").unwrap();
            let db = SqliteSsbDb::new(db_path, offset_log_path);

            let previous: Option<Vec<_>> = db
                .get_feed_latest_sequence(&author)
                .unwrap_or(None)
                .map(|seq| db.get_entry_by_seq(&author, seq).unwrap())
                .unwrap_or(None);

            let new_message =
                publish(Content::Plain(content), previous.clone(), &pk, &sk, 0.0).unwrap();

            // Some extra safety here, just in case publish is broken.
            verify_message(&new_message).expect("published message sig was not valid");
            validate_message_hash_chain(&new_message, previous)
                .expect("published message hash chain was not valid");

            eprintln!("published a new message!");
            println!("{}", std::str::from_utf8(&new_message).unwrap());

            db.append_batch(&author, &[new_message]).unwrap();

            Ok(())
        }
        ("generateSecret", Some(_sub_m)) => {
            use std::io::Write;

            let secret_path = app_m.value_of("secret").unwrap();

            let (pk, sk) = ssb_crypto::generate_longterm_keypair();

            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(secret_path)
                .expect("secret file already exists")
                .write_all(ssb_keyfile::new_keyfile_string(&pk, &sk).as_bytes())
                .expect("could not write to secret file");

            Ok(())
        }
        _ => {
            // println!("{}", app_m.usage());
            Ok(())
        }
    }
}
