use async_trait::async_trait;
use futures::channel::mpsc::Receiver;
use futures::stream::StreamExt;
use snafu::Snafu;
use ssb_db::{SqliteSsbDb, SsbDb};
use ssb_multiformats::multikey::Multikey;
use ssb_packetstream::{mux, BodyType, ChildError, MuxChildSender, MuxHandler, Packet};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, Snafu)]
pub enum RpcError {
    #[snafu(display("Unhandled RPC name: {:?}", name))]
    Unhandled { name: Vec<String> },
}

pub struct SyncRpcHandler {
    db: Arc<Mutex<SqliteSsbDb>>,
}

impl SyncRpcHandler {
    // TODO: should be AsRef<Path>, but SsbDb uses str
    pub fn new<P: AsRef<str>>(db_path: P, offset_log_path: P) -> Self {
        let db = Arc::new(Mutex::new(SqliteSsbDb::new(&db_path, &offset_log_path)));
        Self { db }
    }
}

#[async_trait]
impl MuxHandler for SyncRpcHandler {
    type Error = RpcError;

    async fn handle(
        &self,
        p: Packet,
        mut out: MuxChildSender,
        _inn: Option<Receiver<Packet>>,
    ) -> Result<(), Self::Error> {
        log_packet(&p);

        if let Ok(method) = serde_json::from_slice::<CHSRpcMethod>(&p.body) {
            if method.name != ["createHistoryStream"] {
                out.send_end(BodyType::Json, "true".to_string().into_bytes())
                    .await
                    .unwrap();
                return Ok(());
            }
            eprintln!("got a chs request.");

            let args = method.args[0].clone();
            let feed_id = Multikey::from_legacy(args.id.as_bytes()).unwrap().0;
            let entries = {
                let db = self.db.lock().unwrap();
                db.get_entries_newer_than_sequence(
                    &feed_id,
                    args.seq - 1,
                    args.limit,
                    args.keys.unwrap_or(false),
                    true,
                )
                .unwrap()
            };

            eprintln!("retrieved {} entries", entries.len());

            let mut strm =
                futures::stream::iter(entries.into_iter()).map(|entry| (BodyType::Json, entry));

            out.send_all(&mut strm).await.unwrap();
            out.send_end(BodyType::Json, "true".to_string().into_bytes())
                .await
                .unwrap();
            eprintln!("sent all entries");
        } else {
            eprintln!("couldn't parse packet as CHSRpcMethod");
        }
        Ok(())
    }
}

pub struct PacketLogger {}
#[async_trait]
impl MuxHandler for PacketLogger {
    type Error = RpcError;
    async fn handle(
        &self,
        packet: Packet,
        _sender: MuxChildSender,
        _receiver: Option<Receiver<Packet>>,
    ) -> Result<(), Self::Error> {
        log_packet(&packet);
        Ok(())
    }
}

fn log_packet(p: &Packet) {
    let s = std::str::from_utf8(&p.body).unwrap();
    eprintln!(
        "In: {} strm:{:?} end:{:?} {:?} {}",
        p.id,
        p.is_stream(),
        p.is_end(),
        p.body_type,
        s
    );
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CreateHistoryStreamArgs {
    id: String,
    seq: i32,
    limit: Option<i64>,
    values: Option<bool>,
    keys: Option<bool>,
}
#[derive(Deserialize, Serialize, Debug)]
pub struct CHSRpcMethod {
    args: Vec<CreateHistoryStreamArgs>,
    name: Vec<String>,
    #[serde(rename = "type")]
    type_key: String,
}
#[derive(Deserialize, Serialize, Debug)]
pub struct RpcMethod {
    args: Vec<String>,
    name: Vec<String>,
    #[serde(rename = "type")]
    type_key: String,
}
