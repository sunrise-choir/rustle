use async_std::sync::Mutex;
use async_trait::async_trait;
use futures::channel::mpsc::Receiver;
use futures::stream::StreamExt;
use serde_json::Value;
use snafu::{ResultExt as _, Snafu};
use ssb_db::{SqliteSsbDb, SsbDb};
use ssb_multiformats::multikey::Multikey;
use ssb_packetstream::{mux, BodyType, Packet};
use std::sync::Arc;

#[derive(Debug, Snafu)]
pub enum RpcError {
    #[snafu(display("Unhandled RPC name: {:?}", name))]
    Unhandled { name: Vec<String> },

    #[snafu(display("Failed to parse rpc request: {}", source))]
    ParseBody { source: serde_json::Error },

    #[snafu(display("Failed to parse rpc args: {}", source))]
    ParseArgs { source: serde_json::Error },

    #[snafu(display("SsbDb failure: {}", source))]
    Db { source: ssb_db::error::Error },

    #[snafu(display("Failed to send packet: {}", source))]
    Send { source: mux::SendError },
}

pub struct SyncRpcHandler {
    db: Arc<Mutex<SqliteSsbDb>>,
}

impl SyncRpcHandler {
    // TODO: should be AsRef<Path>, but SsbDb uses str
    pub fn new<P: AsRef<str>>(db_path: P, offset_log_path: P) -> Self {
        let db = Arc::new(Mutex::new(
            // This could block and get the entire async runtime to hang.
            SqliteSsbDb::new(&db_path, &offset_log_path),
        ));
        Self { db }
    }
}

#[async_trait]
impl mux::Handler for SyncRpcHandler {
    type Error = RpcError;

    async fn handle(
        &self,
        p: Packet,
        mut out: mux::ChildSender,
        _inn: Option<Receiver<Packet>>,
    ) -> Result<(), Self::Error> {
        log_packet(&p);

        let method = serde_json::from_slice::<RpcMethod>(&p.body).context(ParseBody)?;

        match &method.name[..] {
            [x] if x == "createHistoryStream" => {
                let args = serde_json::from_value::<Vec<CreateHistoryStreamArgs>>(method.args)
                    .context(ParseArgs)?;

                eprintln!("got a chs request.");

                let args = args[0].clone();
                let feed_id = Multikey::from_legacy(args.id.as_bytes()).unwrap().0;
                let entries = {
                    let db = self.db.lock().await;

                    // This could block and get the entire async runtime to hang.
                    db.get_entries_newer_than_sequence(
                        &feed_id,
                        args.seq - 1,
                        args.limit,
                        args.keys.unwrap_or(false),
                        true,
                    )
                    .context(Db)?
                };

                eprintln!("retrieved {} entries", entries.len());

                let mut strm =
                    futures::stream::iter(entries.into_iter()).map(|entry| (BodyType::Json, entry));

                out.send_all(&mut strm).await.context(Send)?;
                out.send_end(BodyType::Json, "true".to_string().into_bytes())
                    .await
                    .context(Send)
            }
            _ => out
                .send_end(BodyType::Json, "true".to_string().into_bytes())
                .await
                .context(Send),
        }
    }
}

pub struct PacketLogger {}
#[async_trait]
impl mux::Handler for PacketLogger {
    type Error = RpcError;
    async fn handle(
        &self,
        packet: Packet,
        _sender: mux::ChildSender,
        _receiver: Option<mux::ChildReceiver>,
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
    args: Value,
    name: Vec<String>,
    #[serde(rename = "type")]
    type_key: String,
}
