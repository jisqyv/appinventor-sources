#[macro_use]
extern crate lazy_static;
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use std::collections::{BTreeMap, HashSet};
use std::convert::{From, Infallible};
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use structopt::StructOpt;
use tokio::runtime;
use uuid::Uuid;
use warp::reject::{Reject, Rejection};
use warp::reply::Response;
use warp::{Filter, Reply};
extern crate structopt;
use async_openai::{
    types::{
        ChatCompletionRequestMessage, ChatCompletionRequestMessageArgs,
        CreateChatCompletionRequestArgs, Role,
    },
    Client,
};
use debug_print::debug_eprintln;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::error::Error;

mod chat;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    port: u16,
    nthreads: usize,
    dbfile: String,
    blocklist: HashSet<String>,
    hmac_keys: BTreeMap<String, String>,
    apikey: String,
}

impl ::std::default::Default for Config {
    fn default() -> Self {
        Self {
            port: 9001,
            nthreads: 0, // Means as many as cores
            dbfile: String::from("/data/dbfile.sqlite"),
            blocklist: HashSet::from(["foo".to_string(), "bar".to_string()]),
            hmac_keys: BTreeMap::from([
                ("0".into(), "changeme!".into()),
                ("1".into(), "change or delete me!".into()),
            ]),
            apikey: String::from("sk-key-here"),
        }
    }
}

lazy_static! {
    static ref CONFIG: Config = {
        let args = Cli::from_args();
        confy::load_path(args.config_file).unwrap()
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChatproxyError {
    Message(String),
    Unauthorized,
    OverQuota,
}

impl Error for ChatproxyError {}

impl Reject for ChatproxyError {}

impl fmt::Display for ChatproxyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChatproxyError::Message(n) => {
                write!(f, "{}", n).ok();
            }
            ChatproxyError::OverQuota => {
                write!(f, "Over Quota").ok();
            }
            ChatproxyError::Unauthorized => {
                write!(f, "Unauthroized").ok();
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Pair {
    role: Role,
    text: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Conversation {
    uuid: String,
    content: Vec<Pair>,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "chat", about = "Interact with ChatGPT")]
struct Cli {
    /// Config FIle
    config_file: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let rt = match CONFIG.nthreads {
        1 => runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
        0 => runtime::Builder::new_multi_thread().enable_all().build()?,
        n => runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(n)
            .build()?,
    };

    rt.block_on(async {
        let options =
            SqliteConnectOptions::from_str(&CONFIG.dbfile)?.journal_mode(SqliteJournalMode::Wal);

        let dbpool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await?;
        sqlx::query(
            "create table if not exists conversation (uuid text primary key, conversation blob)",
        )
        .execute(&dbpool)
        .await?;
        sqlx::query("create table if not exists whitelist (uuid text primary key)")
            .execute(&dbpool)
            .await?;
        let _t: Result<(), tokio::task::JoinError> = tokio::spawn(async move {
            let rootget = warp::path!("chat" / "v1")
                .and(warp::post())
                .and(warp::body::bytes())
                .and_then(move |data: bytes::Bytes| {
                    let dbpool = dbpool.clone();
                    async move {
                        let mut reader = BytesReader::from_bytes(&data);
                        let message = match chat::request::from_reader(&mut reader, &data) {
                            Ok(n) => n,
                            Err(_) => {
                                debug_eprintln!("Reject 1");
                                return Err(
                                    ChatproxyError::Message("Invalid Request".to_string()).into()
                                );
                            }
                        };
                        let apikey = if let Some(apikey) = message.apikey {
                            if apikey.is_empty() {
                                None
                            } else {
                                Some(apikey)
                            }
                        } else {
                            None
                        };
                        let (huuid, _keyid) = if let Some(token) = message.token {
                            match parse_token(&token) {
                                Ok(n) => n,
                                Err(_) => {
                                    return Err(ChatproxyError::Message(
                                        "Invalid Auth Token".to_string(),
                                    )
                                    .into());
                                }
                            }
                        } else {
                            return Err(
                                ChatproxyError::Message("Invalid Auth Token".to_string()).into()
                            );
                        };
                        debug_eprintln!("huuid = {}", huuid);
                        if apikey.is_none() {
                            // If they supply an apikey, then they are welcome
                            // do not check whitelist or blocklist
                            if !on_whitelist(&huuid, &dbpool).await {
                                println!("Rejecting Request from {}, not on whitelist.", huuid);
                                return Err(ChatproxyError::Unauthorized.into());
                            };
                            if CONFIG.blocklist.contains(&huuid) {
                                return Err(ChatproxyError::OverQuota.into());
                            }
                        }
                        let uuid = match message.uuid {
                            Some(n) => {
                                if message.system.is_some() && !n.is_empty() {
                                    return Err(ChatproxyError::Message(
                                        "Cannot provide uuid with system input".to_string(),
                                    )
                                    .into());
                                };
                                if n.is_empty() {
                                    Uuid::new_v4().to_string()
                                } else {
                                    n
                                }
                            }
                            None =>
                            // New request
                            {
                                Uuid::new_v4().to_string()
                            }
                        };
                        let question = if let Some(q) = message.question {
                            q
                        } else {
                            return Err(
                                ChatproxyError::Message("Must Ask a Question".to_string()).into()
                            );
                        };
                        let answer =
                            match converse(&dbpool, &uuid, message.system, &question, apikey).await
                            {
                                Ok(n) => n,
                                Err(e) => {
                                    return Err(ChatproxyError::Message(format!(
                                        "Error from ChatBox: {}",
                                        e
                                    ))
                                    .into());
                                }
                            };
                        let b = make_response(&answer, &uuid);
                        Ok::<Blob, Rejection>(b)
                    }
                });
            let health = warp::path!("health")
                .and(warp::get())
                .map(|| warp::reply::with_status("OK", warp::http::StatusCode::OK));
            let routes = rootget.or(health).recover(handle_rejection);
            let server = warp::serve(routes);
            let socketaddr: SocketAddr = ([0, 0, 0, 0], CONFIG.port).into();
            let http_server = server.run(socketaddr);
            http_server.await
        })
        .await;
        Ok::<(), Box<dyn Error>>(())
    })
}

async fn converse(
    dbpool: &SqlitePool,
    uuid: &str,
    system: Option<String>,
    question: &str,
    apikey: Option<String>,
) -> Result<String, Box<dyn Error>> {
    let mut conversation: Conversation =
        match sqlx::query("select conversation from conversation where uuid = ?")
            .bind(uuid)
            .fetch_one(dbpool)
            .await
        {
            Ok(n) => {
                let s = n.get::<String, usize>(0);
                serde_json::from_str(&s)?
            }
            Err(_e) => Conversation {
                uuid: uuid.to_string(),
                content: vec![Pair {
                    role: Role::System,
                    text: if let Some(s) = system {
                        s
                    } else {
                        "".to_string()
                    },
                }],
            },
        };
    conversation.content.push(Pair {
        role: Role::User,
        text: question.to_string(),
    });
    let messages = conversation
        .content
        .iter()
        .map(|v| {
            Ok::<ChatCompletionRequestMessage, Box<dyn Error>>(
                ChatCompletionRequestMessageArgs::default()
                    .role(v.role.clone())
                    .content(&v.text)
                    .build()?,
            )
        })
        .collect::<Result<Vec<ChatCompletionRequestMessage>, _>>()?;

    let apikey = if let Some(apikey) = apikey {
        apikey
    } else {
        CONFIG.apikey.clone()
    };
    debug_eprintln!("Using apikey = {}", apikey);
    let client = Client::new().with_api_key(&apikey);
    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model("gpt-3.5-turbo")
        .messages(messages)
        .build()?;

    let response = client.chat().create(request).await?;
    debug_eprintln!("Response: {:#?}", response);
    let mut retval = "Unkonwn".to_string();
    for choice in response.choices {
        if choice.message.role == Role::Assistant {
            retval = choice.message.content.clone();
        };
        conversation.content.push(Pair {
            role: choice.message.role,
            text: choice.message.content,
        });
    }
    sqlx::query("insert or replace into  conversation values(?, ?)")
        .bind(conversation.uuid.clone())
        .bind(serde_json::to_string(&conversation)?)
        .execute(dbpool)
        .await?;
    Ok(retval)
}

fn parse_token(token: &chat::token) -> Result<(String, u64), Box<dyn Error>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let keyid = token.keyid;
    let hmac_key = match &CONFIG.hmac_keys.get(&keyid.to_string()) {
        Some(n) => <&String>::clone(n),
        None => {
            return Err(Box::<dyn Error>::from("Unknown KeyId"));
        }
    };

    let mut hmac = HmacSha256::new_from_slice(hmac_key.as_bytes()).expect("Invalid Key Length");
    let unsignedbytes = match &token.unsigned {
        Some(stuff) => stuff,
        None => {
            return Err(Box::<dyn Error>::from("Invalid Token"));
        }
    };
    let signature = match &token.signature {
        Some(stuff) => stuff,
        None => {
            return Err(Box::<dyn Error>::from("Invalid Token"));
        }
    };
    hmac.update(unsignedbytes);
    match hmac.verify_slice(signature) {
        Ok(v) => v,
        Err(_e) => {
            return Err(Box::<dyn Error>::from("signature did not match"));
        }
    };
    let mut reader = BytesReader::from_bytes(unsignedbytes);
    let inner = chat::unsigned::from_reader(&mut reader, unsignedbytes)?;
    if let Some(huuid) = inner.huuid {
        Ok((huuid, keyid))
    } else {
        Err(Box::<dyn Error>::from("No huuid"))
    }
}

fn make_response(answer: &str, uuid: &str) -> Blob {
    let answer = answer.to_string();
    let r = chat::response {
        uuid: Some(uuid.to_string()),
        answer: Some(answer),
        version: 1,
        status: 1,
    };
    let wsize = r.get_size();
    debug_eprintln!("wsize = {}", wsize);
    let mut out = Vec::with_capacity(wsize + 1);
    let mut writer = Writer::new(&mut out);
    debug_eprintln!("message = {:?}", r);
    writer.write_message(&r).unwrap();
    // debug_eprintln!("out.length = {}", out.len());
    // debug_eprintln!("out = {:?}", out);
    Blob {
        bytes: bytes::Bytes::from(trim(out)),
    }
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    use warp::http::StatusCode;
    let text = if let Some(e) = err.find::<ChatproxyError>() {
        match e {
            ChatproxyError::Message(m) => m.to_string(),
            ChatproxyError::Unauthorized => {
                let text = "You are not on the list of approved users".to_string();
                return Ok(warp::reply::with_status(text, StatusCode::UNAUTHORIZED));
            }
            ChatproxyError::OverQuota => {
                let text = "Usage Over Quota".to_string();
                return Ok(warp::reply::with_status(
                    text,
                    StatusCode::TOO_MANY_REQUESTS,
                ));
            }
        }
    } else {
        "Unknown Error".to_string()
    };

    Ok(warp::reply::with_status(text, StatusCode::NOT_FOUND))
}

struct Blob {
    bytes: bytes::Bytes,
}

impl Reply for Blob {
    fn into_response(self) -> Response {
        use http::*;
        use warp::hyper::Body;
        Response::builder()
            .status(200)
            .header("Content-Type", "application/octet-stream")
            .body(Body::from(self.bytes))
            .unwrap()
    }
}

fn trim(inv: Vec<u8>) -> Vec<u8> {
    let mut invec = inv;
    while invec[0] >= 128 {
        invec = invec.split_off(1);
    }
    invec.split_off(1)
}

async fn on_whitelist(uuid: &str, dbpool: &SqlitePool) -> bool {
    sqlx::query("select * from whitelist where uuid = ?")
        .bind(uuid)
        .fetch_one(dbpool)
        .await
        .is_ok()
}
