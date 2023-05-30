#[macro_use]
extern crate lazy_static;
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use std::borrow::Cow;
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

const SECS_PER_DAY: i32 = 86400;

mod chat;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    port: u16,
    nthreads: usize,
    dbfile: String,
    blocklist: HashSet<String>,
    hmac_keys: BTreeMap<String, String>,
    apikey: String,
    default_quota: i32,
    use_allowlist: bool,
    use_limits: bool,
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
            default_quota: 10000,
            use_allowlist: true,
            use_limits: true,
        }
    }
}

trait Test {
    fn test() -> Self;
}

impl Test for Config {
    fn test() -> Self {
        Self {
            port: 9001,
            nthreads: 0, // Means as many as cores
            dbfile: String::from("/ram/dbfile.sqlite"),
            blocklist: HashSet::from(["foo".to_string(), "bar".to_string()]),
            hmac_keys: BTreeMap::from([
                ("0".into(), "changeme!".into()),
                ("1".into(), "change or delete me!".into()),
            ]),
            apikey: String::from("sk-key-here"),
            default_quota: 10000,
            use_allowlist: true,
            use_limits: true,
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
        let dbpool = setup(&CONFIG).await?;
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
                                Err(_e) => {
                                    debug_eprintln!("parse_token: {:#?}", _e);
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
                        if apikey.is_none() && CONFIG.use_allowlist {
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
                        if apikey.is_none()
                            && CONFIG.use_limits
                            && !match check_limit(&huuid, &dbpool).await {
                                Ok(n) => n,
                                Err(_) => {
                                    return Err(ChatproxyError::OverQuota.into());
                                }
                            }
                        {
                            return Err(ChatproxyError::OverQuota.into());
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
                                    n.to_string()
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
                        let answer = match converse(
                            &huuid,
                            &dbpool,
                            &uuid,
                            message.system,
                            &question,
                            apikey,
                        )
                        .await
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

async fn converse<'a>(
    huuid: &str,
    dbpool: &SqlitePool,
    uuid: &str,
    system: Option<Cow<'_, str>>,
    question: &str,
    apikey: Option<Cow<'_, str>>,
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
                        s.to_string()
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

    let apikey_to_use = if let Some(apikey) = apikey.clone() {
        apikey.into_owned()
    } else {
        CONFIG.apikey.clone()
    };
    let client = Client::new().with_api_key(&apikey_to_use);
    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model("gpt-3.5-turbo")
        .messages(messages)
        .build()?;

    let response = client.chat().create(request).await?;
    let mut retval = "Unkonwn".to_string();
    let usage = if let Some(ref u) = response.usage {
        u.total_tokens
    } else {
        0
    };
    record_usage(huuid, usage, dbpool).await?;
    if apikey.is_none() && CONFIG.use_limits {
        update_limit(huuid, usage.try_into().unwrap(), dbpool, &CONFIG).await
    }
    for choice in response.choices {
        if choice.message.role == Role::Assistant {
            retval = choice.message.content.clone();
        };
        conversation.content.push(Pair {
            role: choice.message.role,
            text: choice.message.content,
        });
    }
    sqlx::query("insert or replace into  conversation (uuid, conversation, timestamp) values(?, ?, datetime())")
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
        Ok((huuid.into_owned(), keyid))
    } else {
        Err(Box::<dyn Error>::from("No huuid"))
    }
}

fn make_response(answer: &str, uuid: &str) -> Blob {
    let answer = answer.to_string();
    let r = chat::response {
        uuid: Some(Cow::Borrowed(uuid)),
        answer: Some(Cow::Owned(answer)),
        version: 1,
        status: 1,
    };
    let wsize = r.get_size();
    let mut out = Vec::with_capacity(wsize + 1);
    let mut writer = Writer::new(&mut out);
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

async fn setup(conf: &Config) -> Result<SqlitePool, Box<dyn Error>> {
    let options = SqliteConnectOptions::from_str(&conf.dbfile)?
        .journal_mode(SqliteJournalMode::Wal)
        .create_if_missing(true);

    let dbpool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;
    sqlx::query(
        "create table if not exists conversation (uuid text primary key, conversation blob, timestamp timestamp)",
    )
    .execute(&dbpool)
    .await?;
    sqlx::query("create table if not exists whitelist (uuid text primary key)")
        .execute(&dbpool)
        .await?;
    sqlx::query("create table if not exists usage (huuid text primary key, usage integer)")
        .execute(&dbpool)
        .await?;
    sqlx::query(
        "create table if not exists limits (huuid text primary key, usage integer, quota integer, timestamp timestamp)",
    )
    .execute(&dbpool)
    .await?;
    Ok(dbpool)
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

async fn record_usage(huuid: &str, usage: u32, dbpool: &SqlitePool) -> Result<(), Box<dyn Error>> {
    let prior_usage = match sqlx::query("select usage from usage where huuid = ?")
        .bind(huuid)
        .fetch_one(dbpool)
        .await
    {
        Ok(row) => row.get::<u32, usize>(0),
        Err(_) => 0,
    };
    let usage = usage + prior_usage;
    sqlx::query("insert or replace into usage values (?, ?)")
        .bind(huuid)
        .bind(usage)
        .execute(dbpool)
        .await?;
    Ok(())
}

async fn update_limit(huuid: &str, usage: i32, dbpool: &SqlitePool, conf: &Config) {
    debug_eprintln!("update_limit: entered");
    let mut transaction = dbpool.begin().await.unwrap();

    let (old_usage, quota, ts) =
        match sqlx::query("select usage, quota, timestamp from limits where huuid = ?")
            .bind(huuid)
            .fetch_one(&mut transaction)
            .await
        {
            Ok(row) => (
                row.get::<i32, usize>(0),
                row.get::<i32, usize>(1),
                row.get::<i64, usize>(2),
            ),
            Err(_) => {
                // First time?
                use std::time::SystemTime;
                let now = SystemTime::now();
                let utime: i64 = now
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .try_into()
                    .unwrap();
                (0, conf.default_quota, utime)
            }
        };
    let usage = old_usage + usage;
    sqlx::query(
        "insert or replace into limits (huuid, usage, quota, timestamp) values (?, ?, ?, ?)",
    )
    .bind(huuid)
    .bind(usage)
    .bind(quota)
    .bind(ts)
    .execute(&mut transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    debug_eprintln!("update_limit: leaving");
}

fn get_unix_now() -> Result<i64, Box<dyn Error>> {
    use std::time::SystemTime;
    let now = SystemTime::now();
    let utime = now
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs()
        .try_into()?;
    debug_eprintln!("check_unix_now: returning {}", utime);
    Ok(utime)
}

async fn check_limit(huuid: &str, dbpool: &SqlitePool) -> Result<bool, Box<dyn Error>> {
    let utime = get_unix_now()?;
    let (usage, quota, their_time) =
        match sqlx::query("select usage, quota, timestamp from limits where huuid = ?")
            .bind(huuid)
            .fetch_one(dbpool)
            .await
        {
            Ok(row) => {
                let usage = row.get::<i32, usize>(0);
                let quota = row.get::<i32, usize>(1);
                let timestamp = row.get::<i64, usize>(2);
                (usage, quota, timestamp)
            }
            Err(_) => (0, CONFIG.default_quota, utime),
        };
    let passed: i64 = utime - their_time;
    let v: i32 = (quota * passed as i32) / SECS_PER_DAY;
    let mut r = usage - v;
    debug_eprintln!("check_limit: r = {}", r);
    if r < 0 {
        r = 0
    }
    match sqlx::query(
        "insert or replace into limits (huuid, usage, quota, timestamp) values (?, ?, ?, ?)",
    )
    .bind(huuid)
    .bind(r)
    .bind(quota)
    .bind(utime)
    .execute(dbpool)
    .await
    {
        Ok(_) => (),
        Err(e) => return Err(e.into()),
    };
    if r < quota {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::fs;

    trait Test {
        fn test() -> Self;
    }

    impl Test for Config {
        fn test() -> Self {
            Self {
                port: 9001,
                nthreads: 0, // Means as many as cores
                dbfile: String::from("/ram/dbfile.sqlite"),
                blocklist: HashSet::from(["foo".to_string(), "bar".to_string()]),
                hmac_keys: BTreeMap::from([
                    ("0".into(), "changeme!".into()),
                    ("1".into(), "change or delete me!".into()),
                ]),
                apikey: String::from("sk-key-here"),
                default_quota: 10000,
                use_allowlist: true,
                use_limits: true,
            }
        }
    }

    #[tokio::test]
    async fn verify_limits() {
        debug_eprintln!("verify_limits");
        let conf: Config = Config::test();
        fs::remove_file(&conf.dbfile).ok();
        fs::remove_file(format!("{}-wal", &conf.dbfile)).ok();
        fs::remove_file(format!("{}-shm", &conf.dbfile)).ok();
        let dbpool = setup(&conf).await.unwrap();
        update_limit("12345", 10000, &dbpool, &conf).await;
        let now = get_unix_now().unwrap();
        let then = now - (3600 * 12); // an hour ago
                                      // Set timestamp back an hour
        sqlx::query("update limits set timestamp = ? where huuid = ?")
            .bind(then)
            .bind("12345")
            .execute(&dbpool)
            .await
            .unwrap();
        let v = check_limit("12345", &dbpool).await.unwrap();
        debug_eprintln!("v = {}", v);
        assert!(v == true);
    }
}
