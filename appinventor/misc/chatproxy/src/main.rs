#[macro_use]
extern crate lazy_static;
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use std::collections::BTreeMap;
use std::convert::{From, Infallible};
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::{borrow::Cow, u64};
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
mod dallelib;
mod image;
mod palmlib;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    port: u16,
    nthreads: usize,
    dbfile: String,
    hmac_keys: BTreeMap<String, String>,
    chatgpt_apikey: String,
    default_quota: i32,
    chatgpt_use_allowlist: bool,
    chatgpt_use_limits: bool,
    palm_apikey: String,
    palm_use_allowlist: bool,
}

impl ::std::default::Default for Config {
    fn default() -> Self {
        Self {
            port: 9001,
            nthreads: 0, // Means as many as cores
            dbfile: String::from("/data/dbfile.sqlite"),
            hmac_keys: BTreeMap::from([
                ("0".into(), "changeme!".into()),
                ("1".into(), "change or delete me!".into()),
            ]),
            chatgpt_apikey: String::from("sk-key-here"),
            default_quota: 10000,
            chatgpt_use_allowlist: true,
            chatgpt_use_limits: true,
            palm_apikey: String::from("key-here"),
            palm_use_allowlist: true,
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
            hmac_keys: BTreeMap::from([
                ("0".into(), "changeme!".into()),
                ("1".into(), "change or delete me!".into()),
            ]),
            chatgpt_apikey: String::from("sk-key-here"),
            default_quota: 10000,
            chatgpt_use_allowlist: true,
            chatgpt_use_limits: true,
            palm_apikey: String::from("key-here"),
            palm_use_allowlist: true,
        }
    }
}

trait Token<'a> {
    fn get_unsigned(&self) -> Option<Cow<'a, [u8]>>;
    fn get_signature(&self) -> Option<Cow<'a, [u8]>>;
    fn get_keyid(&self) -> u64;
}

impl<'a> Token<'a> for chat::token<'a> {
    fn get_unsigned(&self) -> Option<Cow<'a, [u8]>> {
        self.unsigned.clone()
    }
    fn get_signature(&self) -> Option<Cow<'a, [u8]>> {
        self.signature.clone()
    }
    fn get_keyid(&self) -> u64 {
        self.keyid
    }
}

impl<'a> Token<'a> for image::token<'a> {
    fn get_unsigned(&self) -> Option<Cow<'a, [u8]>> {
        self.unsigned.clone()
    }
    fn get_signature(&self) -> Option<Cow<'a, [u8]>> {
        self.signature.clone()
    }
    fn get_keyid(&self) -> u64 {
        self.keyid
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
    UnknownProvider,
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
            ChatproxyError::UnknownProvider => {
                write!(f, "Unknown provider").ok();
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
            let cdbpool = dbpool.clone();
            let chatget = warp::path!("chat" / "v1")
                .and(warp::post())
                .and(warp::body::bytes())
                .and_then(move |data: bytes::Bytes| {
                    let cdbpool = cdbpool.clone();
                    async move {
                        let b = do_chat(data, &cdbpool).await?;
                        Ok::<Blob, Rejection>(b)
                    }
                });
            let imageget = warp::path!("image" / "v1")
                .and(warp::post())
                .and(warp::body::bytes())
                .and_then(move |data: bytes::Bytes| {
                    let dbpool = dbpool.clone();
                    async move {
                        let b: Blob = do_image(data, &dbpool).await?;
                        Ok::<Blob, Rejection>(b)
                    }
                });
            let health = warp::path!("health")
                .and(warp::get())
                .map(|| warp::reply::with_status("OK", warp::http::StatusCode::OK));
            let routes = chatget.or(health).or(imageget).recover(handle_rejection);
            let server = warp::serve(routes);
            let socketaddr: SocketAddr = ([0, 0, 0, 0], CONFIG.port).into();
            let http_server = server.run(socketaddr);
            http_server.await
        })
        .await;
        Ok::<(), Box<dyn Error>>(())
    })
}

async fn do_chat(data: bytes::Bytes, dbpool: &SqlitePool) -> Result<Blob, ChatproxyError> {
    let mut reader = BytesReader::from_bytes(&data);
    let message = chat::request::from_reader(&mut reader, &data)
        .map_err(|e| ChatproxyError::Message(e.to_string()))?;
    let apikey = message.apikey.filter(|apikey| !apikey.is_empty());
    let (huuid, _keyid) = if let Some(token) = message.token {
        parse_token(&token).map_err(|e| ChatproxyError::Message(e.to_string()))?
    } else {
        return Err(ChatproxyError::Message("Invalid Auth Token".to_string()));
    };
    debug_eprintln!("huuid = {}", huuid);
    let provider = message.provider;
    if apikey.is_none() {
        match &*provider {
            "chatgpt" => {
                if CONFIG.chatgpt_use_allowlist && !on_whitelist(&huuid, dbpool, &provider).await {
                    println!("Rejecting Request from {}, not on whitelist.", huuid);
                    return Err(ChatproxyError::Unauthorized);
                }
                if CONFIG.chatgpt_use_limits
                    && !check_limit(&huuid, dbpool, &provider)
                        .await
                        .map_err(|_| ChatproxyError::OverQuota)?
                {
                    return Err(ChatproxyError::OverQuota);
                }
            }
            "palm" => {
                if CONFIG.palm_use_allowlist && !on_whitelist(&huuid, dbpool, &provider).await {
                    println!(
                        "PaLM: Rejecting Request from {}, not on whitelist provider = {}",
                        huuid, provider
                    );
                    return Err(ChatproxyError::Unauthorized);
                }
            }
            _ => {
                return Err(ChatproxyError::UnknownProvider);
            }
        }
    }
    let uuid = match message.uuid {
        Some(n) => {
            if message.system.is_some() && !n.is_empty() {
                return Err(ChatproxyError::Message(
                    "Cannot provide uuid with system input".to_string(),
                ));
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
    let model = if let Some(m) = message.model {
        m
    } else {
        Cow::Borrowed("gpt-3.5-turbo")
    };
    let model = &*model;
    if apikey.is_none() {
        match model {
            "gpt-3.5-turbo" => (),
            "gpt-4.0" | "gpt-4" => {
                let b = make_response("MIT: gpt-4.0 not yet supported", &huuid);
                return Ok(b);
            }
            _ => {
                return Err(ChatproxyError::Message(format!(
                    "Unsupported model {}",
                    model
                )));
            }
        };
    }
    let question = if let Some(q) = message.question {
        q
    } else {
        return Err(ChatproxyError::Message("Must Ask a Question".to_string()));
    };
    let answer = match &*provider {
        "chatgpt" => converse_chatgpt(
            &huuid,
            dbpool,
            &uuid,
            message.system,
            &question,
            apikey,
            model,
        )
        .await
        .map_err(|e| {
            debug_eprintln!("converse_chatgpt error: {:#?}", e);
            ChatproxyError::Message(e.to_string())
        })?,
        "palm" => converse_palm(&huuid, dbpool, &uuid, message.system, &question, apikey)
            .await
            .map_err(|_e| {
                debug_eprintln!("converse_palm error: {:#?}", _e);
                ChatproxyError::Message("PaLM Did not return a response".into())
            })?,
        _ => "Unknown Provider".to_string(),
    };
    let b = make_response(&answer, &uuid);
    Ok(b)
}

async fn do_image(data: bytes::Bytes, dbpool: &SqlitePool) -> Result<Blob, ChatproxyError> {
    let mut reader = BytesReader::from_bytes(&data);
    let request = image::request::from_reader(&mut reader, &data)
        .map_err(|e| ChatproxyError::Message(e.to_string()))?;
    let (huuid, _keyid) = if let Some(ref token) = request.token {
        parse_token(token).map_err(|e| ChatproxyError::Message(e.to_string()))?
    } else {
        return Err(ChatproxyError::Message("Invalid Auth Token".to_string()));
    };
    let ownkey: bool = request.apikey.is_some();
    debug_eprintln!("huuid = {}, ownkey = {}", huuid, ownkey);
    let retval = match request.operation {
        image::mod_request::OperationType::CREATE => do_create_image(&request).await,
        image::mod_request::OperationType::EDIT => do_edit_image(request.clone()).await,
    };
    record_usage(&huuid, 1, dbpool, "dalle", ownkey)
        .await
        .map_err(|e| ChatproxyError::Message(e.to_string()))?;
    retval
}

async fn do_create_image(request: &image::request<'_>) -> Result<Blob, ChatproxyError> {
    let prompt = if let Some(ref prompt) = request.prompt {
        prompt
    } else {
        return Err(ChatproxyError::Message("No Prompt Supplied".to_string()));
    };
    let apikey = request.apikey.clone().filter(|apikey| !apikey.is_empty());
    let apikey_to_use = if let Some(ap) = apikey {
        ap.into_owned()
    } else {
        CONFIG.chatgpt_apikey.clone()
    };
    let size = if let Some(ref size) = request.size {
        size
    } else {
        return Err(ChatproxyError::Message("Must provide size!".to_string()));
    };
    let size = match size {
        Cow::Borrowed("256x256") => "256x256",
        Cow::Borrowed("512x512") => "512x512",
        Cow::Borrowed("1024x1024") => "1024x1024",
        Cow::Borrowed("256") => "256x256",
        Cow::Borrowed("512") => "512x512",
        Cow::Borrowed("1024") => "1024x1024",
        _ => {
            return Err(ChatproxyError::Message(
                "Size must be one of 256, 512, 1024, 256x256, 512x512 or 1024x1024.".to_string(),
            ));
        }
    };
    let image = dallelib::createimage(prompt, size, &apikey_to_use)
        .await
        .map_err(|e| ChatproxyError::Message(e.to_string()))?;
    let response = image::response {
        image: Some(image.into()),
        ..Default::default()
    };
    let wsize = response.get_size();
    let mut out = Vec::with_capacity(wsize + 1);
    let mut writer = Writer::new(&mut out);
    writer
        .write_message(&response)
        .map_err(|e| ChatproxyError::Message(e.to_string()))?;
    let b = Blob {
        bytes: bytes::Bytes::from(trim(out)),
    };
    Ok(b)
}

async fn do_edit_image(request: image::request<'_>) -> Result<Blob, ChatproxyError> {
    let prompt = if let Some(ref prompt) = request.prompt {
        prompt
    } else {
        return Err(ChatproxyError::Message("No Prompt Supplied".to_string()));
    };
    let request = request.clone();
    let apikey = request.apikey.clone().filter(|apikey| !apikey.is_empty());
    let apikey_to_use = if let Some(ap) = apikey {
        ap.into_owned()
    } else {
        CONFIG.chatgpt_apikey.clone()
    };
    let size = if let Some(ref size) = request.size {
        size
    } else {
        return Err(ChatproxyError::Message("Must provide size!".to_string()));
    };
    let size = match size.clone() {
        Cow::Borrowed("256x256") => "256x256",
        Cow::Borrowed("512x512") => "512x512",
        Cow::Borrowed("1024x1024") => "1024x1024",
        Cow::Borrowed("256") => "256x256",
        Cow::Borrowed("512") => "512x512",
        Cow::Borrowed("1024") => "1024x1024",
        _ => {
            return Err(ChatproxyError::Message(
                "Size must be one of 256, 512, 1024, 256x256, 512x512 or 1024x1024.".to_string(),
            ));
        }
    };
    let image = dallelib::editimage(prompt, size, &apikey_to_use, request.source, request.mask)
        .await
        .map_err(|e| ChatproxyError::Message(e.to_string()))?;
    let response = image::response {
        image: Some(image.into()),
        ..Default::default()
    };
    let wsize = response.get_size();
    let mut out = Vec::with_capacity(wsize + 1);
    let mut writer = Writer::new(&mut out);
    writer
        .write_message(&response)
        .map_err(|e| ChatproxyError::Message(e.to_string()))?;
    let b = Blob {
        bytes: bytes::Bytes::from(trim(out)),
    };
    Ok(b)
}

async fn converse_palm(
    huuid: &str,
    dbpool: &SqlitePool,
    uuid: &str,
    system: Option<Cow<'_, str>>,
    question: &str,
    apikey: Option<Cow<'_, str>>,
) -> Result<String, Box<dyn Error>> {
    debug_eprintln!("converse_palm: system = {:#?}, uuid = {}", system, uuid);
    let state: Option<palmlib::State> = {
        match sqlx::query("select conversation from conversation where uuid = ?")
            .bind(uuid)
            .fetch_one(dbpool)
            .await
        {
            Ok(n) => {
                let s = n.get::<String, usize>(0);
                Some(serde_json::from_str(&s)?)
            }
            Err(_) => None,
        }
    };
    let apikey_to_use = if let Some(ref ap) = apikey {
        ap.clone().into_owned()
    } else {
        CONFIG.palm_apikey.clone()
    };
    let system = system.map(|s| s.to_string());
    let answer = palmlib::converse(question, system, &apikey_to_use, state).await?;
    sqlx::query("insert or replace into conversation (uuid, conversation, timestamp) values (?, ?, datetime())")
        .bind(uuid)
        .bind(serde_json::to_string(&answer.state)?)
        .execute(dbpool).await?;
    record_usage(huuid, 1, dbpool, "palm", apikey.is_some()).await?;
    Ok(answer.answer)
}

async fn converse_chatgpt<'a>(
    huuid: &str,
    dbpool: &SqlitePool,
    uuid: &str,
    system: Option<Cow<'_, str>>,
    question: &str,
    apikey: Option<Cow<'_, str>>,
    model: &str,
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
        CONFIG.chatgpt_apikey.clone()
    };
    let client = Client::new().with_api_key(&apikey_to_use);
    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model(model)
        .user(huuid)
        .messages(messages)
        .build()?;

    debug_eprintln!("Request = {:#?}", request);
    let response = client.chat().create(request).await?;
    let mut retval = "Unkonwn".to_string();
    let usage = if let Some(ref u) = response.usage {
        u.total_tokens
    } else {
        0
    };
    record_usage(huuid, usage, dbpool, "chatgpt", apikey.is_some()).await?;
    if apikey.is_none() && CONFIG.chatgpt_use_limits {
        update_limit(huuid, usage.try_into().unwrap(), dbpool, "chatgpt", &CONFIG).await
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

fn parse_token(token: &dyn Token) -> Result<(String, u64), Box<dyn Error>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let keyid = token.get_keyid();
    let hmac_key = match &CONFIG.hmac_keys.get(&keyid.to_string()) {
        Some(n) => <&String>::clone(n),
        None => {
            return Err(Box::<dyn Error>::from("Unknown KeyId"));
        }
    };

    let mut hmac = HmacSha256::new_from_slice(hmac_key.as_bytes()).expect("Invalid Key Length");
    let unsignedbytes = match token.get_unsigned() {
        Some(stuff) => stuff,
        None => {
            return Err(Box::<dyn Error>::from("Invalid Token"));
        }
    };
    let signature = match token.get_signature() {
        Some(stuff) => stuff,
        None => {
            return Err(Box::<dyn Error>::from("Invalid Token"));
        }
    };
    hmac.update(&unsignedbytes);
    match hmac.verify_slice(&signature) {
        Ok(v) => v,
        Err(_e) => {
            return Err(Box::<dyn Error>::from("signature did not match"));
        }
    };
    let mut reader = BytesReader::from_bytes(&unsignedbytes);
    let inner = chat::unsigned::from_reader(&mut reader, &unsignedbytes)?;
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
            ChatproxyError::UnknownProvider => {
                let text = "Unknown Provider".to_string();
                return Ok(warp::reply::with_status(text, StatusCode::BAD_REQUEST));
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
    sqlx::query("create table if not exists whitelist (uuid text, provider text)")
        .execute(&dbpool)
        .await?;
    sqlx::query("create unique index if not exists whitelist_u_p on whitelist(uuid, provider)")
        .execute(&dbpool)
        .await?;
    sqlx::query("create table if not exists usage (huuid text, usage integer, provider text, ownkey boolean)")
        .execute(&dbpool)
        .await?;
    sqlx::query("create unique index if not exists usage_u_p on usage(huuid, provider, ownkey)")
        .execute(&dbpool)
        .await?;
    sqlx::query(
        "create table if not exists limits (huuid text, usage integer, quota integer, timestamp timestamp, provider)",
    )
    .execute(&dbpool)
    .await?;
    sqlx::query("create unique index if not exists limits_u_p on limits (huuid, provider)")
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

async fn on_whitelist(uuid: &str, dbpool: &SqlitePool, provider: &str) -> bool {
    match sqlx::query("select * from whitelist where uuid = ? and provider = ?")
        .bind(uuid)
        .bind(provider)
        .fetch_one(dbpool)
        .await
    {
        Ok(_) => true,
        Err(_e) => {
            debug_eprintln!("on_whitelist: {:#?}", _e);
            false
        }
    }
}

async fn record_usage(
    huuid: &str,
    usage: u32,
    dbpool: &SqlitePool,
    provider: &str,
    ownkey: bool,
) -> Result<(), Box<dyn Error>> {
    let prior_usage =
        match sqlx::query("select usage from usage where huuid = ? and provider = ?, ownkey = ?")
            .bind(huuid)
            .bind(provider)
            .bind(ownkey)
            .fetch_one(dbpool)
            .await
        {
            Ok(row) => row.get::<u32, usize>(0),
            Err(_) => 0,
        };
    let usage = usage + prior_usage;
    sqlx::query("insert or replace into usage values (?, ?, ?, ?)")
        .bind(huuid)
        .bind(usage)
        .bind(provider)
        .bind(ownkey)
        .execute(dbpool)
        .await?;
    Ok(())
}

async fn update_limit(huuid: &str, usage: i32, dbpool: &SqlitePool, provider: &str, conf: &Config) {
    debug_eprintln!("update_limit: entered");
    let mut transaction = dbpool.begin().await.unwrap();
    let (old_usage, quota, ts) = match sqlx::query(
        "select usage, quota, timestamp from limits where huuid = ? and provider = ?",
    )
    .bind(huuid)
    .bind(provider)
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
    sqlx::query("insert or replace into limits (huuid, usage, quota, timestamp, provider) values (?, ?, ?, ?, ?)")
        .bind(huuid)
        .bind(usage)
        .bind(quota)
        .bind(ts)
        .bind(provider)
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

async fn check_limit(
    huuid: &str,
    dbpool: &SqlitePool,
    provider: &str,
) -> Result<bool, Box<dyn Error>> {
    let utime = get_unix_now()?;
    let (usage, quota, their_time) = match sqlx::query(
        "select usage, quota, timestamp from limits where huuid = ? and provider = ?",
    )
    .bind(huuid)
    .bind(provider)
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
    match sqlx::query("insert or replace into limits (huuid, usage, quota, timestamp, provider) values (?, ?, ?, ?, ?)")
        .bind(huuid)
        .bind(r)
        .bind(quota)
        .bind(utime)
        .bind(provider)
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
                hmac_keys: BTreeMap::from([
                    ("0".into(), "changeme!".into()),
                    ("1".into(), "change or delete me!".into()),
                ]),
                chatgpt_apikey: String::from("sk-key-here"),
                default_quota: 10000,
                chatgpt_use_allowlist: true,
                chatgpt_use_limits: true,
                palm_apikey: "none".to_string(),
                palm_use_allowlist: true,
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
        update_limit("12345", 10000, &dbpool, "chatgpt", &conf).await;
        let now = get_unix_now().unwrap();
        let then = now - (3600 * 12); // an hour ago
                                      // Set timestamp back an hour
        sqlx::query("update limits set timestamp = ? where huuid = ?")
            .bind(then)
            .bind("12345")
            .execute(&dbpool)
            .await
            .unwrap();
        let v = check_limit("12345", &dbpool, "chatgpt").await.unwrap();
        debug_eprintln!("v = {}", v);
        assert!(v);
    }
}
