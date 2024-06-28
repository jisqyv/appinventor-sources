#[macro_use]
extern crate lazy_static;
use base64::prelude::*;
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use std::collections::BTreeMap;
use std::convert::{From, Infallible};
use std::fmt;
use std::fmt::Debug;
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
    config::OpenAIConfig,
    types::{
        ChatCompletionRequestAssistantMessage, ChatCompletionRequestMessage,
        ChatCompletionRequestMessageContentPart, ChatCompletionRequestMessageContentPartImage,
        ChatCompletionRequestSystemMessage, ChatCompletionRequestUserMessage,
        ChatCompletionRequestUserMessageContent, CreateChatCompletionRequestArgs,
        CreateModerationRequest, Role as ChatGPTRole,
    },
    Client,
};
use debug_print::debug_eprintln;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::error::Error;

use crate::anthropic::AnthropicConversation;
use crate::titan::TitanConversation;

const SECS_PER_DAY: i32 = 86400;

mod anthropic;
mod chat;
mod dallelib;
mod geminilib;
mod image;
mod palmlib;
mod titan;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    port: u16,
    nthreads: usize,
    dbfile: String,
    hmac_keys: BTreeMap<String, String>,
    chatgpt_apikey: String,
    chatgpt_use_allowlist: bool,
    palm_apikey: String,
    palm_use_allowlist: bool,
    aws_access_key: String,
    aws_access_secret: String,
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
            chatgpt_use_allowlist: true,
            palm_apikey: String::from("key-here"),
            palm_use_allowlist: true,
            aws_access_key: String::from("aws-access-key-here"),
            aws_access_secret: String::from("aws-access-secret-here"),
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
            nthreads: 1, // Just the current thread
            dbfile: String::from("/ram/dbfile.sqlite"),
            hmac_keys: BTreeMap::from([
                ("0".into(), "changeme!".into()),
                ("1".into(), "change or delete me!".into()),
            ]),
            chatgpt_apikey: String::from("sk-key-here"),
            chatgpt_use_allowlist: true,
            palm_apikey: String::from("key-here"),
            palm_use_allowlist: true,
            aws_access_key: String::from("aws-access-key-here"),
            aws_access_secret: String::from("aws-access-secret-here"),
        }
    }
}

trait Token<'a> {
    fn get_unsigned(&self) -> Option<Cow<'a, [u8]>>;
    fn get_signature(&self) -> Option<Cow<'a, [u8]>>;
    fn get_keyid(&self) -> u64;
    fn display(&self) -> String;
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
    fn display(&self) -> String {
        format!("{:#?}", self)
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
    fn display(&self) -> String {
        format!("{:#?}", self)
    }
}

pub trait Converse {
    fn create_body(&self) -> String;
    fn prepare(&self) -> String;
    fn push(&mut self, role: Role, text: String);
    fn serialize(&self) -> Result<String, Box<dyn Error>>;
    fn parse_response(&self, response: &str) -> Result<String, Box<dyn Error>>;
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum Role {
    Human,
    Assistant,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
enum AmazonFlavor {
    Anthropic,
    Titan,
}

#[cfg(test)]
lazy_static! {
    static ref CONFIG: Config = Config::test();
}

#[cfg(not(test))]
lazy_static! {
    static ref CONFIG: Config = {
        let args = Cli::from_args();
        confy::load_path(args.config_file).unwrap()
    };
}

lazy_static! {
    static ref RT: runtime::Runtime = match CONFIG.nthreads {
        1 => runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
        0 => runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap(),
        n => runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(n)
            .build()
            .unwrap(),
    };
    static ref DBPOOL: SqlitePool = {
        RT.handle()
            .block_on(async { setup(&CONFIG).await.unwrap() })
    };
    static ref CHATGPT_DEFAULT_QUOTA: i32 = RT.block_on(async {
        let (_, quota) = get_defaults(&DBPOOL).await;
        quota
    });
    static ref CHATGPT_USE_LIMITS: bool = RT.block_on(async {
        let (limits, _) = get_defaults(&DBPOOL).await;
        limits
    });
}

use aws_credential_types::Credentials;

fn aws_credentials_provider() -> Credentials {
    Credentials::new(
        &CONFIG.aws_access_key,
        &CONFIG.aws_access_secret,
        None,
        None,
        "toml_access_provider",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChatproxyError {
    Message(String),
    Unauthorized,
    UnknownProvider,
    OverQuota,
    UseOwnKey,
    Blocked,
    UnsupportedImageFormat,
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
            ChatproxyError::UseOwnKey => {
                write!(f, "You need to use your own ApiKey, see https://appinv.us/ownkey for more information").ok();
            }
            ChatproxyError::Blocked => {
                write!(f, "Your request was flagged by the moderation system").ok();
            }
            ChatproxyError::UnsupportedImageFormat => {
                write!(f, "Unsupported Image Format, use jpeg, gif or png").ok();
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Pair {
    role: ChatGPTRole,
    text: String,
    #[serde(default)]
    image: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Conversation {
    uuid: String,
    content: Vec<Pair>,
    multiplier: u32, // Cost multiplier, usage = tokens X multiplier
    #[serde(default)]
    model: String,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "chat", about = "Interact with ChatGPT")]
struct Cli {
    /// Config FIle
    config_file: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    // The lines below causes the lazy_static macro (above) to be
    // called It is important that we do this here before we create
    // our main tokio runtime, because the lazy_static block also
    // creates a runtime, and you cannot create and run a runtime
    // inside a runtime. Note: You *can* create a runtime inside a
    // runtime, but you cannot call its block_on method!
    let _ = DBPOOL.clone();
    let _ = *CHATGPT_DEFAULT_QUOTA;
    let _ = *CHATGPT_USE_LIMITS;
    RT.block_on(async {
        let _t: Result<(), tokio::task::JoinError> = tokio::spawn(async move {
            let cdbpool = DBPOOL.clone();
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
                    let dbpool = DBPOOL.clone();
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
    let mut apikey = message.apikey.clone().filter(|apikey| !apikey.is_empty());
    let (mut huuid, _keyid) = if let Some(token) = message.token.clone() {
        parse_token(&token).map_err(|e| ChatproxyError::Message(e.to_string()))?
    } else {
        return Err(ChatproxyError::Message("Invalid Auth Token".to_string()));
    };
    let mut default_quota = *CHATGPT_DEFAULT_QUOTA;
    // The code below is a bit of a kludge. If an apikey is 10 characters or shorter,
    // we assume that it is an MIT issued key. If so, we set apikey to None, because
    // we want to use the configured MIT api key. We then set huuid to the MIT issued
    // api key. We then set default_quota = -1.
    //
    // MIT official keys have a quota already defined in the limits table. If someone
    // provides a short api key which we do not already have an entry in the limits
    // table, the default quota of -1 will cause them to get an error.
    if let Some(ref ap) = apikey {
        if ap.len() <= 10 {
            debug_eprintln!("Found short apikey = {}", ap);
            huuid = ap.to_lowercase();
            let retval = getapikey(dbpool, &*message.provider.clone(), ap).await;
            if let Some(r) = retval {
                apikey = Some(Cow::Owned(r));
            } else {
                apikey = None
            }
            default_quota = -1;
        }
    }

    debug_eprintln!("huuid = {}", huuid);
    let provider = message.provider.clone();
    if apikey.is_none() {
        match &*provider {
            "chatgpt" => {
                if CONFIG.chatgpt_use_allowlist && !on_whitelist(&huuid, dbpool, &provider).await {
                    println!("Rejecting Request from {}, not on whitelist.", huuid);
                    return Err(ChatproxyError::Unauthorized);
                }
                if *CHATGPT_USE_LIMITS
                    && !check_limit(&huuid, dbpool, &provider, default_quota)
                        .await
                        .map_err(|e| match *e.downcast().unwrap() {
                            ChatproxyError::UseOwnKey => ChatproxyError::UseOwnKey,
                            _ => ChatproxyError::OverQuota,
                        })?
                {
                    return Err(ChatproxyError::OverQuota);
                }
            }
            "palm" | "gemini" => {
                if CONFIG.palm_use_allowlist && !on_whitelist(&huuid, dbpool, &provider).await {
                    println!(
                        "PaLM: Rejecting Request from {}, not on whitelist provider = {}",
                        huuid, provider
                    );
                    return Err(ChatproxyError::Unauthorized);
                }
            }
            "bedrock" => (),
            _ => {
                return Err(ChatproxyError::UnknownProvider);
            }
        }
    }
    let uuid = match message.uuid.clone() {
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
    let mut model = if let Some(ref m) = message.model {
        m
    } else {
        ""
    };
    match &*provider {
        "chatgpt" => {
            if apikey.is_none() {
                match model {
                    "" => {
                        if message.inputimage.is_some() {
                            model = "gpt-4-vision-preview";
                        } else {
                            model = "gpt-3.5-turbo";
                        };
                    }
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
            } else if model.is_empty() {
                if message.inputimage.is_some() {
                    model = "gpt-4-vision-preview";
                } else {
                    model = "gpt-3.5-turbo";
                };
            }
        }
        "bedrock" => match model {
            "" => {
                model = "anthropic.claude-v2";
            }
            "anthropic.claude-v2" => (),
            "anthropic.claude-v1" => (),
            _ => (),
            // _ => {
            //     return Err(ChatproxyError::Message(format!(
            //         "Unsupported Model {}",
            //         model
            //     )));
            // }
        },
        _ => (),
    }
    let question = if let Some(q) = message.question.clone() {
        q
    } else {
        return Err(ChatproxyError::Message("Must Ask a Question".to_string()));
    };
    if moderate_chatgpt(&question)
        .await
        .map_err(|e| ChatproxyError::Message(e.to_string()))?
    {
        return Err(ChatproxyError::Blocked);
    }
    debug_eprintln!("Using APIKEY {:#?} for {}", apikey, provider);
    let answer = match &*provider {
        "chatgpt" => converse_chatgpt(&huuid, dbpool, &uuid, &message, apikey, model)
            .await
            .map_err(|e| {
                debug_eprintln!("converse_chatgpt error: {:#?}", e);
                ChatproxyError::Message(e.to_string())
            })?,
        "palm" => converse_palm(&huuid, dbpool, &uuid, message.system, &question, apikey)
            .await
            .map_err(|e| {
                debug_eprintln!("converse_palm error: {:#?}", e);
                ChatproxyError::Message(format!("PaLM Did not return a response: {}", e))
            })?,
        "gemini" => converse_gemini(&huuid, dbpool, &uuid, &message, apikey)
            .await
            .map_err(|e| {
                debug_eprintln!("converse_gemini error: {:#?}", e);
                ChatproxyError::Message(format!("Gemini Did not return a response: {}", e))
            })?,
        "bedrock" => converse_bedrock(&huuid, dbpool, &uuid, model, &question)
            .await
            .map_err(|_e| {
                eprintln!("converse_bedrock: error: {:#?}", _e);
                ChatproxyError::Message("Bedrock Did not return a response".into())
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
    let mut apikey = request.apikey.clone().filter(|apikey| !apikey.is_empty());
    let (mut huuid, _keyid) = if let Some(ref token) = request.token {
        parse_token(token).map_err(|e| ChatproxyError::Message(e.to_string()))?
    } else {
        return Err(ChatproxyError::Message("Invalid Auth Token".to_string()));
    };
    let mut default_quota = *CHATGPT_DEFAULT_QUOTA;
    // Support MIT issued api keys, see comment in do_chat()
    if let Some(ref ap) = apikey {
        if ap.len() <= 10 {
            debug_eprintln!("Found short apikey = {}", ap);
            huuid = ap.to_lowercase();
            let retval = getapikey(dbpool, "dalle", ap).await;
            if let Some(r) = retval {
                apikey = Some(Cow::Owned(r));
            } else {
                apikey = None
            }
            default_quota = -1;
        }
    }
    let ownkey: bool = apikey.is_some();
    debug_eprintln!("huuid = {}, ownkey = {}", huuid, ownkey);
    if !ownkey {
        // not own key, implement quota
        if *CHATGPT_USE_LIMITS
            && !check_limit(&huuid, dbpool, "dalle", default_quota)
                .await
                .map_err(|e| match *e.downcast().unwrap() {
                    ChatproxyError::UseOwnKey => ChatproxyError::UseOwnKey,
                    _ => ChatproxyError::OverQuota,
                })?
        {
            return Err(ChatproxyError::OverQuota);
        }
    }
    let retval = match request.operation {
        image::mod_request::OperationType::CREATE => do_create_image(&request, apikey).await,
        image::mod_request::OperationType::EDIT => do_edit_image(request.clone(), apikey).await,
    };
    if !ownkey && *CHATGPT_USE_LIMITS {
        update_limit(&huuid, 2000, dbpool, "dalle").await
    }
    record_usage(&huuid, 1, dbpool, "dalle", ownkey)
        .await
        .map_err(|e| ChatproxyError::Message(e.to_string()))?;
    retval
}

async fn do_create_image<'a>(
    request: &image::request<'_>,
    apikey: Option<Cow<'a, str>>,
) -> Result<Blob, ChatproxyError> {
    let prompt = if let Some(ref prompt) = request.prompt {
        prompt
    } else {
        return Err(ChatproxyError::Message("No Prompt Supplied".to_string()));
    };
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

async fn do_edit_image<'a>(
    request: image::request<'_>,
    apikey: Option<Cow<'a, str>>,
) -> Result<Blob, ChatproxyError> {
    let prompt = if let Some(ref prompt) = request.prompt {
        prompt
    } else {
        return Err(ChatproxyError::Message("No Prompt Supplied".to_string()));
    };
    let request = request.clone();
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
        if let Some(conversation_str) = get_conversation(uuid, "palm", dbpool).await {
            Some(serde_json::from_str(&conversation_str)?)
        } else {
            None
        }
    };
    let apikey_to_use = if let Some(ref ap) = apikey {
        ap.clone().into_owned()
    } else {
        CONFIG.palm_apikey.clone()
    };
    let system = system.map(|s| s.to_string());
    let answer = palmlib::converse(question, system, &apikey_to_use, state).await?;
    store_conversation(uuid, "palm", dbpool, &serde_json::to_string(&answer.state)?).await?;
    record_usage(huuid, 1, dbpool, "palm", apikey.is_some()).await?;
    Ok(answer.answer)
}

async fn converse_chatgpt<'a>(
    huuid: &str,
    dbpool: &SqlitePool,
    uuid: &str,
    message: &chat::request<'_>,
    apikey: Option<Cow<'_, str>>,
    model: &str,
) -> Result<String, Box<dyn Error>> {
    let inputimage = &message.inputimage;
    let system = &message.system;
    let question = match message.question.clone() {
        None => {
            return Err(Box::new(ChatproxyError::Message(
                "Must Ask a Question".to_string(),
            )));
        }
        Some(q) => q,
    };
    let mut conversation: Conversation =
        if let Some(conversation_str) = get_conversation(uuid, "chatgpt", dbpool).await {
            serde_json::from_str(&conversation_str)?
        } else {
            Conversation {
                uuid: uuid.to_string(),
                content: vec![Pair {
                    role: ChatGPTRole::System,
                    text: if let Some(s) = system {
                        s.to_string()
                    } else {
                        "".to_string()
                    },
                    image: None,
                }],
                multiplier: 1,
                model: model.to_string(),
            }
        };
    if message.inputimage.is_some() {
        conversation.multiplier = 20;
        if conversation.model == "gpt-3.5-turbo" {
            //  This is a kludge!
            conversation.model = "gpt-4-vision-preview".to_string();
        }
    }
    conversation.content.push(Pair {
        role: ChatGPTRole::User,
        text: question.to_string(),
        image: inputimage
            .clone()
            .as_ref()
            .map(|image| -> Result<String, Box<dyn Error>> { get_image_url(image) })
            .transpose()?,
    });
    let messages = conversation
        .content
        .iter()
        .map(|v| match v.role {
            ChatGPTRole::User => {
                if let Some(image) = v.image.clone() {
                    let imagepart = ChatCompletionRequestMessageContentPartImage {
                        image_url: image.into(),
                        r#type: "image_url".to_string(),
                    };
                    let part = ChatCompletionRequestMessageContentPart::Image(imagepart);
                    let text = ChatCompletionRequestMessageContentPart::Text(v.text.clone().into());
                    let content = ChatCompletionRequestUserMessageContent::Array(vec![text, part]);
                    ChatCompletionRequestMessage::from(ChatCompletionRequestUserMessage {
                        content,
                        role: ChatGPTRole::User,
                        name: None,
                    })
                } else {
                    ChatCompletionRequestMessage::from(ChatCompletionRequestUserMessage {
                        content: ChatCompletionRequestUserMessageContent::Text(v.text.clone()),
                        role: ChatGPTRole::User,
                        name: None,
                    })
                }
            }
            ChatGPTRole::Assistant => {
                ChatCompletionRequestMessage::from(ChatCompletionRequestAssistantMessage {
                    content: Some(v.text.clone()),
                    role: ChatGPTRole::Assistant,
                    ..Default::default()
                })
            }
            ChatGPTRole::System => {
                ChatCompletionRequestMessage::from(ChatCompletionRequestSystemMessage {
                    content: v.text.clone(),
                    role: ChatGPTRole::System,
                    name: None,
                })
            }
            _ => {
                debug_eprintln!("Result = {:#?}", v);
                todo!()
            }
        })
        .collect::<Vec<ChatCompletionRequestMessage>>();

    let apikey_to_use = if let Some(apikey) = apikey.clone() {
        apikey.into_owned()
    } else {
        CONFIG.chatgpt_apikey.clone()
    };
    let config = OpenAIConfig::new().with_api_key(&apikey_to_use);
    let client = Client::with_config(config);
    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model(&conversation.model)
        .user(huuid)
        .messages(messages)
        .build()?;

    debug_eprintln!("Request = {:#?}", request);
    let response = client.chat().create(request).await?;
    let mut retval = "Unkonwn".to_string();
    let usage = if let Some(ref u) = response.usage {
        u.total_tokens * conversation.multiplier
    } else {
        0
    };
    debug_eprintln!("Usage = {} Multiplier = {}", usage, conversation.multiplier);
    record_usage(huuid, usage, dbpool, "chatgpt", apikey.is_some()).await?;
    if apikey.is_none() && *CHATGPT_USE_LIMITS {
        update_limit(huuid, usage.try_into().unwrap(), dbpool, "chatgpt").await
    }
    for choice in response.choices {
        if choice.message.role == ChatGPTRole::Assistant {
            if let Some(text) = choice.message.content {
                retval = text.clone();
            } else {
                retval = "NO RESPONSE".to_string();
            };
        };
        conversation.content.push(Pair {
            role: choice.message.role,
            text: retval.clone(),
            image: None,
        });
    }
    store_conversation(
        uuid,
        "chatgpt",
        dbpool,
        &serde_json::to_string(&conversation)?,
    )
    .await?;
    Ok(retval)
}

fn get_amazon_flavor(model: &str) -> Result<AmazonFlavor, Box<dyn Error>> {
    let mut z = model.split('.');
    match z.next() {
        Some("anthropic") => Ok(AmazonFlavor::Anthropic),
        Some("amazon") => Ok(AmazonFlavor::Titan),
        _ => Err(Box::<dyn Error>::from("Unknown Amazon Model")),
    }
}

// AWS models
async fn converse_bedrock(
    huuid: &str,
    dbpool: &SqlitePool,
    uuid: &str,
    model: &str,
    question: &str,
) -> Result<String, Box<dyn Error>> {
    use aws_sdk_bedrockruntime::primitives::Blob;

    let flavor = get_amazon_flavor(model)?;
    let ctag = format!("bedrock-{}", model);
    let mut conversation: Box<dyn Converse + Send> = match flavor {
        AmazonFlavor::Anthropic => {
            if let Some(conversation_str) = get_conversation(uuid, &ctag, dbpool).await {
                AnthropicConversation::load(&conversation_str)?
            } else {
                AnthropicConversation::initial()
            }
        }
        AmazonFlavor::Titan => {
            if let Some(conversation_str) = get_conversation(uuid, &ctag, dbpool).await {
                TitanConversation::load(&conversation_str)?
            } else {
                TitanConversation::initial()
            }
        }
    };
    conversation.push(Role::Human, question.to_string());
    let config = aws_config::from_env()
        .credentials_provider(aws_credentials_provider())
        .region(aws_types::region::Region::new("us-east-1"))
        .load()
        .await;
    let client = aws_sdk_bedrockruntime::Client::new(&config);
    let prompt = conversation.prepare();
    debug_eprintln!("converse_bedrock: prompt = {},", prompt);
    let body = conversation.create_body();
    debug_eprintln!("converse_bedrock: body = {:#?}", body);
    let body = Blob::new(body);
    let fluent_builder = client
        .invoke_model()
        .body(body)
        .model_id(model)
        .content_type("application/json");
    let result = fluent_builder.send().await?;
    if let Some(body) = result.body() {
        let inner = body.clone().into_inner();
        let response = String::from_utf8(inner)?;
        debug_eprintln!("raw response = {}", response);
        let answer = conversation.parse_response(&response)?;
        debug_eprintln!("answer = {}", answer);
        let word_count = answer.split(' ').collect::<Vec<_>>().len();
        record_usage(huuid, word_count as u32, dbpool, &ctag, false)
            .await
            .ok();
        conversation.push(Role::Assistant, answer.clone());
        let conversation_str = conversation.serialize()?;
        store_conversation(uuid, &ctag, dbpool, &conversation_str).await?;
        Ok(answer)
    } else {
        Ok("DID NOT GET ANSWER".to_string())
    }
}

async fn converse_gemini(
    huuid: &str,
    dbpool: &SqlitePool,
    uuid: &str,
    message: &chat::request<'_>,
    apikey: Option<Cow<'_, str>>,
) -> Result<String, Box<dyn Error>> {
    let state: Option<geminilib::State> = {
        if let Some(conversation_str) = get_conversation(uuid, "gemini", dbpool).await {
            Some(serde_json::from_str(&conversation_str)?)
        } else {
            None
        }
    };
    let apikey_to_use = if let Some(ref ap) = apikey {
        ap.clone().into_owned()
    } else {
        CONFIG.palm_apikey.clone()
    };
    let answer = geminilib::converse(message, &apikey_to_use, state).await?;
    store_conversation(
        uuid,
        "gemini",
        dbpool,
        &serde_json::to_string(&answer.state)?,
    )
    .await?;
    record_usage(huuid, 1, dbpool, "gemini", message.apikey.is_some()).await?;
    Ok(answer.answer)
}

fn parse_token(token: &dyn Token) -> Result<(String, u64), Box<dyn Error>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    // debug_eprintln!("token = {}", token.display());
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

async fn moderate_chatgpt(question: &str) -> Result<bool, Box<dyn Error>> {
    let config = OpenAIConfig::new().with_api_key(&CONFIG.chatgpt_apikey);
    let client = Client::with_config(config);

    let request = CreateModerationRequest {
        input: question.into(),
        ..Default::default()
    };
    let response = client.moderations().create(request).await?;
    debug_eprintln!("Moderation Response: {:#?}", response);
    for result in response.results {
        if result.flagged {
            return Ok(true);
        }
    }
    Ok(false)
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
                let text = "You have exceeded your free usage today, more information at https://appinv.us/ownkey".to_string();
                return Ok(warp::reply::with_status(
                    text,
                    StatusCode::TOO_MANY_REQUESTS,
                ));
            }
            ChatproxyError::UnknownProvider => {
                let text = "Unknown Provider".to_string();
                return Ok(warp::reply::with_status(text, StatusCode::BAD_REQUEST));
            }
            ChatproxyError::UseOwnKey => {
                let text =
                    "You need to use your own ApiKey, more information at https://appinv.us/ownkey"
                        .to_string();
                return Ok(warp::reply::with_status(text, StatusCode::BAD_REQUEST));
            }
            ChatproxyError::Blocked => {
                return Ok(warp::reply::with_status(
                    ChatproxyError::Blocked.to_string(),
                    StatusCode::FORBIDDEN,
                ));
            }
            ChatproxyError::UnsupportedImageFormat => {
                return Ok(warp::reply::with_status(
                    ChatproxyError::UnsupportedImageFormat.to_string(),
                    StatusCode::BAD_REQUEST,
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
        "create table if not exists conversation (uuid text primary key, provider text, conversation blob, timestamp timestamp)",
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
    sqlx::query("create table if not exists config (name text, value)")
        .execute(&dbpool)
        .await?;
    sqlx::query(
        "create table if not exists apikeylist (shortapi text, provider text, apikey text)",
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
    let prior_usage = match sqlx::query(
        "select usage from usage where huuid = ? and provider = ? and  ownkey = ?",
    )
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

async fn update_limit(huuid: &str, usage: i32, dbpool: &SqlitePool, provider: &str) {
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
            (0, *CHATGPT_DEFAULT_QUOTA, utime)
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

async fn get_conversation(uuid: &str, provider: &str, dbpool: &SqlitePool) -> Option<String> {
    match sqlx::query("select conversation, provider  from conversation where uuid = ?")
        .bind(uuid)
        .fetch_one(dbpool)
        .await
    {
        Ok(n) => {
            let conversation_provider = n.get::<String, usize>(1);
            if conversation_provider == provider {
                Some(n.get::<String, usize>(0))
            } else {
                None // We switched provider!
            }
        }
        Err(_) => None,
    }
}

async fn store_conversation(
    uuid: &str,
    provider: &str,
    dbpool: &SqlitePool,
    value: &str,
) -> Result<(), Box<dyn Error>> {
    sqlx::query("insert or replace into conversation (uuid, conversation, provider, timestamp) values (?, ?, ?, datetime())")
        .bind(uuid)
        .bind(value)
        .bind(provider)
        .execute(dbpool)
        .await?;
    Ok(())
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
    default_quota: i32,
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
        Err(_) => (0, default_quota, utime),
    };
    // A quota of 0 means infinite!
    if quota == 0 {
        return Ok(true);
    }
    // If quota == -1, then tell them to use their own key
    if quota == -1 {
        return Err(ChatproxyError::UseOwnKey.into());
    }

    let r = {
        if their_time == 0 {
            usage // So we can initialize limits entries with a zero timestamp
        } else {
            let passed: i64 = utime - their_time;
            let v: i32 = (quota * passed as i32) / SECS_PER_DAY;
            let r = usage - v;
            if r < 0 {
                0
            } else {
                r
            }
        }
    };

    debug_eprintln!("check_limit: r = {}", r);

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

fn get_image_url(image: &[u8]) -> Result<String, Box<dyn Error>> {
    let tag = imghdr::from_bytes(image);
    let tag = match tag {
        Some(imghdr::Type::Gif) => "gif",
        Some(imghdr::Type::Jpeg) => "jpeg",
        Some(imghdr::Type::Png) => "png",
        _ => {
            return Err(Box::new(ChatproxyError::UnsupportedImageFormat));
        }
    };
    Ok(format!(
        "data:image/{};base64,{}",
        tag,
        BASE64_STANDARD.encode(image)
    ))
}

async fn get_defaults(dbpool: &SqlitePool) -> (bool, i32) {
    let quota = match sqlx::query("select value from config where name = ?")
        .bind("default_quota")
        .fetch_one(dbpool)
        .await
    {
        Ok(row) => row.get::<i32, usize>(0),
        Err(_) => 10000,
    };
    let use_limits = match sqlx::query("select value from config where name = ?")
        .bind("use_limits")
        .fetch_one(dbpool)
        .await
    {
        Ok(row) => row.get::<bool, usize>(0),
        Err(_) => true,
    };
    (use_limits, quota)
}

/// Given a "short" API Key (the kind we issue) Check to see if there is a specific
/// provider API key to use for this "short" key. If so, return it. Otherwise return
/// None
async fn getapikey(dbpool: &SqlitePool, provider: &str, inapi: &str) -> Option<String> {
    match sqlx::query("select apikey from apikeylist where shortapi = ? and provider = ?")
        .bind(inapi)
        .bind(provider)
        .fetch_one(dbpool)
        .await
    {
        Ok(row) => Some(row.get::<String, usize>(0)),
        Err(_) => None,
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
                chatgpt_use_allowlist: true,
                palm_apikey: "none".to_string(),
                palm_use_allowlist: true,
                aws_access_key: String::from("aws-access-key-here"),
                aws_access_secret: String::from("aws-access-secret-here"),
            }
        }
    }

    #[test]
    fn verify_limits() {
        fs::remove_file(&CONFIG.dbfile).ok();
        fs::remove_file(format!("{}-wal", &CONFIG.dbfile)).ok();
        fs::remove_file(format!("{}-shm", &CONFIG.dbfile)).ok();
        let _ = DBPOOL.clone(); // Make sure it is setup before we call block_on
                                // otherwise we wind up calling block_on recursively, which is not permitted
        let _ = *CHATGPT_DEFAULT_QUOTA;
        RT.block_on(async {
            debug_eprintln!("verify_limits");
            debug_eprintln!("dbfile = {}", &CONFIG.dbfile);
            let dbpool = DBPOOL.clone();
            update_limit("12345", 10000, &dbpool, "chatgpt").await;
            let now = get_unix_now().unwrap();
            let then = now - (3600 * 12); // an hour ago
                                          // Set timestamp back an hour
            sqlx::query("update limits set timestamp = ? where huuid = ?")
                .bind(then)
                .bind("12345")
                .execute(&dbpool)
                .await
                .unwrap();
            let v = check_limit("12345", &dbpool, "chatgpt", *CHATGPT_DEFAULT_QUOTA)
                .await
                .unwrap();
            debug_eprintln!("v = {}", v);
            assert!(v);
        });
    }

    #[test]
    fn test_gemini_2() {
        let mut state = geminilib::State::new();
        debug_eprintln!(
            "Output = {:#?}",
            geminilib::build_gemini_prompt("Who won the World Series in 2004?", &mut state)
                .unwrap()
        );
    }
}
