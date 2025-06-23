#[macro_use]
extern crate lazy_static;
use aws_config::BehaviorVersion;
use base64::prelude::*;
use chrono::Utc;
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};
use sqlx::postgres::{PgConnectOptions, PgPool};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::convert::{From, Infallible};
use std::fmt;
use std::fmt::Debug;
use std::net::SocketAddr;
use structopt::StructOpt;
use tokio::runtime;
use uuid::Uuid;
use warp::reject::{Reject, Rejection};
use warp::reply::Response;
use warp::{Filter, Reply};

extern crate structopt;
use async_openai::{
    Client,
    config::OpenAIConfig,
    types::{
        ChatCompletionRequestAssistantMessage, ChatCompletionRequestMessage,
        ChatCompletionRequestMessageContentPart, ChatCompletionRequestMessageContentPartImage,
        ChatCompletionRequestSystemMessage, ChatCompletionRequestUserMessage,
        ChatCompletionRequestUserMessageContent, CreateChatCompletionRequestArgs,
        CreateModerationRequest, Role as ChatGPTRole,
    },
};
use debug_print::debug_eprintln;
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::anthropic::AnthropicConversation;
use crate::llama::LlamaConversation;
use crate::titan::TitanConversation;

const SECS_PER_DAY: i64 = 86400;

mod anthropic;
mod chat;
mod dallelib;
mod geminilib;
mod image;
mod llama;
mod ollamalib;
mod titan;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    port: u16,
    nthreads: usize,
    dburl: String,
    hmac_keys: BTreeMap<String, String>,
    chatgpt_apikey: String,
    chatgpt_use_allowlist: bool,
    google_apikey: String,
    aws_access_key: String,
    aws_access_secret: String,
    ollama_url: String,
}

impl ::std::default::Default for Config {
    fn default() -> Self {
        Self {
            port: 9001,
            nthreads: 0,           // Means as many as cores
            dburl: "".to_string(), // Must provide
            hmac_keys: BTreeMap::from([
                ("0".into(), "changeme!".into()),
                ("1".into(), "change or delete me!".into()),
            ]),
            chatgpt_apikey: String::from("sk-key-here"),
            chatgpt_use_allowlist: true,
            google_apikey: String::from("key-here"),
            aws_access_key: String::from("aws-access-key-here"),
            aws_access_secret: String::from("aws-access-secret-here"),
            ollama_url: String::from("http://localhost:11434/api/generate"),
        }
    }
}

trait Token<'a> {
    fn get_unsigned(&self) -> Option<Cow<'a, [u8]>>;
    fn get_signature(&self) -> Option<Cow<'a, [u8]>>;
    fn get_keyid(&self) -> u64;
    #[allow(dead_code)]
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
    fn token_count(&self, response: &str) -> Result<i32, Box<dyn Error>>;
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
    Llama,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Answer {
    answer: Option<String>, // Image only answer possible?
    image: Option<Vec<u8>>,
}

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
    static ref DBPOOL: PgPool = {
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
    NoMorePalm,
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
            ChatproxyError::NoMorePalm => {
                write!(f, "Google has shutdown PaLM").ok();
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

            let module_list =
                warp::path!("model_list" / "v1")
                    .and(warp::get())
                    .and_then(|| async move {
                        let j: JsonAnswer = JsonAnswer {
                            json: PROVIDER_MODULES,
                        };
                        Ok::<JsonAnswer, Rejection>(j)
                    });

            let health = warp::path!("health")
                .and(warp::get())
                .and_then(|| async move {
                    let h = HealthAnswer {};
                    Ok::<HealthAnswer, Rejection>(h)
                });

            let head_only = warp::head().and_then(|| async move {
                let b = Blob {
                    bytes: bytes::Bytes::from(""),
                };
                Ok::<Blob, Rejection>(b)
            });

            let routes = chatget
                .or(health)
                .or(imageget)
                .or(module_list)
                .or(head_only)
                .recover(handle_rejection);
            let server = warp::serve(routes);
            let socketaddr: SocketAddr = ([0, 0, 0, 0], CONFIG.port).into();
            let http_server = server.run(socketaddr);
            http_server.await
        })
        .await;
        Ok::<(), Box<dyn Error>>(())
    })
}

async fn do_chat(data: bytes::Bytes, dbpool: &PgPool) -> Result<Blob, ChatproxyError> {
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
    let mut provider = message.provider.as_ref();

    // 6/20/2025(jis): We are changing the default provider and model from chatgpt
    // to bedrock (llama model as of this writing). However the ChatBot component
    // always sends us a provider, the default being chatgpt.
    //
    // So. If the model is blank, *and* the user did not provide their own API KEY
    // we assume that they are just intended to use the default, and we replace
    // "chatgpt" with "bedrock" (Amazon).
    if let Some(ref ap) = apikey {
        if ap.len() <= 10 && message.model.is_none() && provider == "chatgpt" {
            provider = "bedrock";
        }
    } else if message.model.is_none() && provider == "chatgpt" {
        provider = "bedrock";
    }

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
            let retval = getapikey(dbpool, &message.provider.clone(), ap).await;
            if let Some(r) = retval {
                apikey = Some(Cow::Owned(r));
            } else {
                apikey = None
            }
            default_quota = -1;
        }
    }

    debug_eprintln!("huuid = {}", huuid);
    if apikey.is_none() {
        match provider {
            "chatgpt" => {
                if CONFIG.chatgpt_use_allowlist && !on_whitelist(&huuid, dbpool, provider).await {
                    println!("Rejecting Request from {}, not on whitelist.", huuid);
                    return Err(ChatproxyError::Unauthorized);
                }
                if *CHATGPT_USE_LIMITS
                    && !check_limit(&huuid, dbpool, provider, default_quota)
                        .await
                        .map_err(|e| match *e.downcast().unwrap() {
                            ChatproxyError::UseOwnKey => ChatproxyError::UseOwnKey,
                            _ => ChatproxyError::OverQuota,
                        })?
                {
                    return Err(ChatproxyError::OverQuota);
                }
            }
            "gemini" | "bedrock" => {
                if !check_limit(&huuid, dbpool, provider, default_quota)
                    .await
                    .map_err(|e| match *e.downcast().unwrap() {
                        ChatproxyError::UseOwnKey => ChatproxyError::UseOwnKey,
                        _ => ChatproxyError::OverQuota,
                    })?
                {
                    return Err(ChatproxyError::OverQuota);
                }
            }
            "ollama" => (),
            "palm" => {
                return Err(ChatproxyError::NoMorePalm);
            }
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
    let mut model: &str = &message.model.clone().unwrap_or_default();
    match provider {
        "chatgpt" => {
            if apikey.is_none() {
                match model {
                    "" => {
                        debug_eprintln!("Not switching to vision model");
                        model = "gpt-4o-mini";
                        // Code below is from when we needed to
                        // use a special model for vision recognition
                        // if message.inputimage.is_some() {
                        //     model = "gpt-4-vision-preview";
                        // } else {
                        //     model = "gpt-4o-mini";
                        // };
                    }
                    "gpt-3.5-turbo" | "gpt-4o-mini" => (),
                    _ => {
                        return Err(ChatproxyError::Message(format!(
                            "Unsupported model {} when using MIT's API Key",
                            model
                        )));
                    }
                };
            } else if model.is_empty() {
                model = "gpt-4o-mini";
                // Code below is from when we needed to
                // use a special model for vision recognition
                // if message.inputimage.is_some() {
                //     model = "gpt-4-vision-preview";
                // } else {
                //     model = "gpt-4o-mini";
                // };
            }
        }
        "bedrock" => match model {
            "" => {
                model = "us.meta.llama4-maverick-17b-instruct-v1:0";
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
        "gemini" => match model {
            "" => {
                if let Some(doimage) = message.doimage {
                    if doimage {
                        model = "gemini-2.0-flash-exp";
                    } else {
                        model = "gemini-2.0-flash"
                    }
                } else {
                    model = "gemini-2.0-flash";
                }
            }
            "gemini-1.5-pro" => (),
            "gemini-1.0-pro" => (),
            "gemini-2.0-flash-exp" => (),
            "gemini-2.0-flash" => (),
            _ => {
                return Err(ChatproxyError::Message(format!(
                    "Unsupported model {}",
                    model
                )));
            }
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
    let answer = match provider {
        "chatgpt" => converse_chatgpt(&huuid, dbpool, &uuid, &message.clone(), apikey, model)
            .await
            .map_err(|e| {
                debug_eprintln!("converse_chatgpt error: {:#?}", e);
                ChatproxyError::Message(e.to_string())
            })?,
        "gemini" => converse_gemini(&huuid, dbpool, &uuid, &message, apikey, model)
            .await
            .map_err(|e| {
                debug_eprintln!("converse_gemini error: {:#?}", e);
                ChatproxyError::Message(format!("Gemini Did not return a response: {}", e))
            })?,
        "bedrock" => converse_bedrock(&huuid, dbpool, &uuid, &message, &question, apikey, model)
            .await
            .map_err(|e| {
                eprintln!("converse_bedrock: error: {:#?}", e);
                ChatproxyError::Message("Bedrock Did not return a response".into())
            })?,
        "ollama" => ollamalib::converse(&huuid, &CONFIG.ollama_url, dbpool, &uuid, &message)
            .await
            .map_err(|e| {
                eprintln!("converse_ollama: error: {:#?}", e);
                ChatproxyError::Message(format!("Error: {}", e))
            })?,
        _ => Answer {
            answer: Some("Unknown Provider".to_string()),
            image: None,
        },
    };
    let b = make_response(&answer, &uuid);
    Ok(b)
}

async fn do_image(data: bytes::Bytes, dbpool: &PgPool) -> Result<Blob, ChatproxyError> {
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

async fn converse_chatgpt(
    huuid: &str,
    dbpool: &PgPool,
    uuid: &str,
    message: &chat::request<'_>,
    apikey: Option<Cow<'_, str>>,
    model: &str,
) -> Result<Answer, Box<dyn Error>> {
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
    debug_eprintln!("About to get conversation");
    let mut conversation: Conversation =
        if let Some(conversation_str) = get_conversation(uuid, "chatgpt", dbpool).await {
            serde_json::from_str(&conversation_str)?
        } else {
            // What we are about to do here is a kludge. Originally, if the user didn't provide a
            // "system" string, we would provide an empty string. However the o1 models do not want
            // any system string, including an empty one. Perhaps we should never provide a system
            // pair if the user didn't provide one, but I'm not sure what making such a change
            // will break. So we only do not provide a system string if the model name starts
            // with a o1 (sigh!).
            let nosystem = if let Some(ref m) = message.model {
                m.starts_with("o1")
            } else {
                false
            };
            if nosystem {
                // No system string
                Conversation {
                    uuid: uuid.to_string(),
                    content: vec![],
                    multiplier: 1,
                    model: model.to_string(),
                }
            } else {
                // Provide a system string
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
            }
        };
    debug_eprintln!("Done");
    if message.inputimage.is_some() {
        conversation.multiplier = 20;
        // if conversation.model == "gpt-4o-mini" {
        //     //  This is a kludge!
        //     conversation.model = "gpt-4-vision-preview".to_string();
        // }
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
    let request = if conversation.model.starts_with("o1") {
        CreateChatCompletionRequestArgs::default()
            //        .max_tokens(512u16)
            .model(&conversation.model)
            .user(huuid)
            .messages(messages)
            .build()?
    } else {
        CreateChatCompletionRequestArgs::default()
            .max_tokens(512u16)
            .model(&conversation.model)
            .user(huuid)
            .messages(messages)
            .build()?
    };
    debug_eprintln!("Request = {:#?}", request);
    let response = client.chat().create(request).await?;
    let mut retval = "Unkonwn".to_string();
    let usage: i32 = if let Some(ref u) = response.usage {
        (u.total_tokens * conversation.multiplier)
            .try_into()
            .unwrap()
    } else {
        0
    };
    debug_eprintln!("Usage = {} Multiplier = {}", usage, conversation.multiplier);
    record_usage(huuid, usage, dbpool, "chatgpt", apikey.is_some()).await?;
    if apikey.is_none() && *CHATGPT_USE_LIMITS {
        update_limit(huuid, usage, dbpool, "chatgpt").await
    }
    for choice in response.choices {
        if choice.message.role == ChatGPTRole::Assistant {
            if let Some(text) = choice.message.content {
                retval.clone_from(&text);
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
    debug_eprintln!("About to Store Conversation");
    store_conversation(
        uuid,
        "chatgpt",
        dbpool,
        &serde_json::to_string(&conversation)?,
    )
    .await?;
    debug_eprintln!("Done");
    Ok(Answer {
        answer: Some(retval),
        image: None,
    })
}

fn get_amazon_flavor(model: &str) -> Result<AmazonFlavor, Box<dyn Error>> {
    let mut z = model.split('.');
    match z.next() {
        Some("anthropic") => Ok(AmazonFlavor::Anthropic),
        Some("amazon") => Ok(AmazonFlavor::Titan),
        Some("meta") => Ok(AmazonFlavor::Llama),
        Some("us") => match z.next() {
            Some("meta") => Ok(AmazonFlavor::Llama),
            Some("anthropic") => Ok(AmazonFlavor::Anthropic),
            _ => Err(Box::<dyn Error>::from("Unknown Amazon Model")),
        },
        _ => Err(Box::<dyn Error>::from("Unknown Amazon Model")),
    }
}

// AWS models
async fn converse_bedrock(
    huuid: &str,
    dbpool: &PgPool,
    uuid: &str,
    message: &chat::request<'_>,
    question: &str,
    apikey: Option<Cow<'_, str>>,
    model: &str,
) -> Result<Answer, Box<dyn Error>> {
    use aws_sdk_bedrockruntime::primitives::Blob;

    let flavor = get_amazon_flavor(model)?;
    let system = message.system.clone();
    let ctag = format!("bedrock-{}", model);
    let mut conversation: Box<dyn Converse + Send> = match flavor {
        AmazonFlavor::Anthropic => {
            debug_eprintln!("Got a Anthropic Flavor");
            if let Some(conversation_str) = get_conversation(uuid, &ctag, dbpool).await {
                AnthropicConversation::load(&conversation_str)?
            } else {
                AnthropicConversation::initial()
            }
        }
        AmazonFlavor::Titan => {
            debug_eprintln!("Got a Titan Flavor");
            if let Some(conversation_str) = get_conversation(uuid, &ctag, dbpool).await {
                TitanConversation::load(&conversation_str)?
            } else {
                TitanConversation::initial()
            }
        }
        AmazonFlavor::Llama => {
            debug_eprintln!("Got a Llama Flavor");
            if let Some(conversation_str) = get_conversation(uuid, &ctag, dbpool).await {
                LlamaConversation::load(&conversation_str)?
            } else {
                LlamaConversation::initial(system)
            }
        }
    };
    conversation.push(Role::Human, question.to_string());
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(aws_credentials_provider())
        .region(aws_types::region::Region::new("us-east-1"))
        .load()
        .await;
    let client = aws_sdk_bedrockruntime::Client::new(&config);
    #[cfg(debug_assertions)]
    {
        let prompt = conversation.prepare();
        debug_eprintln!("converse_bedrock: prompt = {},", prompt);
    }
    let body = conversation.create_body();
    debug_eprintln!("converse_bedrock: body = {:#?}", body);
    let body = Blob::new(body);
    let fluent_builder = client
        .invoke_model()
        .body(body)
        .model_id(model)
        .content_type("application/json");
    debug_eprintln!("fluent_builder = {:#?}", fluent_builder);
    let body = fluent_builder.send().await?;
    let inner = body.clone().body.into_inner();
    let response = String::from_utf8(inner)?;
    debug_eprintln!("raw response = {}", response);
    let answer = conversation.parse_response(&response)?;
    debug_eprintln!("answer = {}", answer);
    let token_count = conversation.token_count(&response)?;
    record_usage(huuid, token_count, dbpool, &ctag, false)
        .await
        .ok();
    if apikey.is_none() {
        update_limit(huuid, token_count, dbpool, "bedrock").await
    }
    conversation.push(Role::Assistant, answer.clone());
    let conversation_str = conversation.serialize()?;
    store_conversation(uuid, &ctag, dbpool, &conversation_str).await?;
    Ok(Answer {
        answer: Some(answer),
        image: None,
    })
}

async fn converse_gemini(
    huuid: &str,
    dbpool: &PgPool,
    uuid: &str,
    message: &chat::request<'_>,
    apikey: Option<Cow<'_, str>>,
    model: &str,
) -> Result<Answer, Box<dyn Error>> {
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
        CONFIG.google_apikey.clone()
    };
    debug_eprintln!("Gemini: Using model {}", model);
    let answer = geminilib::converse(message, &apikey_to_use, state, model).await?;
    store_conversation(
        uuid,
        "gemini",
        dbpool,
        &serde_json::to_string(&answer.state)?,
    )
    .await?;
    let usage: i32 = answer.tokens;
    record_usage(huuid, usage, dbpool, "gemini", message.apikey.is_some()).await?;
    if apikey.is_none() {
        update_limit(huuid, usage, dbpool, "gemini").await
    }
    Ok(Answer {
        answer: Some(answer.answer),
        image: {
            if let Some(image) = answer.image {
                let mut out_image: Vec<u8> = Vec::new();
                BASE64_STANDARD.decode_vec(&image, &mut out_image)?;
                Some(out_image)
            } else {
                None
            }
        },
    })
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

fn make_response(answer: &Answer, uuid: &str) -> Blob {
    let r = chat::response {
        uuid: Some(Cow::Borrowed(uuid)),
        answer: {
            if let Some(answer) = &answer.answer {
                Some(Cow::Borrowed(answer))
            } else {
                None
            }
        },
        outputimage: {
            if let Some(image) = &answer.image {
                Some(Cow::Borrowed(image))
            } else {
                None
            }
        },
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
            ChatproxyError::NoMorePalm => {
                let text = "Google has shutdown PaLM".to_string();
                return Ok(warp::reply::with_status(text, StatusCode::BAD_REQUEST));
            }
        }
    } else {
        "Unknown Error".to_string()
    };

    Ok(warp::reply::with_status(text, StatusCode::NOT_FOUND))
}

struct HealthAnswer {}

impl Reply for HealthAnswer {
    fn into_response(self) -> Response {
        use http::*;
        use warp::hyper::Body;
        Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .header(
                "Access-Control-Allow-Headers",
                "Content-Type, Accept, Origin, User-Agent",
            )
            .header("Access-Control-Allow-Origin", "*")
            .body(Body::from("OK"))
            .unwrap()
    }
}

struct JsonAnswer {
    json: &'static str,
}

impl Reply for JsonAnswer {
    fn into_response(self) -> Response {
        use http::*;
        use warp::hyper::Body;
        Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .header(
                "Access-Control-Allow-Headers",
                "Content-Type, Accept, Origin, User-Agent",
            )
            .header("Access-Control-Allow-Origin", "*")
            .body(Body::from(self.json))
            .unwrap()
    }
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
            .header(
                "Access-Control-Allow-Headers",
                "Content-Type, Accept, Origin, User-Agent",
            )
            .header("Access-Control-Allow-Origin", "*")
            .body(Body::from(self.bytes))
            .unwrap()
    }
}

async fn setup(conf: &Config) -> Result<PgPool, Box<dyn Error>> {
    let options: PgConnectOptions = conf.dburl.parse()?;
    let dbpool = PgPool::connect_with(options).await?;

    sqlx::query(
        "create table if not exists conversation (uuid text primary key, provider text, conversation text, timestamp timestamp)",
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
        "create table if not exists limits (huuid text, usage integer, quota integer, timestamp timestamptz, provider text)",
    )
    .execute(&dbpool)
    .await?;
    sqlx::query("create unique index if not exists limits_u_p on limits (huuid, provider)")
        .execute(&dbpool)
        .await?;
    sqlx::query("create table if not exists config (name text, value text)")
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

async fn on_whitelist(uuid: &str, dbpool: &PgPool, provider: &str) -> bool {
    match sqlx::query!(
        "select * from whitelist where uuid = $1 and provider = $2",
        uuid,
        provider
    )
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
    usage: i32,
    dbpool: &PgPool,
    provider: &str,
    ownkey: bool,
) -> Result<(), Box<dyn Error>> {
    let prior_usage: i32 = match sqlx::query!(
        "select usage from usage where huuid = $1 and provider = $2 and  ownkey = $3",
        huuid,
        provider,
        ownkey,
    )
    .fetch_one(dbpool)
    .await
    {
        Ok(row) => {
            row.usage.unwrap_or(0) // Row found, but usage null
        }
        Err(_) => 0,
    };

    let usage = usage + prior_usage;

    debug_eprintln!("About to do insert");
    sqlx::query!("insert into usage (huuid, usage, provider, ownkey) values ($1, $2, $3, $4) on conflict (huuid, provider, ownkey) do update set usage = $2",
                 huuid, usage, provider, ownkey)
        .execute(dbpool)
        .await?;
    debug_eprintln!("Done");
    Ok(())
}

async fn update_limit(huuid: &str, usage: i32, dbpool: &PgPool, provider: &str) {
    debug_eprintln!("update_limit: entered, usage = {}", usage);
    let mut transaction = dbpool.begin().await.unwrap();
    let (old_usage, quota, ts) = match sqlx::query!(
        "select usage, quota, timestamp from limits where huuid = $1 and provider = $2",
        huuid,
        provider
    )
    .fetch_one(&mut *transaction)
    .await
    {
        Ok(row) => (
            row.usage.unwrap_or(0),
            row.quota.unwrap_or(*CHATGPT_DEFAULT_QUOTA),
            row.timestamp.unwrap_or(Utc::now()),
        ),
        Err(_) => (0, *CHATGPT_DEFAULT_QUOTA, Utc::now()),
    };
    let usage = old_usage + usage;
    sqlx::query!("insert into limits (huuid, usage, quota, timestamp, provider) values ($1, $2, $3, $4, $5) on conflict (huuid, provider) do update set usage = $2",
                 huuid, usage, quota, ts, provider)
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    debug_eprintln!("update_limit: leaving");
}

async fn get_conversation(uuid: &str, provider: &str, dbpool: &PgPool) -> Option<String> {
    let row = sqlx::query!(
        "select conversation, provider  from conversation where uuid = $1",
        uuid
    )
    .fetch_one(dbpool)
    .await;
    match row {
        Err(_) => None,
        Ok(row) => {
            if row.provider == Some(provider.to_string()) {
                row.conversation
            } else {
                None // We switched provider!
            }
        }
    }
}

async fn store_conversation(
    uuid: &str,
    provider: &str,
    dbpool: &PgPool,
    value: &str,
) -> Result<(), Box<dyn Error>> {
    sqlx::query!("insert into conversation (uuid, conversation, provider, timestamp) values ($1, $2, $3, CURRENT_TIMESTAMP) on conflict (uuid) do update set conversation = $2",
                 uuid, value, provider)
        .execute(dbpool)
        .await?;
    Ok(())
}

async fn check_limit(
    huuid: &str,
    dbpool: &PgPool,
    provider: &str,
    default_quota: i32,
) -> Result<bool, Box<dyn Error>> {
    let (usage, quota, their_time) = match sqlx::query!(
        "select usage, quota, timestamp from limits where huuid = $1 and provider = $2",
        huuid,
        provider
    )
    .fetch_one(dbpool)
    .await
    {
        Ok(row) => (
            row.usage.unwrap_or(0),
            row.quota.unwrap_or(default_quota),
            row.timestamp.unwrap_or(Utc::now()),
        ),
        Err(_) => (0, default_quota, Utc::now()),
    };
    // A quota of 0 means infinite!
    if quota == 0 {
        return Ok(true);
    }
    // If quota == -1, then tell them to use their own key
    if quota == -1 {
        return Err(ChatproxyError::UseOwnKey.into());
    }

    let passed = Utc::now().timestamp() - their_time.timestamp();
    debug_eprintln!(
        "Their Timestamp = {}, passed = {}, quota = {}",
        their_time,
        passed,
        quota
    );
    // The screwiness below is because quota * passed might yield a
    // large negative number if a lot of time has passed. But ultimately
    // we can use an i32 because we ignore all negative numbers
    let v: i64 = (quota as i64 * passed) / SECS_PER_DAY;
    let mut r: i64 = (usage as i64) - v;
    if r < 0 {
        r = 0
    };
    let r: i32 = r.try_into().unwrap_or(0);
    debug_eprintln!("check_limit: r = {}", r);

    match sqlx::query!("insert into limits (huuid, usage, quota, timestamp, provider) values ($1, $2, $3, CURRENT_TIMESTAMP, $4) on conflict (huuid, provider) do update set usage = $2, timestamp = CURRENT_TIMESTAMP",
                       huuid, r, quota,  provider)
        .execute(dbpool)
        .await
    {
        Ok(_) => (),
        Err(e) => return Err(e.into()),
    };
    if r < quota { Ok(true) } else { Ok(false) }
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

async fn get_defaults(dbpool: &PgPool) -> (bool, i32) {
    let quota = match sqlx::query!("select value from config where name = 'default_quota'")
        .fetch_one(dbpool)
        .await
    {
        Ok(row) => {
            let value: i32 = row
                .value
                .unwrap_or("10000".to_string())
                .parse()
                .unwrap_or(10000);
            value
        }
        Err(_) => 10000,
    };
    let use_limits = match sqlx::query!("select value from config where name = 'use_limits'")
        .fetch_one(dbpool)
        .await
    {
        Ok(row) => row.value == Some("true".to_string()),
        Err(_) => true,
    };
    (use_limits, quota)
}

/// Given a "short" API Key (the kind we issue) Check to see if there is a specific
/// provider API key to use for this "short" key. If so, return it. Otherwise return
/// None
async fn getapikey(dbpool: &PgPool, provider: &str, inapi: &str) -> Option<String> {
    match sqlx::query!(
        "select apikey from apikeylist where shortapi = $1 and provider = $2",
        inapi,
        provider
    )
    .fetch_one(dbpool)
    .await
    {
        Ok(row) => row.apikey,
        Err(_) => None,
    }
}

static PROVIDER_MODULES: &str = r#"{ "provider" : ["chatgpt", "gemini", "bedrock", "ollama"],
  "model" : { "chatgpt:gpt-4o-mini" : "gpt-4o-mini",
    "chatgpt:o1-preview" : "o1-preview",
    "chatgpt:o1-mini" : "o1-mini",
    "google:gemini" : "",
    "google:gemini-1.0-pro" : "gemini-1.0-pro",
    "google:gemini-1.5-pro" : "gemini-1.5-pro",
    "google:gemini-2.0-flash" : "gemini-2.0-flash",
    "google:gemini-2.0-flash-exp" : "gemini-2.0-flash-exp",
    "bedrock:anthropic.claude-v2" : "anthropic.claude-v2",
    "bedrock:anthropic.claude-v1" : "anthropic.claude-v1",
    "bedrock:meta.llama3-70b-instruct-v1:0" : "meta.llama3-70b-instruct-v1:0",
    "bedrock:us.meta.llama3-3-70b-instruct-v1:0" : "us.meta.llama3-3-70b-instruct-v1:0",
    "bedrock:us.meta.llama4-maverick-17b-instruct-v1:0" : "us.meta.llama4-maverick-17b-instruct-v1:0",
    "ollama:gemma2" : "gemma2",
    "ollama:gemma2:2b" : "gemma2:2b" }
}
"#;

#[cfg(test)]
mod tests {
    use crate::*;
    use chrono::TimeZone;

    lazy_static! {
        static ref CONFIG: Config = Config::test();
    }

    trait Test {
        fn test() -> Self;
    }

    impl Test for Config {
        fn test() -> Self {
            Self {
                port: 9001,
                nthreads: 0, // Means as many as cores
                dburl: String::from(""),
                hmac_keys: BTreeMap::from([
                    ("0".into(), "changeme!".into()),
                    ("1".into(), "change or delete me!".into()),
                ]),
                chatgpt_apikey: String::from("sk-key-here"),
                chatgpt_use_allowlist: true,
                google_apikey: "none".to_string(),
                aws_access_key: String::from("aws-access-key-here"),
                aws_access_secret: String::from("aws-access-secret-here"),
                ollama_url: String::from("ollama url here"),
            }
        }
    }

    #[test]
    fn verify_limits() {
        let _ = DBPOOL.clone(); // Make sure it is setup before we call block_on
        // otherwise we wind up calling block_on recursively, which is not permitted
        let _ = *CHATGPT_DEFAULT_QUOTA;
        RT.block_on(async {
            debug_eprintln!("verify_limits");
            let dbpool = DBPOOL.clone();
            update_limit("12345", 10000, &dbpool, "chatgpt").await;
            let now = Utc::now().timestamp();
            let then = now - (3600 * 12); // an hour ago
            // Set timestamp back an hour
            let then = Utc.timestamp_opt(then, 0).unwrap();
            sqlx::query!(
                "update limits set timestamp = $1 where huuid = $2",
                then,
                "12345"
            )
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
            geminilib::build_gemini_prompt("Who won the World Series in 2004?", &mut state, false)
                .unwrap()
        );
    }
}
