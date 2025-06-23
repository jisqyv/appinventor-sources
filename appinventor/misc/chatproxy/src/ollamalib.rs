use debug_print::debug_eprintln;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::borrow::Cow;
use std::error::Error;

// static CHAT_URL: &str = "http://localhost:11434/api/generate";

use crate::Answer;
use crate::chat;

#[derive(Serialize, Deserialize, Debug)]
struct Context {
    model: String,
    context: Option<Vec<u32>>,
    system: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Request {
    model: String,
    prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    stream: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    error: Option<String>,
    response: Option<String>,
    context: Option<Vec<u32>>,
    prompt_eval_count: Option<u32>,
    eval_count: Option<u32>,
}

pub async fn converse(
    huuid: &str,
    ollama_url: &str,
    dbpool: &PgPool,
    uuid: &str,
    message: &chat::request<'_>,
) -> Result<Answer, Box<dyn Error>> {
    let mut model = message.model.clone().unwrap_or_default();
    // let mut model = if let Some(ref m) = message.model {
    //     m
    // } else {
    //     ""
    // };
    let system = if message.system.is_some() {
        Some(message.system.clone().unwrap().to_string())
    } else {
        None
    };
    if model.is_empty() {
        model = Cow::Borrowed("gemma2");
    };
    let mut context: Context = {
        if let Some(conversation_str) = crate::get_conversation(uuid, "ollama", dbpool).await {
            serde_json::from_str(&conversation_str)?
        } else {
            Context {
                model: model.to_string(),
                context: None,
                system,
            }
        }
    };
    let client = reqwest::Client::new();
    let request = Request {
        model: model.to_string(),
        prompt: message.question.clone().unwrap().to_string(),
        context: context.context,
        system: context.system.clone(),
        stream: false,
    };
    debug_eprintln!("request = {:#?}", request);
    let data = serde_json::to_string(&request)?;
    debug_eprintln!("data = {}", data);
    let res = client
        .post(ollama_url)
        .header("Content-Type", "application/json")
        .body(data)
        .send()
        .await?;
    debug_eprintln!("Res = {:#?}", res);
    let resjson = res.text().await?;
    debug_eprintln!("Answer = {}", resjson);
    let res: Response = serde_json::from_str(&resjson)?;
    let pev = res.prompt_eval_count.unwrap_or(0);
    let evc = res.eval_count.unwrap_or(0);
    let usage: i32 = (pev + evc).try_into().unwrap();
    debug_eprintln!("Cost = {}", usage);
    crate::record_usage(huuid, usage, dbpool, "ollama", false).await?;
    if res.response.is_some() {
        context.context = res.context;
        crate::store_conversation(uuid, "ollama", dbpool, &serde_json::to_string(&context)?)
            .await?;
        Ok(Answer {
            answer: Some(res.response.unwrap()),
            image: None,
        })
    } else if let Some(ref error) = res.error {
        Err(Box::new(crate::ChatproxyError::Message(format!(
            "Error from Ollama: {}",
            error
        ))))
    } else {
        Err(Box::new(crate::ChatproxyError::Message(
            "Unknown Error from Ollama".to_string(),
        )))
    }
}
