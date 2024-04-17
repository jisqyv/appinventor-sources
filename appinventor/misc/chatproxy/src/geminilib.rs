use debug_print::debug_eprintln;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::{u64};

use crate::chat;
use crate::ChatproxyError;

//    #[serde(skip_serializing_if = "Option::is_none")]

static URL: &str =
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=";

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    contents: Vec<Parts>,
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub answer: String,
    pub state: State,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct State {
    parts: Vec<Parts>,
}

impl State {
    pub fn new() -> Self {
        Self { parts: vec![] }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Parts {
    parts: Vec<Part>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum Part {
    text(String),
    inline_data(InlineData),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct InlineData {
    mime_type: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Candidates {
    candidates: Vec<Response>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    content: Parts,
}

pub async fn converse(
    message: &chat::request<'_>,
    apikey: &str,
    state: Option<State>,
) -> Result<Answer, Box<dyn Error>> {
    // create empty state structure if none provided
    let mut state = if let Some(state) = state {
        state
    } else {
        State::new()
    };

    let question = if let Some(ref question) = message.question {
        question
    } else {
        return Err(Box::new(ChatproxyError::Message(
            "Must Ask a Question".to_string(),
        )));
    };

    let request = build_gemini_prompt(question, &mut state)?;

    let data = serde_json::to_string(&request)?;
    debug_eprintln!("Gemini Data = {}", data);
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}{}", URL, apikey))
        .json(&request)
        .send()
        .await?;
    let status = res.status();
    let retval = res.text().await?;
    if !status.is_success() {
        debug_eprintln!("Status Failure: {:#}: Retval: {}", status, retval);
        return Err("Error from Gemini".into());
    }
    debug_eprintln!("StatusCode = {}", status.as_u16());
    {
        use serde_json::value::Value;
        let _v: Value = serde_json::from_str(&retval)?;
        debug_eprintln!("Value = {:#?}", _v);
    }
    debug_eprintln!("Retval = {}", retval);
    let candidates: Candidates = serde_json::from_str(&retval)?;
    debug_eprintln!("Candidates = {:#?}", candidates);
    let pts = &candidates.candidates;
    if pts.is_empty() {
        return Err("Gemini didn't return answer".into());
    }
    let content = &pts[0].content;
    if content.parts.is_empty() {
        return Err("Gemini didn't return answer".into());
    }
    state.parts.push(content.clone());
    if let Part::text(t) = &content.parts[0] {
        let answer = Answer {
            answer: t.into(),
            state,
        };
        Ok(answer)
    } else {
        Err("Gemini didn't return an answer".into())
    }
}

pub fn build_gemini_prompt(input: &str, state: &mut State) -> Result<Request, Box<dyn Error>> {
    let _parts = state.parts.to_owned();
    state.parts.push(Parts {
        parts: vec![Part::text(input.to_string())],
        role: Some("user".to_string()),
    });
    let request = Request {
        contents: state.parts.clone(),
    };
    Ok(request)
}
