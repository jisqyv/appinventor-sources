use debug_print::debug_eprintln;
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::ChatproxyError;
use crate::chat;

// static URL: &str =
//     "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=";

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Request {
    contents: Vec<Parts>,
    generationConfig: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct GeminiAnswer {
    pub answer: String,
    pub image: Option<String>, // base64 encoded image
    pub state: State,
    pub tokens: i32,
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
#[allow(non_camel_case_types)]
enum Part {
    text(String),
    inlineData(InlineData),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct InlineData {
    mime_type: Option<String>,
    data: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct GeminiRetVal {
    candidates: Vec<Response>,
    usageMetadata: usageMetadata,
}

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug)]
struct usageMetadata {
    totalTokenCount: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    content: Parts,
}

// Below struct us used when returning answer to the caller.
// The idea is that if we return a string that doesn't start with a "["
// Then it is a simple text answer. This is to support older versions of
// the ChatBot component that expected a simple text based answer.
// When we return images, we return it as a JSON array with elements of
// the array being objects with an "image" or a "text" part.

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug)]
enum ClientAnswerElement {
    text(String),
    image(String), // Base64 encoded image
}

pub async fn converse(
    message: &chat::request<'_>,
    apikey: &str,
    state: Option<State>,
    model: &str,
) -> Result<GeminiAnswer, Box<dyn Error>> {
    let system = &message.system; // Gemini doesn't naturally support a system string, so we will
    // just add it as a prepended user text string
    // create empty state structure if none provided
    let mut state = if let Some(state) = state {
        state
    } else {
        let mut s = State::new(); // Start with an empty state
        if let Some(system) = system {
            // We have a system string
            s.parts.push(Parts {
                parts: vec![Part::text(system.to_string())],
                role: Some("user".to_string()),
            });
        }
        s
    };

    let question = if let Some(ref question) = message.question {
        question
    } else {
        return Err(Box::new(ChatproxyError::Message(
            "Must Ask a Question".to_string(),
        )));
    };

    let request = build_gemini_prompt(question, &mut state, message.doimage.unwrap_or_default())?;

    // #[cfg(debug_assertions)]
    // {
    //     let data = serde_json::to_string(&request)?;
    //     debug_eprintln!("Gemini Data = {}", data);
    // }
    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            model, apikey
        ))
        .json(&request)
        .send()
        .await?;
    let status = res.status();
    let retval = res.text().await?;
    if !status.is_success() {
        // debug_eprintln!("Status Failure: {:#}: Retval: {}", status, retval);
        debug_eprintln!("Gemini Error: Status = {} Retval = {}", status, retval);
        if status == 429 {
            return Err(Box::new(ChatproxyError::OverQuota));
        } else {
            return Err("Error from Gemini".into());
        }
    }
    //     debug_eprintln!("StatusCode = {}", status.as_u16());
    {
        use serde_json::value::Value;
        let _v: Value = serde_json::from_str(&retval)?;
        // debug_eprintln!("Value = {:#?}", _v);
    }
    // debug_eprintln!("Retval = {}", retval);
    let candidates: GeminiRetVal = serde_json::from_str(&retval)?;
    // debug_eprintln!("GeminiRetVal = {:#?}", candidates);
    let pts = &candidates.candidates;
    if pts.is_empty() {
        return Err("Gemini didn't return answer".into());
    }
    // debug_eprintln!("pts.len() == {}", pts.len());
    match pts.len() {
        0 => Err("Gemini didn't return an answer".into()),
        1 => {
            // debug_eprintln!("in pts.len() == 1)");
            let content = &pts[0].content;
            if content.parts.is_empty() {
                return Err("Gemini didn't return answer".into());
            }
            // debug_eprintln!("content.parts.len() == {}", content.parts.len());
            if content.parts.len() == 1 {
                let partvec: Vec<Part> = content
                    .parts
                    .clone()
                    .into_iter()
                    .filter(|x| match x {
                        Part::inlineData(_) => false,
                        Part::text(_) => true,
                    })
                    .collect();
                let parts: Parts = Parts {
                    parts: partvec,
                    role: content.role.clone(),
                };
                // debug_eprintln!("Pushing state: {:#?}", parts);
                state.parts.push(parts);
                match &content.parts[0] {
                    Part::text(t) => {
                        let answer = GeminiAnswer {
                            answer: t.into(),
                            state,
                            tokens: candidates.usageMetadata.totalTokenCount,
                            image: None,
                        };
                        Ok(answer)
                    }
                    Part::inlineData(d) => {
                        let answer = GeminiAnswer {
                            answer: "".to_string(),
                            image: Some(d.data.clone()),
                            state,
                            tokens: candidates.usageMetadata.totalTokenCount,
                        };
                        Ok(answer)
                    }
                }
            } else {
                let mut answer = create_client_answer(&content.parts, state.clone())?;
                let partvec: Vec<Part> = content
                    .parts
                    .clone()
                    .into_iter()
                    .filter(|x| match x {
                        Part::inlineData(_) => false,
                        Part::text(_) => true,
                    })
                    .collect();
                let parts: Parts = Parts {
                    parts: partvec,
                    role: content.role.clone(),
                };
                // debug_eprintln!("Pushing state: {:#?}", parts);
                state.parts.push(parts);
                answer.state = state;
                answer.tokens = candidates.usageMetadata.totalTokenCount;
                Ok(answer)
            }
        }
        _ => Err("Gemini gave us more then we expected".into()),
    }
}

#[allow(non_snake_case)]
pub fn build_gemini_prompt(
    input: &str,
    state: &mut State,
    do_image: bool,
) -> Result<Request, Box<dyn Error>> {
    let _parts = state.parts.to_owned();
    state.parts.push(Parts {
        parts: vec![Part::text(input.to_string())],
        role: Some("user".to_string()),
    });
    use serde_json::json;
    let request = if do_image {
        Request {
            contents: state.parts.clone(),
            generationConfig: json!({"responseModalities":["TEXT","IMAGE"]}),
        }
    } else {
        Request {
            contents: state.parts.clone(),
            generationConfig: json!({ "maxOutputTokens" : 800}),
        }
    };
    Ok(request)
}

fn create_client_answer(parts: &Vec<Part>, state: State) -> Result<GeminiAnswer, Box<dyn Error>> {
    let mut retval = GeminiAnswer {
        answer: "".to_string(),
        image: None,
        state,
        tokens: 0,
    };
    for part in parts {
        match part {
            Part::text(t) => retval.answer = t.to_string(),
            Part::inlineData(d) => retval.image = Some(d.data.clone()),
        }
    }
    Ok(retval)
}
