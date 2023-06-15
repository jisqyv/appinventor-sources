use debug_print::debug_eprintln;
use serde::{Deserialize, Serialize};
use std::error::Error;

static URL: &str =
    "https://generativelanguage.googleapis.com/v1beta2/models/chat-bison-001:generateMessage?key=";

#[derive(Serialize, Deserialize, Debug)]
struct Message {
    prompt: Prompt,
}

#[derive(Serialize, Deserialize, Debug)]
struct Prompt {
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
    examples: Vec<Dialog>,
    #[serde(skip_serializing_if = "Option::is_none")]
    messages: Option<Vec<Input>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Dialog {
    input: Input,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<Input>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Input {
    content: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Candidate {
    author: String,
    content: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    candidates: Vec<Candidate>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct State {
    context: Option<String>,
    dialogs: Vec<Dialog>,
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub answer: String,
    pub state: State,
}

pub async fn converse(
    question: &str,
    context: Option<String>,
    apikey: &str,
    state: Option<State>,
) -> Result<Answer, Box<dyn Error>> {
    // create empty state structure if none provided
    let mut state = if let Some(state) = state {
        state
    } else {
        State {
            context: None,
            dialogs: vec![],
        }
    };
    // context in the State structure overrides any argument
    let context = if let Some(ref c) = state.context {
        Some(c.clone())
    } else {
        context
    };
    debug_eprintln!("context: {:#?}", context);
    let p = Message {
        prompt: Prompt {
            context: context.clone(),
            messages: Some(vec![Input {
                content: question.to_string(),
            }]),
            examples: state.dialogs.clone(),
        },
    };

    let data = serde_json::to_string(&p)?;
    debug_eprintln!("{}", data);
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}{}", URL, apikey))
        .body(data)
        .send()
        .await?;
    let status = res.status();
    let retval = res.text().await?;
    if !status.is_success() {
        debug_eprintln!("Status Failure: {:#}: Retval: {}", status, retval);
        return Err("Error from PaLM".into());
    }
    debug_eprintln!("StatusCode = {}", status.as_u16());
    {
        use serde_json::value::Value;
        let _v: Value = serde_json::from_str(&retval)?;
        debug_eprintln!("Value = {:#?}", _v);
    }
    let v: Response = match serde_json::from_str(&retval) {
        Ok(n) => n,
        Err(e) => {
            debug_eprintln!("serde_json: {:#?}", e);
            debug_eprintln!("result = {:#?}", retval);
            return Err(e.into());
        }
    };
    let added_dialog = Dialog {
        input: Input {
            content: question.to_string(),
        },
        output: Some(Input {
            content: v.candidates[0].content.clone(),
        }),
    };
    state.dialogs.push(added_dialog);
    state.context = context;
    let answer: Answer = Answer {
        answer: v.candidates[0].content.clone(),
        state: state.clone(),
    };
    Ok(answer)
    // Ok("foo".to_string())
}
