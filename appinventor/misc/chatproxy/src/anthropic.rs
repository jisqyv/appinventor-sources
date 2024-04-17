use crate::{Converse, Role};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AnthropicPair {
    role: Role,
    text: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AnthropicConversation {
    conversation: Vec<AnthropicPair>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Anthropicresponse {
    completion: Option<String>,
    stop_reason: Option<String>,
    stop: Option<String>,
}

impl AnthropicConversation {
    pub fn initial() -> Box<dyn Converse + Send> {
        Box::new(AnthropicConversation {
            conversation: vec![],
        }) as Box<dyn Converse + Send>
    }
    pub fn load(input: &str) -> Result<Box<dyn Converse + Send>, Box<dyn Error>> {
        let retval: Self = serde_json::from_str(input)?;
        Ok(Box::new(retval) as Box<dyn Converse + Send>)
    }
}

impl Converse for AnthropicConversation {
    fn create_body(&self) -> String {
        use serde_json::json;
        let prompt = self.prepare();
        json!({"prompt" : prompt,
               "temperature" : 0.5,
               "top_p" : 1,
               "top_k" : 400,
               "max_tokens_to_sample": 200})
        .to_string()
    }

    fn prepare(&self) -> String {
        let mut retval: String = String::from("\n\n");
        for c in &self.conversation {
            match c.role {
                Role::Human => {
                    retval.push_str(&format!("Human:{}\n\n", c.text));
                }
                Role::Assistant => {
                    retval.push_str(&format!("Assistant:{}\n\n", c.text));
                }
            }
        }
        retval.push_str("Assistant:\n\n");
        retval
    }
    fn push(&mut self, role: Role, text: String) {
        let pair = AnthropicPair { role, text };
        self.conversation.push(pair);
    }

    fn serialize(&self) -> Result<String, Box<dyn Error>> {
        Ok(serde_json::to_string(&self)?)
    }

    fn parse_response(&self, response: &str) -> Result<String, Box<dyn Error>> {
        let r: Anthropicresponse = serde_json::from_str(response)?;
        if let Some(r) = r.completion {
            Ok(r)
        } else {
            Err(Box::<dyn Error>::from("Invalid Anthropic Resonse"))
        }
    }
}
