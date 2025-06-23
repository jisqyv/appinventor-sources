#![allow(non_snake_case)]
use crate::{Converse, Role};
use debug_print::debug_eprintln;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::error::Error;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LlamaPair {
    role: Role,
    text: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LlamaConversation {
    system: Option<String>,
    conversation: Vec<LlamaPair>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct LlamaResults {
    tokenCount: i32,
    outputText: String,
    completionReason: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct LlamaResponse {
    generation: String,
    prompt_token_count: i32,
    generation_token_count: i32,
}

impl LlamaConversation {
    pub fn initial(system: Option<Cow<'_, str>>) -> Box<dyn Converse + Send> {
        Box::new(LlamaConversation {
            system: system.as_ref().map(|v| v.to_string()),
            conversation: vec![],
        }) as Box<dyn Converse + Send>
    }
    pub fn load(input: &str) -> Result<Box<dyn Converse + Send>, Box<dyn Error>> {
        let retval: Self = serde_json::from_str(input)?;
        Ok(Box::new(retval) as Box<dyn Converse + Send>)
    }
}

impl Converse for LlamaConversation {
    fn create_body(&self) -> String {
        use serde_json::json;
        let prompt = self.prepare();
        json!({"prompt" : prompt,
               "max_gen_len": 512,
               "temperature" : 0.5,})
        .to_string()
    }

    fn prepare(&self) -> String {
        debug_eprintln!("Preparing: {:#?}", self);
        let mut prompt: String = r#"<|begin_of_text|>"#.to_string();
        if let Some(ref system) = self.system {
            prompt += &format!(
                "<|start_header_id|>system<|end_header_id|>{}<|eot_id|>",
                system
            );
        }
        for conversation in &self.conversation {
            match conversation.role {
                Role::Human => {
                    prompt += &format!(
                        "<|start_header_id|>user<|end_header_id|>{}<|eot_id|>",
                        &conversation.text
                    );
                }
                Role::Assistant => {
                    prompt += &format!(
                        "<|start_header_id|>assistant<|end_header_id|>{}<|eot_id|>",
                        &conversation.text
                    );
                }
            }
        }
        prompt += "<|start_header_id|>assistant<|end_header_id|>";
        prompt
    }
    //         format!(
    //             r#"<|begin_of_text|><|start_header_id|>user<|end_header_id|>
    // {}
    // <|eot_id|>
    // <|start_header_id|>assistant<|end_header_id|>"#,
    //             self.conversation[0].text
    //     )
    // }

    fn push(&mut self, role: Role, text: String) {
        let pair = LlamaPair { role, text };
        self.conversation.push(pair);
    }

    fn serialize(&self) -> Result<String, Box<dyn Error>> {
        Ok(serde_json::to_string(&self)?)
    }

    fn token_count(&self, response: &str) -> Result<i32, Box<dyn Error>> {
        let r: LlamaResponse = serde_json::from_str(response)?;
        Ok(r.generation_token_count + r.prompt_token_count)
    }

    fn parse_response(&self, response: &str) -> Result<String, Box<dyn Error>> {
        let r: LlamaResponse = serde_json::from_str(response)?;
        let mut answer = r.generation;
        if answer.ends_with("<|eot_id|>") {
            answer = answer
                .strip_suffix("<|eot_id|>")
                .unwrap_or_default()
                .to_string();
        }
        Ok(answer)
    }
}
