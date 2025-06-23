#![allow(non_snake_case)]
use crate::{Converse, Role};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TitanPair {
    role: Role,
    text: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TitanConversation {
    conversation: Vec<TitanPair>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct TitanResults {
    tokenCount: i32,
    outputText: String,
    completionReason: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct TitanResponse {
    inputTextTokenCount: i32,
    results: Vec<TitanResults>,
}

impl TitanConversation {
    pub fn initial() -> Box<dyn Converse + Send> {
        Box::new(TitanConversation {
            conversation: vec![],
        }) as Box<dyn Converse + Send>
    }
    pub fn load(input: &str) -> Result<Box<dyn Converse + Send>, Box<dyn Error>> {
        let retval: Self = serde_json::from_str(input)?;
        Ok(Box::new(retval) as Box<dyn Converse + Send>)
    }
}

impl Converse for TitanConversation {
    fn create_body(&self) -> String {
        use serde_json::json;
        let prompt = self.prepare();
        json!({"inputText" : prompt,
               "textGenerationConfig" :
               {"temperature" : 0,
                "topP" : 1,
                "stopSequences" : [],
                "maxTokenCount": 2000}
        })
        .to_string()
    }

    fn prepare(&self) -> String {
        self.conversation[0].text.clone()
    }

    fn push(&mut self, role: Role, text: String) {
        let pair = TitanPair { role, text };
        self.conversation.push(pair);
    }

    fn serialize(&self) -> Result<String, Box<dyn Error>> {
        Ok(serde_json::to_string(&self)?)
    }

    fn parse_response(&self, response: &str) -> Result<String, Box<dyn Error>> {
        let r: TitanResponse = serde_json::from_str(response)?;
        Ok(r.results[0].outputText.clone())
    }

    // Stub Implementation
    fn token_count(&self, _response: &str) -> Result<i32, Box<dyn Error>> {
        Ok(0)
    }
}
