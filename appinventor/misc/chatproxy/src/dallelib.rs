use debug_print::debug_eprintln;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::error::Error;

static CREATE_URL: &str = "https://api.openai.com/v1/images/generations";
static EDIT_URL: &str = "https://api.openai.com/v1/images/edits";

#[derive(Serialize, Deserialize, Debug)]
struct Prompt {
    prompt: String,
    size: String,
    n: i32,
    response_format: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Image {
    b64_json: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    created: i64,
    data: Vec<Image>,
}

pub async fn createimage(
    prompt: &str,
    size: &str,
    apikey: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let p = Prompt {
        prompt: prompt.to_string(),
        size: size.to_string(),
        response_format: "b64_json".to_string(),
        n: 1,
    };
    let data = serde_json::to_string(&p)?;
    debug_eprintln!("{}", data);
    let client = reqwest::Client::new();
    let res = client
        .post(CREATE_URL)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", apikey))
        .body(data)
        .send()
        .await?;
    let status = res.status();
    let retval = res.text().await?;
    if !status.is_success() {
        debug_eprintln!("Status Failure: {:#}: Retval: {}", status, retval);
        return Err("Error from DALL-E".into());
    }
    debug_eprintln!("StatusCode = {}", status.as_u16());
    // {
    //     use serde_json::value::Value;
    //     let _v: Value = serde_json::from_str(&retval)?;
    //     debug_eprintln!("Value = {:#?}", _v);
    // }
    // let v: Response = match serde_json::from_str(&retval) {
    //     Ok(n) => n,
    //     Err(e) => {
    //         debug_eprintln!("serde_json: {:#?}", e);
    //         debug_eprintln!("result = {:#?}", retval);
    //         return Err(e.into());
    //     }
    // };
    let response: Response = serde_json::from_str(&retval)?;
    let image = &response.data[0];
    {
        use base64::{Engine as _, engine::general_purpose};
        let bytes = general_purpose::STANDARD.decode(image.b64_json.clone())?;
        Ok(bytes)
    }
}

pub async fn editimage(
    prompt: &str,
    size: &str,
    apikey: &str,
    source: Option<Cow<'_, [u8]>>,
    mask: Option<Cow<'_, [u8]>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use reqwest::multipart::{Form, Part};
    let source = source.ok_or_else(|| Into::<Box<dyn Error>>::into("Must provide source image"))?;
    let mask = mask.ok_or_else(|| Into::<Box<dyn Error>>::into("Must provide mask image"))?;
    let source_part = Part::bytes(Cow::Owned(source.into()))
        .file_name("source.png")
        .mime_str("image/png")?;
    let mask_part = Part::bytes(Cow::Owned(mask.into()))
        .file_name("mask.png")
        .mime_str("image/png")?;
    let prompt_part = Part::text(Cow::Owned(prompt.to_string()));
    let size_part = Part::text(Cow::Owned(size.to_string()));
    let n_part = Part::text("1");
    let response_format_part = Part::text("b64_json");
    let f = Form::new()
        .part("prompt", prompt_part)
        .part("image", source_part)
        .part("mask", mask_part)
        .part("n", n_part)
        .part("response_format", response_format_part)
        .part("size", size_part);
    let client = reqwest::Client::new();
    let res = client
        .post(EDIT_URL)
        .header("Content-Type", "multipart/form-data")
        .header("Authorization", format!("Bearer {}", apikey))
        .multipart(f)
        .send()
        .await?;
    debug_eprintln!("{:#?}", res);
    let content = res.text().await?;
    let response: Response = match serde_json::from_str(&content) {
        Ok(n) => n,
        Err(e) => {
            println!(
                "Could not parse response from DALL-E: error = {} raw response = {}",
                e, content
            );
            return Err(Into::<Box<dyn Error>>::into(format!(
                "Could not parse resonse from DALL-E: error = {} raw response = {}",
                e, content
            )));
        }
    };
    let image = &response.data[0];
    {
        use base64::{Engine as _, engine::general_purpose};
        let bytes = general_purpose::STANDARD.decode(image.b64_json.clone())?;
        Ok(bytes)
    }
}
