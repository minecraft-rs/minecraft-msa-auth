use std::collections::HashMap;

use getset::{CopyGetters, Getters};
use reqwest::{Client as HttpClient, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

use crate::microsoft::device_flow::{MicrosoftAuthenticationResponse};

const MINECRAFT_LOGIN_WITH_XBOX: &str = "https://api.minecraftservices.com/authentication/login_with_xbox";
const XBOX_USER_AUTHERNITATE: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XBOX_XSTS_AUTHORIZE: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";

#[derive(Error, Debug)]
pub enum MinecraftAuthorizationError {
    #[error("Http error: {0}")]
    Http(StatusCode, String),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

/// The response from Minecraft when attempting to authenticate with an xbox
/// token
#[derive(Deserialize, Debug, Getters, CopyGetters, Clone)]
pub struct MinecraftAuthenticationResponse {
    /// Some UUID of the account
    #[getset(get = "pub")]
    username: String,

    /// The minecraft JWT access token
    #[getset(get = "pub")]
    access_token: String,

    /// The type of access token
    #[getset(get = "pub")]
    token_type: String,

    /// How many seconds until the token expires
    #[getset(get_copy = "pub")]
    expires_in: u32,
}

/// The response from Xbox when authenticating with a Microsoft token
#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct XboxLiveAuthenticationResponse {
    /// The xbox authentication token to use
    token: String,

    /// An object that contains a vec of `uhs` objects
    /// Looks like { "xui": [{"uhs": "xbl_token"}] }
    display_claims: HashMap<String, Vec<HashMap<String, String>>>,
}

/// The flow for authenticating with a Microsoft access token and getting a
/// Minecraft access token.
pub struct MinecraftAuthorizationFlow {
    http_client: HttpClient,
}

impl MinecraftAuthorizationFlow {
    /// Creates a new [MinecraftAuthorizationFlow].
    pub fn new(http_client: HttpClient) -> Self {
        Self { http_client }
    }

    /// Authenticates with the Microsoft identity platform using the given
    /// Microsoft access token and returns a [MinecraftAuthenticationResponse]
    /// that contains the Minecraft access token.
    pub async fn exchange_microsoft_token(
        &self, authorization_token: &MicrosoftAuthenticationResponse,
    ) -> Result<MinecraftAuthenticationResponse, MinecraftAuthorizationError> {
        let xbox_authenticate_json = json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": &format!("d={}", authorization_token.access_token())
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        });
        let response = self
            .http_client
            .post(XBOX_USER_AUTHERNITATE)
            .json(&xbox_authenticate_json)
            .send()
            .await?;
        let response = error_for_status(response).await?;
        let xbox_resp: XboxLiveAuthenticationResponse = response.json().await?;

        let xbox_token = &xbox_resp.token;
        let user_hash = &xbox_resp.display_claims["xui"][0]["uhs"];

        let response = self
            .http_client
            .post(XBOX_XSTS_AUTHORIZE)
            .json(&json!({
                "Properties": {
                    "SandboxId": "RETAIL",
                    "UserTokens": [xbox_token]
                },
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT"
            }))
            .send()
            .await?;
        let response = error_for_status(response).await?;
        let xbox_security_token_resp: XboxLiveAuthenticationResponse = response.json().await?;

        let xbox_security_token = &xbox_security_token_resp.token;
        let response = self
            .http_client
            .post(MINECRAFT_LOGIN_WITH_XBOX)
            .json(&json!({
                "identityToken":
                    format!(
                        "XBL3.0 x={user_hash};{xsts_token}",
                        user_hash = user_hash,
                        xsts_token = xbox_security_token
                    )
            }))
            .send()
            .await?;
        let response = error_for_status(response).await?;
        let minecraft_resp: MinecraftAuthenticationResponse = response.json().await?;
        Ok(minecraft_resp)
    }
}

async fn error_for_status(response: Response) -> Result<Response, MinecraftAuthorizationError> {
    let status = response.status();
    if !status.is_success() {
        let response = response.text().await?;
        return Err(MinecraftAuthorizationError::Http(status, response));
    }
    Ok(response)
}
