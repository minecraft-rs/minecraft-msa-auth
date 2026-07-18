//! This crate allows you to authenticate into Minecraft online services using a
//! Microsoft Oauth2 token. You can integrate it with [oauth2-rs](https://github.com/ramosbugs/oauth2-rs)
//! and build interactive authentication flows.
//!
//! By default the flow uses [reqwest](https://crates.io/crates/reqwest) as the HTTP client,
//! but any other client can be plugged in by implementing the [AsyncHttpClient]
//! trait and disabling the default `reqwest` feature.
//!
//! # Example
//!
//! ```no_run
//! # use minecraft_msa_auth::MinecraftAuthorizationFlow;
//! # use oauth2::basic::BasicClient;
//! # use oauth2::{
//! #     AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, StandardDeviceAuthorizationResponse, TokenResponse,
//! #     TokenUrl,
//! # };
//! # use reqwest::Client;
//! #
//! # const DEVICE_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
//! # const MSA_AUTHORIZE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
//! # const MSA_TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
//! #
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let client_id = std::env::args().nth(1).expect("client_id as first argument");
//! let client = BasicClient::new(ClientId::new(client_id))
//!     .set_auth_uri(AuthUrl::new(MSA_AUTHORIZE_URL.to_string())?)
//!     .set_token_uri(TokenUrl::new(MSA_TOKEN_URL.to_string())?)
//!     .set_device_authorization_url(DeviceAuthorizationUrl::new(DEVICE_CODE_URL.to_string())?);
//!
//! // oauth2 bundles its own reqwest version, which may differ from the one
//! // minecraft-msa-auth is built against.
//! let oauth_http_client = oauth2::reqwest::Client::new();
//! let details: StandardDeviceAuthorizationResponse = client
//!     .exchange_device_code()
//!     .add_scope(Scope::new("XboxLive.signin offline_access".to_string()))
//!     .request_async(&oauth_http_client)
//!     .await?;
//!
//! println!(
//!     "Open this URL in your browser:\n{}\nand enter the code: {}",
//!     details.verification_uri().to_string(),
//!     details.user_code().secret().to_string()
//! );
//!
//! let token = client
//!     .exchange_device_access_token(&details)
//!     .request_async(&oauth_http_client, tokio::time::sleep, None)
//!     .await?;
//! println!("microsoft token: {:?}", token);
//!
//! let mc_flow = MinecraftAuthorizationFlow::new(Client::new());
//! let mc_token = mc_flow.exchange_microsoft_token(token.access_token().secret()).await?;
//! println!("minecraft token: {:?}", mc_token);
//! # Ok(())
//! # }
//! ```
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

use getset::{CopyGetters, Getters};
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use nutype::nutype;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

const MINECRAFT_LOGIN_WITH_XBOX: &str = "https://api.minecraftservices.com/authentication/login_with_xbox";
const XBOX_USER_AUTHENTICATE: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XBOX_XSTS_AUTHORIZE: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";

/// An HTTP request executed by an [AsyncHttpClient].
pub type HttpRequest = Request<Vec<u8>>;

/// An HTTP response returned by an [AsyncHttpClient].
pub type HttpResponse = http::Response<Vec<u8>>;

/// An asynchronous HTTP client capable of executing the requests made by
/// [MinecraftAuthorizationFlow].
///
/// An implementation for [reqwest::Client] is provided behind the `reqwest`
/// feature, which is enabled by default.
pub trait AsyncHttpClient {
    /// The error type returned when a request fails at the transport level.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Executes the given request, returning the response with its full body.
    fn call<'a>(
        &'a self, request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'a>>;
}

/// Represents a Minecraft access token
#[nutype(
    validate(not_empty),
    derive(Clone, PartialEq, Eq, Hash, Deserialize, Serialize, AsRef, Into)
)]
pub struct MinecraftAccessToken(String);

impl Debug for MinecraftAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MinecraftAccessToken").field(&"[redacted]").finish()
    }
}

/// Represents the token type of a Minecraft access token
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum MinecraftTokenType {
    Bearer,
}

/// Represents an error that can occur when authenticating with Minecraft.
#[derive(Error, Debug)]
pub enum MinecraftAuthorizationError<E: std::error::Error> {
    /// An error occurred while executing the HTTP request
    #[error(transparent)]
    Http(E),

    /// The server responded with a non-success status code
    #[error("HTTP status error: {0}")]
    HttpStatus(StatusCode),

    /// An error occurred while serializing or deserializing JSON
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Account belongs to a minor who needs to be added to a microsoft family
    #[error("Minor must be added to microsoft family")]
    AddToFamily,

    /// Account does not have xbox, user must create an xbox account to continue
    #[error("Account does not have xbox")]
    NoXbox,

    /// Claims were missing from the response
    #[error("missing claims from response")]
    MissingClaims,
}

/// The response from Minecraft when attempting to authenticate with an xbox
/// token
#[derive(Deserialize, Serialize, Debug, Getters, CopyGetters, Clone)]
pub struct MinecraftAuthenticationResponse {
    /// UUID of the Xbox account.
    /// Please note that this is not the Minecraft player's UUID
    #[getset(get = "pub")]
    username: String,

    /// The minecraft JWT access token
    #[getset(get = "pub")]
    access_token: MinecraftAccessToken,

    /// The type of access token
    #[getset(get = "pub")]
    token_type: MinecraftTokenType,

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

/// The error response from Xbox when authenticating with a Microsoft token
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XboxLiveAuthenticationResponseError {
    /// Always zero
    identity: String,

    /// Error id
    /// 2148916238 means <18 and needs to be added to microsoft family
    /// 2148916233 means xbox account needs to be created
    x_err: i64,

    /// Message about error
    message: String,

    /// Where to go to fix the error as a user
    redirect: String,
}

/// The flow for authenticating with a Microsoft access token and getting a
/// Minecraft access token.
pub struct MinecraftAuthorizationFlow<C> {
    http_client: C,
}

impl<C> MinecraftAuthorizationFlow<C> {
    /// Creates a new [MinecraftAuthorizationFlow] using the given
    /// [AsyncHttpClient].
    pub const fn new(http_client: C) -> Self {
        Self { http_client }
    }
}

impl<C: AsyncHttpClient> MinecraftAuthorizationFlow<C> {
    /// Authenticates with the Microsoft identity platform using the given
    /// Microsoft access token and returns a [MinecraftAuthenticationResponse]
    /// that contains the Minecraft access token.
    pub async fn exchange_microsoft_token(
        &self, microsoft_access_token: impl AsRef<str>,
    ) -> Result<MinecraftAuthenticationResponse, MinecraftAuthorizationError<C::Error>> {
        let (xbox_token, user_hash) = self.xbox_token(microsoft_access_token).await?;
        let xbox_security_token = self.xbox_security_token(xbox_token).await?;

        let response = self
            .post_json(
                MINECRAFT_LOGIN_WITH_XBOX,
                &json!({
                    "identityToken":
                        format!(
                            "XBL3.0 x={user_hash};{xsts_token}",
                            user_hash = user_hash,
                            xsts_token = xbox_security_token.token
                        )
                }),
            )
            .await?;
        if !response.status().is_success() {
            return Err(MinecraftAuthorizationError::HttpStatus(response.status()));
        }

        let response = serde_json::from_slice(response.body())?;
        Ok(response)
    }

    async fn xbox_security_token(
        &self, xbox_token: String,
    ) -> Result<XboxLiveAuthenticationResponse, MinecraftAuthorizationError<C::Error>> {
        let response = self
            .post_json(
                XBOX_XSTS_AUTHORIZE,
                &json!({
                    "Properties": {
                        "SandboxId": "RETAIL",
                        "UserTokens": [xbox_token]
                    },
                    "RelyingParty": "rp://api.minecraftservices.com/",
                    "TokenType": "JWT"
                }),
            )
            .await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            let xbox_security_token_err_resp_res = serde_json::from_slice(response.body());
            if xbox_security_token_err_resp_res.is_err() {
                return Err(MinecraftAuthorizationError::MissingClaims);
            }
            let xbox_security_token_err_resp: XboxLiveAuthenticationResponseError =
                xbox_security_token_err_resp_res.expect("This should succeed always");
            match xbox_security_token_err_resp.x_err {
                2148916238 => Err(MinecraftAuthorizationError::AddToFamily),
                2148916233 => Err(MinecraftAuthorizationError::NoXbox),
                _ => Err(MinecraftAuthorizationError::MissingClaims),
            }
        } else if !response.status().is_success() {
            Err(MinecraftAuthorizationError::HttpStatus(response.status()))
        } else {
            let xbox_security_token_resp: XboxLiveAuthenticationResponse = serde_json::from_slice(response.body())?;
            Ok(xbox_security_token_resp)
        }
    }

    async fn xbox_token(
        &self, microsoft_access_token: impl AsRef<str>,
    ) -> Result<(String, String), MinecraftAuthorizationError<C::Error>> {
        let xbox_authenticate_json = json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": &format!("d={}", microsoft_access_token.as_ref())
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        });
        let response = self.post_json(XBOX_USER_AUTHENTICATE, &xbox_authenticate_json).await?;
        if !response.status().is_success() {
            return Err(MinecraftAuthorizationError::HttpStatus(response.status()));
        }

        let xbox_resp: XboxLiveAuthenticationResponse = serde_json::from_slice(response.body())?;
        let xbox_token = xbox_resp.token;
        let user_hash = xbox_resp
            .display_claims
            .get("xui")
            .ok_or(MinecraftAuthorizationError::MissingClaims)?
            .first()
            .ok_or(MinecraftAuthorizationError::MissingClaims)?
            .get("uhs")
            .ok_or(MinecraftAuthorizationError::MissingClaims)?
            .to_owned();
        Ok((xbox_token, user_hash))
    }

    async fn post_json(
        &self, url: &str, body: &serde_json::Value,
    ) -> Result<HttpResponse, MinecraftAuthorizationError<C::Error>> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .body(serde_json::to_vec(body)?)
            .expect("static request parts should be valid");
        self.http_client
            .call(request)
            .await
            .map_err(MinecraftAuthorizationError::Http)
    }
}

#[cfg(feature = "reqwest")]
mod reqwest_client {
    use std::future::Future;
    use std::pin::Pin;

    use super::{AsyncHttpClient, HttpRequest, HttpResponse};

    impl AsyncHttpClient for reqwest::Client {
        type Error = reqwest::Error;

        fn call<'a>(
            &'a self, request: HttpRequest,
        ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'a>> {
            Box::pin(async move {
                let response = self.execute(reqwest::Request::try_from(request)?).await?;
                let status = response.status();
                let headers = response.headers().clone();
                let body = response.bytes().await?.to_vec();

                let mut response = HttpResponse::new(body);
                *response.status_mut() = status;
                *response.headers_mut() = headers;
                Ok(response)
            })
        }
    }
}
