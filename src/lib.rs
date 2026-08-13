//! This crate allows you to authenticate into Minecraft online services using a
//! Microsoft Oauth2 token. You can integrate it with [oauth2-rs](https://github.com/ramosbugs/oauth2-rs)
//! and build interactive authentication flows.
//!
//! By default the flow is asynchronous and uses [reqwest](https://crates.io/crates/reqwest)
//! as the HTTP client, but any other client can be plugged in by implementing
//! the [HttpClient] trait and disabling the default `reqwest` feature.
//!
//! Enabling the `is_sync` feature turns the whole API synchronous: the
//! [HttpClient] trait and the flow methods lose their `async`, and the
//! `reqwest` implementation switches to [reqwest::blocking::Client]. This is
//! aimed at small launchers that do not want an async runtime, ideally
//! combined with the [ureq](https://crates.io/crates/ureq)-backed [UreqClient]
//! available behind the `ureq` feature.
//!
//! The example below assumes the default asynchronous mode.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(not(feature = "is_sync"))]
//! # {
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
//! # }
//! ```
use std::collections::HashMap;
use std::fmt::Debug;

use getset::{CopyGetters, Getters};
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use nutype::nutype;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MINECRAFT_LOGIN_WITH_XBOX: &str = "https://api.minecraftservices.com/authentication/login_with_xbox";
const XBOX_USER_AUTHENTICATE: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XBOX_XSTS_AUTHORIZE: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";

/// An HTTP request executed by an [HttpClient].
pub type HttpRequest = Request<Vec<u8>>;

/// An HTTP response returned by an [HttpClient].
pub type HttpResponse = http::Response<Vec<u8>>;

/// An HTTP client capable of executing the requests made by
/// [MinecraftAuthorizationFlow].
///
/// The trait is asynchronous by default and becomes synchronous when the
/// `is_sync` feature is enabled. Implementations should be annotated with
/// [macro@maybe_async::maybe_async] to support both modes.
///
/// An implementation for [reqwest::Client] ([reqwest::blocking::Client] with
/// `is_sync`) is provided behind the `reqwest` feature, which is enabled by
/// default.
#[maybe_async::maybe_async]
pub trait HttpClient {
    /// The error type returned when a request fails at the transport level.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Executes the given request, returning the response with its full body.
    async fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error>;
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

    /// Xbox Live rejected authentication with an unrecognized error code
    #[error("Xbox Live authentication failed with error code {code}")]
    XboxLive { code: u32 },
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

/// The error response from Xbox when authenticating with a Microsoft token.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XboxLiveErrorResponse {
    #[serde(rename = "XErr")]
    code: XboxLiveErrorCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(from = "u32")]
enum XboxLiveErrorCode {
    XboxAccountRequired,
    FamilyMembershipRequired,
    Unknown(u32),
}

impl From<u32> for XboxLiveErrorCode {
    fn from(code: u32) -> Self {
        match code {
            2_148_916_233 => Self::XboxAccountRequired,
            2_148_916_238 => Self::FamilyMembershipRequired,
            code => Self::Unknown(code),
        }
    }
}

/// The flow for authenticating with a Microsoft access token and getting a
/// Minecraft access token.
pub struct MinecraftAuthorizationFlow<C> {
    http_client: C,
}

impl<C> MinecraftAuthorizationFlow<C> {
    /// Creates a new [MinecraftAuthorizationFlow] using the given
    /// [HttpClient].
    pub const fn new(http_client: C) -> Self {
        Self { http_client }
    }
}

#[maybe_async::maybe_async]
impl<C: HttpClient> MinecraftAuthorizationFlow<C> {
    /// Authenticates with the Microsoft identity platform using the given
    /// Microsoft access token and returns a [MinecraftAuthenticationResponse]
    /// that contains the Minecraft access token.
    pub async fn exchange_microsoft_token(
        &self, microsoft_access_token: impl AsRef<str>,
    ) -> Result<MinecraftAuthenticationResponse, MinecraftAuthorizationError<C::Error>> {
        #[derive(Serialize)]
        struct MinecraftAuthenticationRequest {
            #[serde(rename = "identityToken")]
            identity_token: String,
        }

        let (xbox_token, user_hash) = self.xbox_token(microsoft_access_token).await?;
        let xbox_security_token = self.xbox_security_token(xbox_token).await?;

        let response = self
            .post_json(MINECRAFT_LOGIN_WITH_XBOX, &MinecraftAuthenticationRequest {
                identity_token: format!(
                    "XBL3.0 x={user_hash};{xsts_token}",
                    user_hash = user_hash,
                    xsts_token = xbox_security_token.token
                ),
            })
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
        #[derive(Serialize)]
        struct Properties {
            #[serde(rename = "SandboxId")]
            sandbox_id: &'static str,
            #[serde(rename = "UserTokens")]
            user_tokens: [String; 1],
        }

        #[derive(Serialize)]
        struct XboxSecurityTokenRequest {
            #[serde(rename = "Properties")]
            properties: Properties,
            #[serde(rename = "RelyingParty")]
            relying_party: &'static str,
            #[serde(rename = "TokenType")]
            token_type: &'static str,
        }

        let response = self
            .post_json(XBOX_XSTS_AUTHORIZE, &XboxSecurityTokenRequest {
                properties: Properties {
                    sandbox_id: "RETAIL",
                    user_tokens: [xbox_token],
                },
                relying_party: "rp://api.minecraftservices.com/",
                token_type: "JWT",
            })
            .await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            let error: XboxLiveErrorResponse = serde_json::from_slice(response.body())?;
            Err(match error.code {
                XboxLiveErrorCode::XboxAccountRequired => MinecraftAuthorizationError::NoXbox,
                XboxLiveErrorCode::FamilyMembershipRequired => MinecraftAuthorizationError::AddToFamily,
                XboxLiveErrorCode::Unknown(code) => MinecraftAuthorizationError::XboxLive { code },
            })
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
        #[derive(Serialize)]
        struct Properties {
            #[serde(rename = "AuthMethod")]
            auth_method: &'static str,
            #[serde(rename = "SiteName")]
            site_name: &'static str,
            #[serde(rename = "RpsTicket")]
            rps_ticket: String,
        }

        #[derive(Serialize)]
        struct XboxTokenRequest {
            #[serde(rename = "Properties")]
            properties: Properties,
            #[serde(rename = "RelyingParty")]
            relying_party: &'static str,
            #[serde(rename = "TokenType")]
            token_type: &'static str,
        }

        let response = self
            .post_json(XBOX_USER_AUTHENTICATE, &XboxTokenRequest {
                properties: Properties {
                    auth_method: "RPS",
                    site_name: "user.auth.xboxlive.com",
                    rps_ticket: format!("d={}", microsoft_access_token.as_ref()),
                },
                relying_party: "http://auth.xboxlive.com",
                token_type: "JWT",
            })
            .await?;
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

    async fn post_json<T: Serialize>(
        &self, url: &str, body: &T,
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
    use super::{HttpClient, HttpRequest, HttpResponse};

    #[maybe_async::async_impl]
    impl HttpClient for reqwest::Client {
        type Error = reqwest::Error;

        async fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            let response = self.execute(reqwest::Request::try_from(request)?).await?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await?.to_vec();

            let mut response = HttpResponse::new(body);
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            Ok(response)
        }
    }

    #[maybe_async::sync_impl]
    impl HttpClient for reqwest::blocking::Client {
        type Error = reqwest::Error;

        fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            let response = self.execute(reqwest::blocking::Request::try_from(request)?)?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes()?.to_vec();

            let mut response = HttpResponse::new(body);
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            Ok(response)
        }
    }
}

#[cfg(feature = "ureq")]
pub use ureq_client::UreqClient;

#[cfg(feature = "ureq")]
mod ureq_client {
    use super::{HttpClient, HttpRequest, HttpResponse};

    /// An [HttpClient] backed by [ureq](https://crates.io/crates/ureq).
    ///
    /// Requests are always executed synchronously, so this client is intended
    /// for use with the `is_sync` feature, where the whole flow becomes
    /// blocking and no async runtime is needed:
    ///
    /// ```ignore
    /// // with features = ["ureq", "is_sync"]
    /// let mc_flow = MinecraftAuthorizationFlow::new(UreqClient::default());
    /// let mc_token = mc_flow.exchange_microsoft_token("msa token")?;
    /// ```
    ///
    /// Without `is_sync` the client still works, but it will block the
    /// executor thread while a request is in flight.
    #[derive(Debug, Clone)]
    pub struct UreqClient(ureq::Agent);

    impl UreqClient {
        /// Creates a [UreqClient] from an existing [ureq::Agent].
        ///
        /// The agent must be configured with
        /// [http_status_as_error(false)](ureq::config::ConfigBuilder::http_status_as_error),
        /// otherwise error responses from the Xbox services cannot be
        /// inspected and specific errors like
        /// [MinecraftAuthorizationError::AddToFamily](super::MinecraftAuthorizationError::AddToFamily)
        /// cannot be reported.
        pub fn with_agent(agent: ureq::Agent) -> Self {
            Self(agent)
        }
    }

    impl Default for UreqClient {
        fn default() -> Self {
            Self(ureq::Agent::config_builder().http_status_as_error(false).build().into())
        }
    }

    #[maybe_async::maybe_async]
    impl HttpClient for UreqClient {
        type Error = ureq::Error;

        async fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            let response = self.0.run(request)?;
            let (parts, mut body) = response.into_parts();
            Ok(HttpResponse::from_parts(parts, body.read_to_vec()?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{XboxLiveErrorCode, XboxLiveErrorResponse};

    #[test]
    fn deserializes_known_xbox_live_error_codes() {
        let no_xbox: XboxLiveErrorResponse =
            serde_json::from_str(r#"{"Identity":"0","XErr":2148916233,"Message":"","Redirect":""}"#).unwrap();
        let add_to_family: XboxLiveErrorResponse =
            serde_json::from_str(r#"{"Identity":"0","XErr":2148916238,"Message":"","Redirect":""}"#).unwrap();

        assert_eq!(no_xbox.code, XboxLiveErrorCode::XboxAccountRequired);
        assert_eq!(add_to_family.code, XboxLiveErrorCode::FamilyMembershipRequired);
    }

    #[test]
    fn preserves_unknown_xbox_live_error_codes() {
        let response: XboxLiveErrorResponse = serde_json::from_str(r#"{"XErr":42}"#).unwrap();

        assert_eq!(response.code, XboxLiveErrorCode::Unknown(42));
    }

    #[test]
    fn rejects_malformed_xbox_live_error_responses() {
        let response = serde_json::from_str::<XboxLiveErrorResponse>(r#"{"XErr":"invalid"}"#);

        assert!(response.is_err());
    }
}
