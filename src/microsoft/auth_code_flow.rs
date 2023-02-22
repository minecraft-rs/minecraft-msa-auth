use reqwest::{Client as HttpClient, Response, StatusCode};
use thiserror::Error;

use super::{MicrosoftError, MicrosoftClientId};

const MICROSOFT_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const MICROSOFT_CODE_RESPONSE_TYPE: &str = "code";
const MICROSOFT_CODE_GRANT_TYPE: &str = "authorization_code";

#[derive(Error, Debug)]
pub enum AuthorizationCodeFlowError {
    #[error("Microsoft API error: {0}: {1}")]
    MicrosoftHttp(StatusCode, MicrosoftError),
    
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

/// Uses the Microsoft identity platform [Authorization Code Flow] to obtain a
/// Minecraft access token. This requires the user to manually enter a code on
/// a web page.
/// 
/// [Authorization Code Flow]: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
#[derive(Debug, Clone)]
pub struct MicrosoftAuthorizationCodeFlow {
    client_id: MicrosoftClientId,
    http_client: HttpClient,
}


impl MicrosoftAuthorizationCodeFlow {
    /// Creates a new [MicrosoftAuthorizationCodeFlow] with the given client ID.
    pub fn new(client_id: MicrosoftClientId, http_client: HttpClient) -> Self {
        Self { client_id, http_client }
    }
}