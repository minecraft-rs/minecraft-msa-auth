use std::time::Duration;

use getset::{CopyGetters, Getters};
use reqwest::{Client as HttpClient, Response, StatusCode};
use serde::Deserialize;
use tokio::time::sleep;

use super::{MicrosoftClientId, MicrosoftError};
use crate::Error;

const MICROSOFT_DEVICE_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const MICROSOFT_DEVICE_TOKEN_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MICROSOFT_TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const MICROSOFT_TOKEN_SCOPE: &str = "XboxLive.signin offline_access";

/// An error returned by the Microsoft identity platform when using the Device
/// Authorization Flow.
#[derive(Error, Debug)]
pub enum DeviceAuthorizationFlowError {
    /// The end user denied the authorization request.
    #[error("The end user denied the authorization request.")]
    Declined,

    /// The authorization request has expired.
    #[error("The authorization request has expired.")]
    Expired,

    #[error("An error occurred while communicating with the Microsoft identity platform.")]
    Other(String),

    #[error("Microsoft API error: {0}: {1}")]
    MicrosoftHttp(StatusCode, MicrosoftError),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

/// Uses the Microsoft identity platform [Device Authorization Flow] to obtain a
/// Minecraft access token. This requires the user to manually enter a code on
/// a web page.
///
/// [Device Authorization Flow]: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
#[derive(Debug, Clone)]
pub struct MicrosoftDeviceAuthorizationFlow {
    client_id: MicrosoftClientId,
    http_client: HttpClient,
}

/// Contains the response from the Microsoft identity platform [Device
/// Authorization Flow]. This response contains a device code, user code,
/// verification URI, and other information that is used to obtain a Minecraft
/// access token.
///
/// [Device Authorization Flow]: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
#[derive(Deserialize, Debug, Getters, CopyGetters, Clone)]
pub struct DeviceAuthorizationResponse {
    /// A long string used to verify the session between the client and the
    /// authorization server. The client uses this parameter to request the
    /// access token from the authorization server.
    #[getset(get = "pub")]
    device_code: String,

    /// A short string shown to the user that's used to identify the session on
    /// a secondary device.
    #[getset(get = "pub")]
    user_code: String,

    /// The URI the user should go to with the `user_code` in order to sign in.
    #[getset(get = "pub")]
    verification_uri: String,

    /// The number of seconds before the device_code and user_code expire.
    #[getset(get_copy = "pub")]
    expires_in: u32,

    /// The number of seconds the client should wait between polling requests.
    #[getset(get_copy = "pub")]
    interval: u64,

    /// A human-readable string with instructions for the user. This can be
    /// localized by including a query parameter in the request of the form
    /// `?mkt=xx-XX`, filling in the appropriate language culture code.
    #[getset(get = "pub")]
    message: String,
}

#[derive(Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum MicrosoftTokenType {
    Bearer,
}

/// Contains the response from the Microsoft identity platform [Device
/// Authorization Flow]. This response contains the Microsoft access token and
/// refresh token.
///
/// [Device Authorization Flow]: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
#[derive(Deserialize, Debug, Getters, CopyGetters, Clone)]
pub struct MicrosoftAuthenticationResponse {
    /// The type of token for authentication
    #[getset(get = "pub")]
    token_type: MicrosoftTokenType,

    /// This lists the scopes in which the access token is valid for.
    #[getset(get = "pub")]
    scope: String,

    /// Number of seconds the included access token is valid for.
    #[getset(get_copy = "pub")]
    expires_in: u32,

    /// Issued for the scopes that were requested.
    #[getset(get = "pub")]
    access_token: String,

    /// Issued if the original scope parameter included offline_access.
    #[getset(get = "pub")]
    refresh_token: String,
}

impl MicrosoftDeviceAuthorizationFlow {
    /// Creates a new [DeviceAuthorizationFlow] with the given client ID.
    pub fn new(client_id: MicrosoftClientId, http_client: HttpClient) -> Self {
        Self { client_id, http_client }
    }

    /// Starts the Device Authorization Flow. This returns a
    /// [DeviceAuthorizationResponse] that contains a device code, user code,
    /// verification URI, and other information that is used to obtain a
    /// Minecraft access token.
    pub async fn start(&self) -> Result<DeviceAuthorizationResponse, DeviceAuthorizationFlowError> {
        let response = self
            .http_client
            .post(MICROSOFT_DEVICE_CODE_URL)
            .form(&[("client_id", self.client_id.as_ref()), ("scope", MICROSOFT_TOKEN_SCOPE)])
            .send()
            .await?;
        let response = error_for_status(response).await?;
        let response = response.json::<DeviceAuthorizationResponse>().await?;
        Ok(response)
    }

    /// Checks if the user has logged in yet. You should call this method every
    /// `interval` seconds, where `interval` is the `interval` field of the
    /// [DeviceAuthorizationResponse] that was returned from
    /// [DeviceAuthorizationFlow::start].
    ///
    /// # Arguments
    ///
    /// * `authorization` - The [DeviceAuthorizationResponse] that was returned
    ///  from [DeviceAuthorizationFlow::start].
    ///
    /// # Returns
    ///
    /// - If the user has logged in, this returns a [MicrosoftTokenResponse]
    ///   that
    /// contains the Microsoft access token and refresh token.
    ///
    /// - If the user has not logged in yet, this returns [None].
    ///
    /// - If the user has denied the authorization request, this returns
    /// [DeviceAuthorizationError::Declined].
    ///
    /// - If the authorization request has expired, this returns
    /// [DeviceAuthorizationError::Expired].
    pub async fn check_login(
        &self, authorization: &DeviceAuthorizationResponse,
    ) -> Result<Option<MicrosoftAuthenticationResponse>, DeviceAuthorizationFlowError> {
        let response = self
            .http_client
            .post(MICROSOFT_TOKEN_URL)
            .form(&[
                ("client_id", self.client_id.as_ref()),
                ("scope", MICROSOFT_TOKEN_SCOPE),
                ("grant_type", MICROSOFT_DEVICE_TOKEN_GRANT_TYPE),
                ("device_code", authorization.device_code.as_ref()),
            ])
            .send()
            .await?;

        #[derive(Deserialize)]
        struct MicrosoftErrorResponse {
            error: String,
        }

        if response.status() == StatusCode::BAD_REQUEST {
            let response = response.json::<MicrosoftErrorResponse>().await?;
            match response.error.as_str() {
                "authorization_declined" => {
                    return Err(DeviceAuthorizationFlowError::Declined);
                },
                "expired_token" => {
                    return Err(DeviceAuthorizationFlowError::Expired);
                },
                "authorization_pending" => {
                    return Ok(None);
                },
                other => {
                    return Err(DeviceAuthorizationFlowError::Other(other.to_string()));
                },
            };
        }

        let response = error_for_status(response).await?;
        let response = response.json::<MicrosoftAuthenticationResponse>().await?;
        Ok(Some(response))
    }

    /// Waits until the Microsoft identity platform has verified the user code
    /// and returns a [MicrosoftTokenResponse] that contains the Microsoft
    /// access token and refresh token.
    pub async fn wait_for_login(
        &self, authorization: &DeviceAuthorizationResponse,
    ) -> Result<MicrosoftAuthenticationResponse, DeviceAuthorizationFlowError> {
        loop {
            if let Some(response) = self.check_login(authorization).await? {
                return Ok(response);
            }
            sleep(Duration::from_secs(authorization.interval)).await;
        }
    }
}

async fn error_for_status(response: Response) -> Result<Response, DeviceAuthorizationFlowError> {
    let status = response.status();
    if !status.is_success() {
        let response = response.json().await?;
        return Err(DeviceAuthorizationFlowError::MicrosoftHttp(status, response));
    }
    Ok(response)
}
