//! Synchronous device code flow using the ureq-backed client.
//!
//! Run with the `ureq` and `is_sync` features and no async runtime:
//!
//! ```sh
//! cargo run --no-default-features --features "ureq is_sync" --example sync_device_flow <client_id>
//! ```
use minecraft_msa_auth::{MinecraftAuthorizationFlow, UreqClient};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
};

const DEVICE_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const MSA_AUTHORIZE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const MSA_TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_id = std::env::args().nth(1).expect("client_id as first argument");
    let client = BasicClient::new(ClientId::new(client_id))
        .set_auth_uri(AuthUrl::new(MSA_AUTHORIZE_URL.to_string())?)
        .set_token_uri(TokenUrl::new(MSA_TOKEN_URL.to_string())?)
        .set_device_authorization_url(DeviceAuthorizationUrl::new(DEVICE_CODE_URL.to_string())?);

    // oauth2 bundles its own reqwest version, which may differ from the one
    // minecraft-msa-auth is built against.
    let oauth_http_client = oauth2::reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()?;
    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scope(Scope::new("XboxLive.signin offline_access".to_string()))
        .request(&oauth_http_client)?;

    println!(
        "Open this URL in your browser:\n{}\nand enter the code: {}",
        details.verification_uri().to_string(),
        details.user_code().secret().to_string()
    );

    let token = client
        .exchange_device_access_token(&details)
        .request(&oauth_http_client, std::thread::sleep, None)?;
    println!("microsoft token: {:?}", token);

    let mc_flow = MinecraftAuthorizationFlow::new(UreqClient::default());
    let mc_token = mc_flow.exchange_microsoft_token(token.access_token().secret())?;
    println!("minecraft token: {:?}", mc_token);
    Ok(())
}
