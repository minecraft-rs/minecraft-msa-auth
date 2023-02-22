use minecraft_microsoft_auth::MinecraftAuthorizationFlow;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
    TokenUrl,
};
use reqwest::{Client, Url};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_id = std::env::args().nth(1).expect("client_id as first argument");

    let client = BasicClient::new(
        ClientId::new(client_id),
        None,
        AuthUrl::new("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize".to_string())?,
        Some(TokenUrl::new(
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/token".to_string(),
        )?),
    )
    // Microsoft requires client_id in URL rather than using Basic authentication.
    .set_auth_type(AuthType::RequestBody)
    // This example will be running its own server at 127.0.0.1:8114.
    // See below for the server implementation.
    .set_redirect_uri(
        RedirectUrl::new("http://127.0.0.1:8114/redirect".to_string())
            .expect("Invalid redirect URL"),
    );

    // Microsoft supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("XboxLive.signin offline_access".to_string()))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    println!("Open this URL in your browser:\n{}\n", authorize_url.to_string());

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8114").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        stream.readable().await?;
        let mut stream = BufReader::new(stream);

        let code;
        let state;
        {
            let mut request_line = String::new();
            stream.read_line(&mut request_line).await?;

            let redirect_url = request_line.split_whitespace().nth(1).unwrap();
            let url = Url::parse(&("http://localhost".to_string() + redirect_url))?;

            let code_pair = url
                .query_pairs()
                .find(|pair| {
                    let &(ref key, _) = pair;
                    key == "code"
                })
                .unwrap();

            let (_, value) = code_pair;
            code = AuthorizationCode::new(value.into_owned());

            let state_pair = url
                .query_pairs()
                .find(|pair| {
                    let &(ref key, _) = pair;
                    key == "state"
                })
                .unwrap();

            let (_, value) = state_pair;
            state = CsrfToken::new(value.into_owned());
        }

        let message = "Go back to your terminal :)";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
            message.len(),
            message
        );
        stream.write_all(response.as_bytes()).await?;

        println!("MS returned the following code:\n{}\n", code.secret());
        println!(
            "MS returned the following state:\n{} (expected `{}`)\n",
            state.secret(),
            csrf_state.secret()
        );

        // Exchange the code with a token.
        let token = client
            .exchange_code(code)
            // Send the PKCE code verifier in the token request
            .set_pkce_verifier(pkce_code_verifier)
            .request_async(async_http_client).await?;

        println!("microsoft token:\n{:?}\n", token);

        let mc_flow = MinecraftAuthorizationFlow::new(Client::new());
        let mc_token = mc_flow.exchange_microsoft_token(token.access_token()).await?;
        println!("minecraft token: {:?}", mc_token);

        // The server will terminate itself after collecting the first code.
        break;
    }
    Ok(())
}
