# `minecraft-msa-auth`

This crate allows you to authenticate into Minecraft online services using a Microsoft Oauth2 token. You can integrate it with [oauth2-rs](https://github.com/ramosbugs/oauth2-rs) and build interactive authentication flows.

# Example

```rust
const DEVICE_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const MSA_AUTHORIZE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const MSA_TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

let client = BasicClient::new(
    ClientId::new(client_id),
    None,
    AuthUrl::new(MSA_AUTHORIZE_URL.to_string())?,
    Some(TokenUrl::new(MSA_TOKEN_URL.to_string())?),
)
.set_device_authorization_url(DeviceAuthorizationUrl::new(DEVICE_CODE_URL.to_string())?);

let details: StandardDeviceAuthorizationResponse = client
    .exchange_device_code()?
    .add_scope(Scope::new("XboxLive.signin offline_access".to_string()))
    .request_async(async_http_client)
    .await?;

println!(
    "Open this URL in your browser: {} and enter the code: {}",
    details.verification_uri().to_string(),
    details.user_code().secret().to_string()
);

let token = client
    .exchange_device_access_token(&details)
    .request_async(async_http_client, tokio::time::sleep, None)
    .await?;
println!("microsoft token: {:?}", token);

let mc_flow = MinecraftAuthorizationFlow::new(Client::new());
let mc_token = mc_flow.exchange_microsoft_token(token.access_token()).await?;
println!("minecraft token: {:?}", mc_token);
```

See full examples in the [examples](examples) folder.

# License

Except where noted (below and/or in individual files), all code in this repository is dual-licensed under either:

* MIT License ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))