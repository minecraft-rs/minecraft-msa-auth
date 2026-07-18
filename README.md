# `minecraft-msa-auth`

[![Crates.io](https://img.shields.io/crates/v/minecraft-msa-auth.svg)](https://crates.io/crates/minecraft-msa-auth)
[![docs.rs](https://img.shields.io/docsrs/minecraft-msa-auth)](https://docs.rs/minecraft-msa-auth)
[![MIT/Apache 2.0](https://img.shields.io/badge/license-MIT%2FApache-blue.svg)](https://github.com/KernelFreeze/minecraft-msa-auth#license)
[![Crates.io](https://img.shields.io/crates/d/minecraft-msa-auth.svg)](https://crates.io/crates/minecraft-msa-auth)
[![Rust](https://github.com/KernelFreeze/minecraft-msa-auth/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/KernelFreeze/minecraft-msa-auth/actions/workflows/rust.yml)

This crate allows you to authenticate into Minecraft online services using a Microsoft Oauth2 token. You can integrate it with [oauth2-rs](https://github.com/ramosbugs/oauth2-rs) and build interactive authentication flows.

# Example

```rust
const DEVICE_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const MSA_AUTHORIZE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const MSA_TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

let client = BasicClient::new(ClientId::new(client_id))
    .set_auth_uri(AuthUrl::new(MSA_AUTHORIZE_URL.to_string())?)
    .set_token_uri(TokenUrl::new(MSA_TOKEN_URL.to_string())?)
    .set_device_authorization_url(DeviceAuthorizationUrl::new(DEVICE_CODE_URL.to_string())?);

let oauth_http_client = oauth2::reqwest::Client::new();
let details: StandardDeviceAuthorizationResponse = client
    .exchange_device_code()
    .add_scope(Scope::new("XboxLive.signin offline_access".to_string()))
    .request_async(&oauth_http_client)
    .await?;

println!(
    "Open this URL in your browser: {} and enter the code: {}",
    details.verification_uri().to_string(),
    details.user_code().secret().to_string()
);

let token = client
    .exchange_device_access_token(&details)
    .request_async(&oauth_http_client, tokio::time::sleep, None)
    .await?;
println!("microsoft token: {:?}", token);

let mc_flow = MinecraftAuthorizationFlow::new(Client::new());
let mc_token = mc_flow.exchange_microsoft_token(token.access_token()).await?;
println!("minecraft token: {:?}", mc_token);
```

See full examples in the [examples](examples) folder.

# HTTP clients

By default the crate is asynchronous and uses [reqwest](https://crates.io/crates/reqwest) to perform the authentication requests. Two cargo features change that:

- `ureq` provides `UreqClient`, a synchronous client backed by [ureq](https://crates.io/crates/ureq).
- `is_sync` turns the whole API synchronous via [maybe-async](https://crates.io/crates/maybe-async): the flow methods lose their `async` and the reqwest implementation switches to `reqwest::blocking::Client`.

For a small launcher that does not want an async runtime:

```toml
[dependencies]
minecraft-msa-auth = { version = "0.5", default-features = false, features = ["ureq", "is_sync"] }
```

```rust
let mc_flow = MinecraftAuthorizationFlow::new(UreqClient::default());
let mc_token = mc_flow.exchange_microsoft_token(msa_token)?;
```

To use any other HTTP client, disable the default `reqwest` feature and implement the `HttpClient` trait for your client of choice:

```toml
[dependencies]
minecraft-msa-auth = { version = "0.5", default-features = false }
```

# What's new in 0.5

Version 0.5 removes the hard dependency on reqwest. `MinecraftAuthorizationFlow` is generic over an `HttpClient` trait, with implementations included for reqwest (the default), `reqwest::blocking` and ureq, and a new `is_sync` feature makes the whole API synchronous for launchers without an async runtime. Two changes break existing code: `MinecraftAuthorizationError` is now generic over the client's error type, and its `Reqwest` variant was replaced by `Http`, `HttpStatus` and `Json`. Code using the default reqwest client only needs to update its error handling. See the [changelog](CHANGELOG.md) for the full list.

# License

Except where noted (below and/or in individual files), all code in this repository is dual-licensed under either:

* MIT License ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))