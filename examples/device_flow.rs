use minecraft_microsoft_auth::microsoft::device_flow::MicrosoftDeviceAuthorizationFlow;
use minecraft_microsoft_auth::microsoft::MicrosoftClientId;
use minecraft_microsoft_auth::minecraft::MinecraftAuthorizationFlow;
use reqwest::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_id = std::env::args().nth(1).expect("client_id as first argument");
    let client_id = MicrosoftClientId::new(client_id)?;

    let msa_flow = MicrosoftDeviceAuthorizationFlow::new(client_id, Client::new());
    let device_auth = msa_flow.start().await?;
    println!("{}", device_auth.message());

    let token = msa_flow.wait_for_login(&device_auth).await?;
    println!("microsoft token: {:?}", token);

    let mc_flow = MinecraftAuthorizationFlow::new(Client::new());
    let mc_token = mc_flow.exchange_microsoft_token(&token).await?;
    println!("minecraft token: {:?}", mc_token);
    Ok(())
}
