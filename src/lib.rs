use microsoft::device_flow::DeviceAuthorizationFlowError;
use minecraft::MinecraftAuthorizationError;
use thiserror::Error;

pub mod microsoft;
pub mod minecraft;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    DeviceAuthorization(#[from] DeviceAuthorizationFlowError),

    #[error(transparent)]
    MinecraftAuthorization(#[from] MinecraftAuthorizationError),
}
