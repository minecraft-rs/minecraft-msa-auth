use std::fmt::{Display, Formatter};

use getset::Getters;
use nutype::nutype;
use serde::Deserialize;

pub mod device_flow;
pub mod auth_code_flow;

/// Represents a Microsoft identity platform client ID.
#[nutype(validate(present))]
#[derive(AsRef, Debug, Clone, PartialEq, Eq, Hash)]
pub struct MicrosoftClientId(String);

/// An error returned by the Microsoft identity platform.
#[derive(Default, Debug, Clone, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct MicrosoftError {
    error: String,
    error_description: String,
    error_codes: Vec<i64>,
    timestamp: String,
    trace_id: String,
    correlation_id: String,
    error_uri: String,
}

impl Display for MicrosoftError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.error_description)
    }
}