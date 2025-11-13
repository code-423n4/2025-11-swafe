use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{SwafeError, Tagged};

/// Offchain Node ID
/// e.g. node:example-node-id
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct NodeId(String);

impl AsRef<str> for NodeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<String> for NodeId {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for NodeId {
    type Err = SwafeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');

        let typ = parts
            .next()
            .ok_or(SwafeError::InvalidInput("missing node type".to_string()))?;

        let id = parts
            .next()
            .ok_or(SwafeError::InvalidInput("missing node id".to_string()))?;

        if parts.next().is_some() {
            return Err(SwafeError::InvalidInput(
                "unexpected extra part".to_string(),
            ));
        }

        if typ != "node" {
            return Err(SwafeError::InvalidInput("invalid node type".to_string()));
        }

        // check on the id part
        if !id
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c.is_ascii_digit() || c == '-')
        {
            return Err(SwafeError::InvalidInput(
                "node id must contain only letters, digits and hyphens".to_string(),
            ));
        }

        Ok(NodeId(s.to_owned()))
    }
}

impl Tagged for NodeId {
    const SEPARATOR: &'static str = "v0:node-id";
}
