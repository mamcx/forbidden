//! A common set of user structs that implement [Identity].
//!
//! A User can be authenticated with an [crate::credentials] and could have many of them.

use std::collections::HashMap;

use crate::credentials::UserPass;
use crate::prelude::*;

/// Represent an full user with the most common of the fields.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct User {
    /// A global, unique-id.
    user_id: String,
    user_name: String,
    password: Password,
    realm: Option<String>,
    properties: Option<HashMap<String, Properties>>,
}

impl Identity for User {
    fn identity_id(&self) -> &str {
        &self.user_id
    }

    fn realm(&self) -> &str {
        self.realm.as_deref().unwrap_or(REALM_DEFAULT)
    }

    fn credentials(&self) -> Vec<Credential> {
        vec![UserPass::new(&self.user_name, self.password.clone()).into()]
    }
}
