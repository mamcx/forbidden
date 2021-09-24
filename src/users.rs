use std::collections::HashMap;

use crate::credentials::*;
use crate::identity::{Identity, REALM_DEFAULT};
use crate::properties::Properties;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct User {
    user_id: String,
    credential: UserPass,
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
        vec![(&self.credential).into()]
    }
}
