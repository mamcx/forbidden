//! A common set of user structs that implement [Identity].
//!
//! A User can be authenticated with many [crate::credentials] that link to it.

use std::collections::HashMap;

use crate::credentials::{CredentialEmail, CredentialUser};
use crate::prelude::*;

/// The default username for an admin user
pub const USERNAME_ADMIN: &str = "admin";

/// Represent a full user with the most common set of fields.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct User {
    /// A global, unique-id.
    user_id: String,
    user_name: String,
    email: String,
    password: Password,
    realm: Option<String>,
    properties: Option<HashMap<String, Properties>>,
}

impl User {
    pub fn new(
        user_id: &str,
        user_name: &str,
        email: &str,
        password: Password,
        realm: Option<&str>,
        properties: Option<HashMap<String, Properties>>,
    ) -> Self {
        User {
            user_id: user_id.into(),
            user_name: user_name.into(),
            email: email.into(),
            password,
            realm: realm.map(String::from),
            properties,
        }
    }

    pub fn new_admin(
        user_id: &str,
        email: &str,
        password: Password,
        realm: Option<&str>,
        properties: Option<HashMap<String, Properties>>,
    ) -> Self {
        Self::new(user_id, USERNAME_ADMIN, email, password, realm, properties)
    }
}

impl Identity for User {
    fn identity_id(&self) -> &str {
        &self.user_id
    }

    fn realm(&self) -> &str {
        self.realm.as_deref().unwrap_or(REALM_DEFAULT)
    }

    fn credentials(&self) -> Vec<Credential> {
        vec![CredentialUser::new(&self.user_name).into()]
    }
}

/// Represent an anonymous user.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct UserAnonymous {
    /// A global, unique-id that permit to "upgrade" later this user to a permanent one.
    anon_id: String,
}

impl Identity for UserAnonymous {
    fn identity_id(&self) -> &str {
        &self.anon_id
    }

    fn credentials(&self) -> Vec<Credential> {
        vec![Credential::Anon(self.anon_id.clone())]
    }
}

/// Represent a user using a username/password.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct UserPass {
    pub username: String,
    pub pwd: Password,
}

impl UserPass {
    pub fn new(username: &str, pwd: Password) -> Self {
        UserPass {
            username: username.into(),
            pwd,
        }
    }
}

impl Identity for UserPass {
    fn identity_id(&self) -> &str {
        &self.username
    }

    fn credentials(&self) -> Vec<Credential> {
        vec![Credential::User(CredentialUser {
            username: self.username.clone(),
        })]
    }
}

/// Represent a user using an email/password.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct EmailPass {
    pub email: String,
    pub pwd: Password,
}

impl Identity for EmailPass {
    fn identity_id(&self) -> &str {
        &self.email
    }

    fn credentials(&self) -> Vec<Credential> {
        vec![Credential::UserEmail(CredentialEmail {
            email: self.email.clone(),
        })]
    }
}
