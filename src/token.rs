//! A token that is issued after a successfully authentication.

use std::collections::BTreeMap;

use crate::credentials::{CredentialEmail, CredentialUser};
use crate::forms::{EmailPassForm, UserPassForm};
use crate::prelude::{Credential, Properties};
use crate::properties::TimeStamp;

/// The [Token] flexible container of data used for lookup the [crate::identity] and [Credential] generated
/// after the authentication
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Token {
    /// A global, unique ID that is used to lookup an [crate::identity]
    identity_id: String,
    /// The credential used to generate this
    credential: Credential,
    /// When the token must expire
    expire: Option<TimeStamp>,
    /// Arbitrary map of extra data
    properties: Option<BTreeMap<String, Properties>>,
}

impl Token {
    pub fn new(
        identity_id: &str,
        credential: Credential,
        expire: Option<TimeStamp>,
        properties: Option<BTreeMap<String, Properties>>,
    ) -> Self {
        Token {
            identity_id: identity_id.into(),
            credential,
            expire,
            properties,
        }
    }
}

impl From<&UserPassForm> for Token {
    fn from(x: &UserPassForm) -> Self {
        Token::new(
            &x.username,
            CredentialUser::new(&x.username).into(),
            None,
            None,
        )
    }
}

impl From<&EmailPassForm> for Token {
    fn from(x: &EmailPassForm) -> Self {
        Token::new(&x.email, CredentialEmail::new(&x.email).into(), None, None)
    }
}
