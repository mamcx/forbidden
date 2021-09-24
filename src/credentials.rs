//! A common set of Credentials used to associate a [crate::users] with an authentication provider.
//!
//! As explained in [13 best practices for user account, authentication, and password management, 2021 edition](https://cloud.google.com/blog/products/identity-security/account-authentication-and-password-management-best-practices),
//! an user identity & user account are not always the same thing, and because is now common for give several auth mechanism to the users,
//! is desirable to account for this.
//!
//! NOTE: The [Identity] trait is implemented for this credentials because identity, user account, credentials
//! are not necessarily the same, but *sometimes ARE* in simpler system, so is convenient to use this structs as
//! "User"

use crate::identity::Identity;
use crate::password::Password;

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
        vec![Credential::Anon(self.clone())]
    }
}

/// Represent an credential/user using common username/password.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct UserPass {
    username: String,
    pwd: Password,
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
        vec![Credential::User(self.clone())]
    }
}

/// Represent an credential/user using common email/password.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct EmailPass {
    email: String,
    pwd: Password,
}

impl Identity for EmailPass {
    fn identity_id(&self) -> &str {
        &self.email
    }

    fn credentials(&self) -> Vec<Credential> {
        vec![Credential::UserEmail(self.clone())]
    }
}

/// Represent an opaque Token given, probably, by a external auth system.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Token {
    data: String,
}

impl Identity for Token {
    fn identity_id(&self) -> &str {
        &self.data
    }

    fn credentials(&self) -> Vec<Credential> {
        vec![Credential::Token(self.clone())]
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Credential {
    Anon(UserAnonymous),
    User(UserPass),
    UserEmail(EmailPass),
    Token(Token),
}

impl Credential {
    fn password(&self) -> Option<&Password> {
        match self {
            Credential::Anon(_) | Credential::Token(_) => None,
            Credential::User(x) => Some(&x.pwd),
            Credential::UserEmail(x) => Some(&x.pwd),
        }
    }
}

impl From<UserPass> for Credential {
    fn from(x: UserPass) -> Self {
        Credential::User(x)
    }
}
