//! A common set of Credentials used to associate a [crate::users] with an authentication provider.
//!
//! As explained in [13 best practices for user account, authentication, and password management, 2021 edition](https://cloud.google.com/blog/products/identity-security/account-authentication-and-password-management-best-practices),
//! an user identity & user account are not always the same thing, and because is now common for give several auth mechanism to the users,
//! is desirable to account for this.

/// Represent an credential using username/password.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CredentialUser {
    pub username: String,
}

impl CredentialUser {
    pub fn new(username: &str) -> Self {
        Self {
            username: username.into(),
        }
    }
}

/// Represent an credential using email/password.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CredentialEmail {
    pub email: String,
}

/// Represent an opaque Token given, probably, by a external auth system.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CredentialToken {
    pub data: String,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Credential {
    Anon(String),
    User(CredentialUser),
    UserEmail(CredentialEmail),
    Token(CredentialToken),
}

impl From<CredentialUser> for Credential {
    fn from(x: CredentialUser) -> Self {
        Credential::User(x)
    }
}

impl From<CredentialEmail> for Credential {
    fn from(x: CredentialEmail) -> Self {
        Credential::UserEmail(x)
    }
}
