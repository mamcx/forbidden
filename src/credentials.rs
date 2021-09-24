//! A common set of Credentials used to associate a [User] with an authentication provider.
//!
//! As explained in [13 best practices for user account, authentication, and password management, 2021 edition](https://cloud.google.com/blog/products/identity-security/account-authentication-and-password-management-best-practices),
//! an user identity and and user account are not always the same thing, and because is now common for give several auth mechanism to the users,
//! is desirable to account for this.

use crate::password::Password;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct UserAnonymous {
    anon_id: String,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct UserPass {
    username: String,
    pwd: Password,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct EmailPass {
    email: String,
    pwd: Password,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Credential {
    Anon(UserAnonymous),
    User(UserPass),
    UserEmail(EmailPass),
}

impl Credential {
    fn password(&self) -> Option<&Password> {
        match self {
            Credential::Anon(_) => None,
            Credential::User(x) => Some(&x.pwd),
            Credential::UserEmail(x) => Some(&x.pwd),
        }
    }
}

impl From<&UserPass> for Credential {
    fn from(x: &UserPass) -> Self {
        Credential::User(x.clone())
    }
}
