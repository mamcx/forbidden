//! A common set of forms structs used to send authentication request  to an [crate::identity::IdentityProvider].

/// Represent a Form using username/password.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct UserPassForm {
    pub username: String,
    pub pwd: String,
}

impl UserPassForm {
    pub fn new(username: &str, pwd: &str) -> Self {
        Self {
            username: username.into(),
            pwd: pwd.into(),
        }
    }
}

/// Represent a Form using email/password.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct EmailPassForm {
    pub email: String,
    pub pwd: String,
}

impl EmailPassForm {
    pub fn new(email: &str, pwd: &str) -> Self {
        EmailPassForm {
            email: email.into(),
            pwd: pwd.into(),
        }
    }
}

/// Represent an opaque Form Token given, probably, by a external auth system.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct TokenForm {
    pub data: String,
}
