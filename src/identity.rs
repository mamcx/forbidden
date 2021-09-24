use crate::credentials::Credential;
use crate::errors::ResultAuth;
use crate::properties::Properties;
use std::collections::HashMap;

/// A default realm name
pub const REALM_DEFAULT: &str = "GLOBAL";

/// The [Identity] trait define the "who" of a software.
/// It can be a customer, employee, user, company, or others constructs such as an IoT device, application, etc.
pub trait Identity {
    /// A global, unique ID
    fn identity_id(&self) -> &str;
    /// To which realm this belong
    fn realm(&self) -> &str {
        REALM_DEFAULT
    }
    /// A unique list of permissions
    fn permissions(&self) -> &[String] {
        &[]
    }
    /// A unique list of roles
    fn roles(&self) -> &[String] {
        &[]
    }
    /// A unique list of [Credential]
    fn credentials(&self) -> Vec<Credential> {
        vec![]
    }
    /// An arbitrary [HashMap] of values with extra information
    fn properties(&self) -> Option<HashMap<String, Properties>> {
        None
    }
}

pub trait IdentityStore {
    type Identity: Identity;
    type Token;

    fn find(&self, id: &str) -> ResultAuth<Option<Self::Identity>>;

    fn login(&self, identity: &Self::Identity) -> ResultAuth<Self::Token>;

    fn logout(&self, token: &Self::Token) -> ResultAuth<bool>;
}

pub trait IdentityStoreUserPwd: IdentityStore {
    fn verify_password(&self, identity: &Self::Identity, password: &str)
        -> ResultAuth<Self::Token>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
