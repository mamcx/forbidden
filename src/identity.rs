//! The [Identity] trait represent the "who" of a software that needs authentication.
use std::collections::HashMap;

use crate::credentials::Credential;
use crate::errors::ResultAuth;
use crate::properties::Properties;

/// A default realm name
pub const REALM_DEFAULT: &str = "GLOBAL";

/// The [Identity] trait define the "who" of a software.
/// It can be a customer, employee, user, company, or others constructs such as an IoT device, application, etc.
pub trait Identity {
    /// A global, unique ID
    fn identity_id(&self) -> &str;
    /// To show in the user interface
    fn display_name(&self) -> Option<String> {
        None
    }
    /// To which realm this belong (A realm manages a set of users, credentials, roles, and groups, like a company or web domain)
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

/// An identity provider (IDP) is a service that can authenticate a user.
pub trait IdentityProvider {
    type Identity: Identity;
    type Credential;
    type Token;

    fn find(&self, id: &str) -> ResultAuth<Option<Self::Identity>>;
    fn find_by_token(&self, token: &Self::Token) -> ResultAuth<Option<Self::Identity>>;

    fn login(&self, identity: &Self::Credential) -> ResultAuth<Self::Token>;

    fn logout(&self, token: &Self::Token) -> ResultAuth<bool>;
}

pub trait IdentityProviderUserPwd: IdentityProvider {
    fn verify_password(
        &self,
        identity: &Self::Credential,
        password: &str,
    ) -> ResultAuth<Self::Token>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
