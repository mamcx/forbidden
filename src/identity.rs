//! The [Identity] trait represent the "who" of a software that needs authentication.
use std::collections::HashMap;

use crate::credentials::Credential;
use crate::errors::{ResultAuth, ResultPwd};
use crate::forms::{EmailPassForm, UserPassForm};
use crate::prelude::AuthError;
use crate::properties::Properties;
use crate::token::Token;

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
    /// Verify the security challenge (like a password) is valid for this identity
    fn verify_challenge(&self, against: &str) -> ResultPwd<()>;
}

/// An identity provider (IDP) is a service that can authenticate a user with a [crate::credentials] and return an Token.
pub trait IdentityProvider<Credential> {
    type Identity: Identity;

    fn find(&self, id: &str) -> ResultAuth<Option<Self::Identity>>;
    fn find_by_token(&self, token: &Token) -> ResultAuth<Option<Self::Identity>>;

    fn logout(&self, token: &Token) -> ResultAuth<bool>;
}

/// An identity provider (IDP) that can authenticate a user with [UserPassForm] credential.
pub trait IdentityProviderUserPwd: IdentityProvider<UserPassForm> {
    fn login(&self, identity: &UserPassForm) -> ResultAuth<Token> {
        self.verify_password(identity)
    }

    fn verify_password(&self, credentials: &UserPassForm) -> ResultAuth<Token> {
        if let Some(user) = self.find(&credentials.username)? {
            user.verify_challenge(&credentials.pwd)?;
            Ok(credentials.into())
        } else {
            Err(AuthError::UserNotFound {
                named: credentials.username.clone(),
            })
        }
    }
}

/// An identity provider (IDP) that can authenticate a user with [EmailPassForm] credential.
pub trait IdentityProviderEmailPwd: IdentityProvider<EmailPassForm> {
    fn login(&self, identity: &EmailPassForm) -> ResultAuth<Token> {
        self.verify_password(identity)
    }

    fn verify_password(&self, credentials: &EmailPassForm) -> ResultAuth<Token> {
        if let Some(user) = self.find(&credentials.email)? {
            user.verify_challenge(&credentials.pwd)?;
            Ok(credentials.into())
        } else {
            Err(AuthError::EmailNotFound {
                email: credentials.email.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ResultPwd;
    use crate::password::{Password, PasswordIsSafe};
    use crate::prelude::AuthError;
    use crate::users::UserPass;

    const TEST_PWD: &str = "1";
    const USER_1: &str = "user1";
    const USER_2: &str = "user2";

    struct ByPass {}

    impl PasswordIsSafe for ByPass {
        fn is_safe(&self, _raw: &str) -> ResultPwd<()> {
            Ok(())
        }
    }

    struct TestProvider {
        users: [UserPass; 2],
    }

    impl TestProvider {
        pub fn new() -> Self {
            let p = Password::hash(TEST_PWD, ByPass {}).unwrap();
            let u1 = UserPass::new(USER_1, p.clone());
            let u2 = UserPass::new(USER_2, p);

            TestProvider { users: [u1, u2] }
        }
    }

    impl IdentityProvider<UserPassForm, String> for TestProvider {
        type Identity = UserPass;

        fn find(&self, id: &str) -> ResultAuth<Option<Self::Identity>> {
            Ok(self.users.iter().find(|x| x.identity_id() == id).cloned())
        }

        fn find_by_token(&self, _token: &String) -> ResultAuth<Option<Self::Identity>> {
            todo!()
        }

        fn logout(&self, _token: &String) -> ResultAuth<bool> {
            Ok(true)
        }
    }

    impl IdentityProviderUserPwd<String> for TestProvider {
        fn verify_password(&self, credentials: &UserPassForm) -> ResultAuth<String> {
            if let Some(user) = self.find(&credentials.username)? {
                user.pwd.validate_password(&credentials.pwd)?;
                Ok(credentials.username.clone())
            } else {
                Err(AuthError::UserNotFound {
                    named: credentials.username.clone(),
                })
            }
        }
    }

    #[test]
    fn user_provider() {
        let idp = TestProvider::new();

        assert!(idp.find(USER_1).map(|x| x.is_some()).unwrap_or(false));

        let mut form = UserPassForm::new(USER_1, "wrong");
        assert!(idp.login(&form).is_err());
        form.pwd = TEST_PWD.into();
        assert!(idp.login(&form).is_ok());
    }
}
