pub mod credentials;
mod errors;
pub mod forms;
pub mod identity;
pub mod password;
mod properties;
pub mod token;
pub mod users;

pub mod prelude {
    pub use crate::credentials::Credential;
    pub use crate::errors::{AuthError, PasswordError, ResultAuth, ResultPwd};
    pub use crate::identity::{Identity, IdentityProvider, IdentityProviderUserPwd, REALM_DEFAULT};
    pub use crate::password;
    pub use crate::password::{Password, PasswordIsSafe};
    pub use crate::properties::Properties;
    pub use crate::token::Token;
}
