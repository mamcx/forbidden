pub mod credentials;
mod errors;
pub mod identity;
pub mod password;
mod properties;
mod users;

pub mod prelude {
    pub use crate::credentials::Credential;
    pub use crate::errors::{AuthError, PasswordError, ResultAuth, ResultPwd};
    pub use crate::password;
    pub use crate::password::{Password, PasswordIsSafe};
    pub use crate::properties::Properties;
}
