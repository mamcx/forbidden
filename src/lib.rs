mod errors;
mod identity;
pub mod password;
mod users;

pub mod prelude {
    pub use crate::errors::{AuthError, PasswordError, ResultAuth, ResultPwd};
    pub use crate::password;
    pub use crate::password::{Password, PasswordIsSafe};
}
