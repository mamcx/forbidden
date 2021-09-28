use std::error::Error;

pub type ResultAuth<T> = Result<T, AuthError>;
pub type ResultPwd<T> = Result<T, PasswordError>;

#[derive(Debug)]
pub enum PasswordError {
    InvalidPassword,
    MinimumPasswordLength { provided: usize },
    MaximumPasswordLength { provided: usize },
    InvalidPasswordAlgo { provided: String },
    HashError(password_hash::Error),
}

impl From<password_hash::Error> for PasswordError {
    fn from(err: password_hash::Error) -> Self {
        PasswordError::HashError(err)
    }
}

#[derive(Debug)]
pub enum AuthError {
    Other(Box<dyn Error>),
    Password(PasswordError),
    IdentityNotFound { named: String },
    EmailNotFound { email: String },
    UserNotFound { named: String },
    TokenNotFound { token: String },
}

impl From<PasswordError> for AuthError {
    fn from(err: PasswordError) -> Self {
        AuthError::Password(err)
    }
}
