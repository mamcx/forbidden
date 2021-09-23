use argon2::password_hash;

pub type ResultAuth<T> = Result<T, AuthError>;

#[derive(Debug)]
pub enum PasswordError {
    InvalidPassword,
    InvalidPasswordAlgo(String),
    HashError(password_hash::Error),
}

impl From<password_hash::Error> for PasswordError {
    fn from(err: password_hash::Error) -> Self {
        PasswordError::HashError(err)
    }
}

#[derive(Debug)]
pub enum AuthError {
    InvalidPassword,
    InvalidPasswordAlgo(String),
    HashError(password_hash::Error),
}

impl From<password_hash::Error> for AuthError {
    fn from(err: password_hash::Error) -> Self {
        AuthError::HashError(err)
    }
}
