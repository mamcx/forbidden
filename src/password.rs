//! A safely constructed Password according to OWASP
//!
//! The password use a [PHC String format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification)
//! as the proper way to store and retrieve passwords.
//!
//! # Examples
//!
//! ```
//! use forbidden::prelude::*;
//! use std::str::FromStr;
//!
//! let p = Password::hash("hi").unwrap();
//! dbg!(p);
//! ```

use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::errors::AuthError;
use password_hash::{PasswordHash, SaltString};
use rand_core::OsRng;

pub mod hash_argon2 {
    use crate::password::Password;
    use argon2::Argon2;
    use password_hash::{Ident, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

    //List of the internal algos define for `argon2`
    pub(crate) const ARGON_IDENT: &[Ident<'_>] = &[
        argon2::ARGON2D_IDENT,
        argon2::ARGON2I_IDENT,
        argon2::ARGON2ID_IDENT,
    ];

    pub(crate) fn hash_password<'a>(
        raw: &'a str,
        salt: &'a SaltString,
    ) -> password_hash::Result<PasswordHash<'a>> {
        Argon2::default().hash_password(raw.as_ref(), salt.as_ref())
    }

    pub(crate) fn validate_password(of: &Password, against: &str) -> password_hash::Result<()> {
        let p = of.get_hash();
        Argon2::default().verify_password(against.as_bytes(), &p)
    }
}

pub mod hash_scrypt {
    use crate::password::Password;
    use password_hash::{Ident, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
    use scrypt;
    use scrypt::Scrypt;

    //List of the internal algos define for `scrypt`
    pub(crate) const SCRYPT_IDENT: &[Ident<'_>] = &[scrypt::ALG_ID];

    pub(crate) fn hash_password<'a>(
        raw: &'a str,
        salt: &'a SaltString,
    ) -> password_hash::Result<PasswordHash<'a>> {
        Scrypt.hash_password(raw.as_ref(), salt.as_ref())
    }

    pub(crate) fn validate_password(of: &Password, against: &str) -> password_hash::Result<()> {
        let p = of.get_hash();
        Scrypt.verify_password(against.as_bytes(), &p)
    }
}

/// A list of the recommended algorithms for password hashing,
/// according to [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum PasswordAlgo {
    Argon2,
    Scrypt,
}

impl TryFrom<&PasswordHash<'_>> for PasswordAlgo {
    type Error = AuthError;

    fn try_from(value: &PasswordHash<'_>) -> Result<Self, Self::Error> {
        if hash_argon2::ARGON_IDENT.contains(&value.algorithm) {
            return Ok(PasswordAlgo::Argon2);
        }

        if hash_scrypt::SCRYPT_IDENT.contains(&value.algorithm) {
            return Ok(PasswordAlgo::Scrypt);
        }

        Err(AuthError::InvalidPasswordAlgo(
            value.algorithm.as_str().to_string(),
        ))
    }
}

impl PasswordAlgo {
    //https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#bcrypt
    fn max_length(&self) -> Option<usize> {
        match self {
            PasswordAlgo::Argon2 => Some(argon2::MAX_PWD_LEN),
            PasswordAlgo::Scrypt => Some(72),
        }
    }
}

/// A safely constructed Password
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Password {
    phc: String,
    algo: PasswordAlgo,
}

impl Password {
    //Internal constructor, not mean to be used directly
    fn _new(hash: PasswordHash, algo: PasswordAlgo) -> Self {
        Password {
            phc: hash.to_string(),
            algo,
        }
    }

    /// Load a password from a PCH formatted string, use this for load from a Storage
    pub fn new(phc: &str) -> Result<Self, AuthError> {
        let hash = PasswordHash::new(phc)?;
        let algo: PasswordAlgo = (&hash).try_into()?;
        Ok(Self::_new(hash, algo))
    }

    /// Hash a raw string into a PCH salted string using recommended algorithm (`Argon2` as 2021)
    pub fn hash(raw: &str) -> Result<Self, AuthError> {
        Self::hash_argon(raw)
    }

    /// Hash a raw string into a PCH salted string using `Argon2`
    pub fn hash_argon(raw: &str) -> Result<Self, AuthError> {
        let salt = Password::salt();
        let hash = hash_argon2::hash_password(raw.as_ref(), &salt)?;
        Ok(Self::_new(hash, PasswordAlgo::Argon2))
    }

    /// Return the constructed hash from the internal `String`
    ///
    /// # Safety
    ///
    /// At this point the internal string is always a correct PHC in the defined `PasswordAlgo`
    pub fn get_hash(&self) -> PasswordHash {
        PasswordHash::new(&self.phc).unwrap()
    }

    /// Check if this password match a raw `&str`
    ///
    /// # Examples
    ///
    /// ```
    /// use forbidden::prelude::*;
    /// use std::str::FromStr;
    ///
    /// let p = Password::hash("hi").unwrap();
    /// assert!(p.validate_password("hi").is_ok());
    ///
    /// //Also can be used with equality in case you don't care for the error causes of not matching:
    /// assert_eq!(p, "hi");
    /// ```
    pub fn validate_password(&self, against: &str) -> Result<(), AuthError> {
        hash_argon2::validate_password(&self, against)?;
        Ok(())
    }

    /// A salted string that can be used for hashing passwords
    pub fn salt() -> SaltString {
        SaltString::generate(&mut OsRng)
    }
}

impl FromStr for Password {
    type Err = AuthError;

    fn from_str(phc: &str) -> Result<Self, Self::Err> {
        Self::new(phc)
    }
}

impl PartialEq<&str> for Password {
    fn eq(&self, other: &&str) -> bool {
        self.validate_password(other).is_ok()
    }
}

/// When using `Display` trait, not allow to leak the details of the `Password`
impl Display for Password {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "****")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_passwords() {
        assert!(Password::new("hi").is_err());

        let p = Password::new("$argon2id$v=19$m=4096,t=3,p=1$B+wShXe3YjVd5C8oh4x3pw$XxZJ3BnZMGnBNwPnXrvVM4MMAeFzxf9yxkbXAPcvBzQ").unwrap();
        p.validate_password("hi").unwrap();

        assert_eq!(p, "hi")
    }
}
