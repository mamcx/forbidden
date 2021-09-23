//! A safely constructed Password according to [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
//!
//! The password use a [PHC String](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification)
//! as the proper way to store and retrieve passwords from a storage (like database or file).
//!
//! The default hashing algorithm is [PasswordAlgo::Argon2].
//!
//! Use the field `password.phc` as the value to store.
//!
//! # Examples
//!
//! ```
//! use forbidden::prelude::*;
//! use forbidden::password::CHECKER_MIN_SIZE;
//!
//! // Sorry, you can't cheat and pass a unsafe password without use `unsafe`, ugh!
//! assert!(unsafe{Password::hash_unsafe("").is_ok()});
//! assert!(unsafe{Password::hash_unsafe("hi").is_ok()});
//!
//! // To avoid `unsafe`, pass a checker that implement the trait [PasswordIsSafe]
//! assert!(Password::hash_check("short", CHECKER_MIN_SIZE).is_err());
//! // This checker verify is at least 8 chars long.
//! assert!(Password::hash_check("12345678", CHECKER_MIN_SIZE).is_ok());
//! ```

use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::errors::{PasswordError, ResultPwd};
use password_hash::{PasswordHash, SaltString};
use rand_core::OsRng;

// To make it easy to disable, put these on separate modules...

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

pub trait PasswordIsSafe {
    fn is_safe(&self, raw: &str) -> ResultPwd<()>;
}

/// The minimum size in chars for a password to be safe.
pub const MINIMUM_PASSWORD_LENGTH: usize = 8;

/// A convenient constant for get a constructed [CheckPasswordMinSize].
pub const CHECKER_MIN_SIZE: CheckPasswordMinSize = CheckPasswordMinSize {};

/// A password checker that verify is at least [MINIMUM_PASSWORD_LENGTH] chars long.
pub struct CheckPasswordMinSize {}

impl PasswordIsSafe for CheckPasswordMinSize {
    fn is_safe(&self, raw: &str) -> ResultPwd<()> {
        let provided = raw.trim().chars().count();
        if provided < MINIMUM_PASSWORD_LENGTH {
            return Err(PasswordError::MinimumPasswordLength { provided });
        }

        Ok(())
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
    type Error = PasswordError;

    fn try_from(value: &PasswordHash<'_>) -> Result<Self, Self::Error> {
        if hash_argon2::ARGON_IDENT.contains(&value.algorithm) {
            return Ok(PasswordAlgo::Argon2);
        }

        if hash_scrypt::SCRYPT_IDENT.contains(&value.algorithm) {
            return Ok(PasswordAlgo::Scrypt);
        }

        Err(PasswordError::InvalidPasswordAlgo {
            provided: value.algorithm.as_str().to_string(),
        })
    }
}

impl PasswordAlgo {
    //https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#bcrypt
    fn max_length(&self) -> usize {
        match self {
            PasswordAlgo::Argon2 => argon2::MAX_PWD_LEN,
            PasswordAlgo::Scrypt => 72,
        }
    }
}

impl PasswordIsSafe for PasswordAlgo {
    fn is_safe(&self, raw: &str) -> ResultPwd<()> {
        let provided = raw.trim().chars().count();
        if provided > self.max_length() {
            Err(PasswordError::MaximumPasswordLength { provided })
        } else {
            Ok(())
        }
    }
}

/// A safely constructed [Password]
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Password {
    pub phc: String,
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

    /// Load a password from a PCH formatted string. (Use this for load from a Storage)
    pub fn new(phc: &str) -> ResultPwd<Self> {
        let hash = PasswordHash::new(phc)?;
        let algo: PasswordAlgo = (&hash).try_into()?;
        //Check the max size
        algo.is_safe(phc)?;
        Ok(Self::_new(hash, algo))
    }

    /// Hash a raw string into a PCH salted string using recommended algorithm ([argon2::Argon2] as 2021)
    /// and verify is safe using a checker
    pub fn hash_check(raw: &str, check: impl PasswordIsSafe) -> ResultPwd<Self> {
        Self::hash_argon(raw, check)
    }

    /// Hash a raw string into a PCH salted string using recommended algorithm ([argon2::Argon2] as 2021)
    ///
    /// # Safety
    ///
    /// This is marked unsafe because allow to use empty string, short password, leaked passwords, etc
    /// use [Self::hash_check] and prove the password is safe instead
    ///
    /// Available because is useful for testing or for provide a way to upgrade later to a strong password.
    pub unsafe fn hash_unsafe(raw: &str) -> ResultPwd<Self> {
        Self::hash_argon_unsafe(raw)
    }

    /// Hash a raw string into a PCH salted string using [argon2::Argon2]
    /// and verify is safe using a checker
    pub fn hash_argon(raw: &str, check: impl PasswordIsSafe) -> ResultPwd<Self> {
        check.is_safe(raw)?;
        unsafe { Self::hash_argon_unsafe(raw) }
    }

    /// Hash a raw string into a PCH salted string using [argon2::Argon2]
    ///
    /// # Safety
    ///
    /// Check comment on [Self::hash_unsafe]
    pub unsafe fn hash_argon_unsafe(raw: &str) -> ResultPwd<Self> {
        let salt = Password::salt();
        let hash = hash_argon2::hash_password(raw, &salt)?;
        Ok(Self::_new(hash, PasswordAlgo::Argon2))
    }

    /// Hash a raw string into a PCH salted string using [scrypt::Scrypt]
    /// and verify is safe using a checker
    pub fn hash_scrypt(raw: &str, check: impl PasswordIsSafe) -> ResultPwd<Self> {
        check.is_safe(raw)?;
        unsafe { Self::hash_scrypt_unsafe(raw) }
    }

    /// Hash a raw string into a PCH salted string using [scrypt::Scrypt]
    ///
    /// # Safety
    ///
    /// Check comment on [Self::hash_unsafe]
    pub unsafe fn hash_scrypt_unsafe(raw: &str) -> ResultPwd<Self> {
        let salt = Password::salt();
        let hash = hash_scrypt::hash_password(raw, &salt)?;
        Ok(Self::_new(hash, PasswordAlgo::Scrypt))
    }

    /// Return the constructed hash_unsafe from the internal [String]
    ///
    /// # Safety
    ///
    /// At this point the internal string is always a correct PHC in the defined [PasswordAlgo]
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
    /// let p = unsafe{ Password::hash_unsafe("hi").unwrap() };
    /// // Verify if the password match...
    /// assert!(p.validate_password("hi").is_ok());
    ///
    /// //Also can be used with equality in case you don't care for the error causes of not matching:
    /// assert_eq!(p, "hi");
    /// ```
    pub fn validate_password(&self, against: &str) -> Result<(), PasswordError> {
        match self.algo {
            PasswordAlgo::Argon2 => {
                hash_argon2::validate_password(self, against)?;
            }
            PasswordAlgo::Scrypt => {
                hash_scrypt::validate_password(self, against)?;
            }
        }

        Ok(())
    }

    /// A salted string that can be used for hashing passwords
    pub fn salt() -> SaltString {
        SaltString::generate(&mut OsRng)
    }
}

impl FromStr for Password {
    type Err = PasswordError;

    fn from_str(phc: &str) -> Result<Self, Self::Err> {
        Self::new(phc)
    }
}

impl PartialEq<&str> for Password {
    fn eq(&self, other: &&str) -> bool {
        self.validate_password(other).is_ok()
    }
}

/// When using [Display] trait, not allow to leak the details of the [Password]
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
