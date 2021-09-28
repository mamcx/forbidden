use forbidden::forms::UserPassForm;
use forbidden::prelude::*;
use forbidden::users::UserPass;

use sqlite3;

const TEST_PWD: &str = "1";
const USER_1: &str = "user1";
const USER_2: &str = "user2";

const TABLES: &str = "
CREATE TABLE users (name TEXT, role TEXT, pwd TEXT);
";

// Assert the password is safe, I promise!
struct ByPass {}

impl PasswordIsSafe for ByPass {
    fn is_safe(&self, _raw: &str) -> ResultPwd<()> {
        Ok(())
    }
}

fn to_err(err: sqlite3::Error) -> AuthError {
    AuthError::Other(Box::new(err))
}

struct SqliteProvider {
    db: sqlite3::Connection,
}

impl SqliteProvider {
    pub fn new() -> Result<Self, sqlite3::Error> {
        let p = Password::hash(TEST_PWD, ByPass {}).unwrap();

        let db = sqlite3::open(":memory:")?;

        db.execute(TABLES)?;

        for x in [USER_1, USER_2] {
            db.execute(format!(
                "INSERT INTO users(name, role , pwd) VALUES ('{}', '{}', '{}')",
                x, "admin", &p.phc
            ))?;
        }

        Ok(SqliteProvider { db })
    }
}

impl IdentityProvider<UserPassForm, String> for SqliteProvider {
    type Identity = UserPass;

    fn find(&self, id: &str) -> ResultAuth<Option<Self::Identity>> {
        let mut cursor = self
            .db
            .prepare("SELECT name, pwd FROM users WHERE name = ?")
            .map_err(to_err)?
            .cursor();

        cursor
            .bind(&[sqlite3::Value::String(id.into())])
            .map_err(to_err)?;

        while let Some(row) = cursor.next().unwrap() {
            let pwd = Password::new(&row[1].as_string().unwrap_or_default())?;

            return Ok(Some(UserPass::new(&row[0].as_string().unwrap(), pwd)));
        }

        Ok(None)
    }

    fn find_by_token(&self, _token: &String) -> ResultAuth<Option<Self::Identity>> {
        todo!()
    }

    fn logout(&self, _token: &String) -> ResultAuth<bool> {
        Ok(true)
    }
}

impl IdentityProviderUserPwd<String> for SqliteProvider {
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

fn main() -> ResultAuth<()> {
    let idp = SqliteProvider::new().unwrap();

    assert!(idp.find(USER_1)?.is_some());

    let mut form = UserPassForm::new(USER_1, "wrong");
    assert!(idp.login(&form).is_err());
    form.pwd = TEST_PWD.into();
    assert!(idp.login(&form).is_ok());

    Ok(())
}
