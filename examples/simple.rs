/// A simple in-memory IDP
use forbidden::forms::UserPassForm;
use forbidden::prelude::*;
use forbidden::users::UserPass;

const TEST_PWD: &str = "1";
const USER_1: &str = "user1";
const USER_2: &str = "user2";

// Assert the password is safe, I promise!
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

/// Log in with credential [UserPassForm] and return token as [String]
impl IdentityProvider<UserPassForm> for TestProvider {
    type Identity = UserPass;

    fn find(&self, id: &str) -> ResultAuth<Option<Self::Identity>> {
        Ok(self.users.iter().find(|x| x.identity_id() == id).cloned())
    }

    fn find_by_token(&self, _token: &Token) -> ResultAuth<Option<Self::Identity>> {
        todo!()
    }

    fn logout(&self, _token: &Token) -> ResultAuth<bool> {
        Ok(true)
    }
}

impl IdentityProviderUserPwd for TestProvider {}

fn main() -> ResultAuth<()> {
    let idp = TestProvider::new();

    assert!(idp.find(USER_1)?.is_some());

    let mut form = UserPassForm::new(USER_1, "wrong");
    assert!(idp.login(&form).is_err());
    form.pwd = TEST_PWD.into();
    assert!(idp.login(&form).is_ok());

    Ok(())
}
