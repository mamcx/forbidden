use crate::errors::ResultAuth;

pub trait Identity {
    fn identity_id(&self) -> &str;
    fn realm(&self) -> &str {
        "global"
    }
    fn permissions(&self) -> &[String] {
        &[]
    }
    fn roles(&self) -> &[String] {
        &[]
    }
}

pub trait IdentityStore {
    type Identity: Identity;
    type Token;

    fn find(&self, id: &str) -> ResultAuth<Option<Self::Identity>>;

    fn login(&self, identity: &Self::Identity) -> ResultAuth<Self::Token>;

    fn logout(&self, token: &Self::Token) -> ResultAuth<bool>;
}

pub trait IdentityStoreUserPwd: IdentityStore {
    fn verify_password(&self, identity: &Self::Identity, password: &str)
        -> ResultAuth<Self::Token>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
