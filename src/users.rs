use crate::identity::Identity;
use crate::password::Password;

pub struct UserAnonymous {
    username: String,
    realm: Option<String>,
}

impl Identity for UserAnonymous {
    fn identity_id(&self) -> &str {
        &self.username
    }
}

pub struct UserPass {
    username: String,
    pwd: Password,
    realm: Option<String>,
}

pub struct EmailPass {
    username: String,
    email: String,
    pwd: Password,
    realm: Option<String>,
}

impl Identity for UserPass {
    fn identity_id(&self) -> &str {
        &self.username
    }
}
