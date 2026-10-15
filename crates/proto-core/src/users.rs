use redb::Database;

pub struct UserDb {
    db: Database,
}

#[derive(Debug)]
pub enum UserDbError {
    Storage(redb::Error),
    Hash(String),
    InvalidName,
    EmptyPassword,
    UserExists,
    NoSuchUser,
}
