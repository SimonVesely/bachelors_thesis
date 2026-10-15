use std::fmt;
use std::path::Path;

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

const USERS: TableDefinition<&str, &str> = TableDefinition::new("users");

#[derive(Debug)]
pub enum UserDbError {
    Storage(redb::Error),
    Hash(String),
    InvalidName,
    EmptyPassword,
    UserExists,
    NoSuchUser,
}

impl fmt::Display for UserDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserDbError::Storage(e) => write!(f, "user database error: {e}"),
            UserDbError::Hash(e) => write!(f, "password hashing failed: {e}"),
            UserDbError::InvalidName => {
                f.write_str("user name must be 1-64 characters without spaces")
            }
            UserDbError::EmptyPassword => f.write_str("password must not be empty"),
            UserDbError::UserExists => f.write_str("user already exists"),
            UserDbError::NoSuchUser => f.write_str("no such user"),
        }
    }
}

impl std::error::Error for UserDbError {}

fn storage<E: Into<redb::Error>>(e: E) -> UserDbError {
    UserDbError::Storage(e.into())
}

pub struct UserDb {
    db: Database,
}

impl UserDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, UserDbError> {
        let db = Database::create(path).map_err(storage)?;
        let txn = db.begin_write().map_err(storage)?;
        txn.open_table(USERS).map_err(storage)?;
        txn.commit().map_err(storage)?;
        Ok(UserDb { db })
    }

    pub fn list_users(&self) -> Result<Vec<String>, UserDbError> {
        let txn = self.db.begin_read().map_err(storage)?;
        let table = txn.open_table(USERS).map_err(storage)?;
        let mut names = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (name, _) = row.map_err(storage)?;
            names.push(name.value().to_string());
        }
        Ok(names)
    }

    pub fn add_user(&self, name: &str, password: &str) -> Result<(), UserDbError> {
        validate_name(name)?;
        let hash = hash_password(password)?;
        let txn = self.db.begin_write().map_err(storage)?;
        {
            let mut table = txn.open_table(USERS).map_err(storage)?;
            if table.get(name).map_err(storage)?.is_some() {
                return Err(UserDbError::UserExists);
            }
            table.insert(name, hash.as_str()).map_err(storage)?;
        }
        txn.commit().map_err(storage)
    }

    pub fn set_password(&self, name: &str, password: &str) -> Result<(), UserDbError> {
        let hash = hash_password(password)?;
        let txn = self.db.begin_write().map_err(storage)?;
        {
            let mut table = txn.open_table(USERS).map_err(storage)?;
            if table.get(name).map_err(storage)?.is_none() {
                return Err(UserDbError::NoSuchUser);
            }
            table.insert(name, hash.as_str()).map_err(storage)?;
        }
        txn.commit().map_err(storage)
    }

    pub fn remove_user(&self, name: &str) -> Result<(), UserDbError> {
        let txn = self.db.begin_write().map_err(storage)?;
        let removed = {
            let mut table = txn.open_table(USERS).map_err(storage)?;
            table.remove(name).map_err(storage)?.is_some()
        };
        txn.commit().map_err(storage)?;
        if removed {
            Ok(())
        } else {
            Err(UserDbError::NoSuchUser)
        }
    }

    pub fn verify(&self, name: &str, password: &str) -> bool {
        let stored = self
            .db
            .begin_read()
            .ok()
            .and_then(|txn| txn.open_table(USERS).ok())
            .and_then(|table| {
                table
                    .get(name)
                    .ok()
                    .flatten()
                    .map(|v| v.value().to_string())
            });

        match stored {
            Some(hash) => check(&hash, password),
            None => false,
        }
    }
}

fn validate_name(name: &str) -> Result<(), UserDbError> {
    let ok = !name.is_empty()
        && name.chars().count() <= 64
        && !name.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(())
    } else {
        Err(UserDbError::InvalidName)
    }
}

fn hash_password(password: &str) -> Result<String, UserDbError> {
    if password.is_empty() {
        return Err(UserDbError::EmptyPassword);
    }
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| UserDbError::Hash(e.to_string()))
}

fn check(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}
