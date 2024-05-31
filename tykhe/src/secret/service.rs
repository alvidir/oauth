use super::domain::{Secret, SecretKind};
use super::error::Result;
use crate::user::domain::{User, UserID};
use async_trait::async_trait;

#[async_trait]
pub trait SecretRepository {
    async fn find_by_owner_and_kind(&self, owner: UserID, kind: SecretKind) -> Result<Secret>;
    async fn create(&self, secret: &Secret) -> Result<()>;
    async fn delete(&self, secret: &Secret) -> Result<()>;
    async fn delete_by_owner(&self, owner: &User) -> Result<()>;
}

#[cfg(test)]
pub mod tests {
    use super::super::domain::Secret;
    use super::super::error::{Error, Result};
    use super::SecretRepository;
    use crate::secret::domain::SecretKind;
    use crate::user::domain::{User, UserID};
    use async_trait::async_trait;

    type MockFnFindByOwnerAndKind = fn(owner: UserID, kind: SecretKind) -> Result<Secret>;
    type MockFnCreate = fn(secret: &Secret) -> Result<()>;
    type MockFnSave = fn(secret: &Secret) -> Result<()>;
    type MockFnDelete = fn(secret: &Secret) -> Result<()>;
    type MockFnDeleteByOwner = fn(owner: &User) -> Result<()>;

    #[derive(Default)]
    pub struct SecretRepositoryMock {
        pub fn_find_by_owner_and_kind: Option<MockFnFindByOwnerAndKind>,
        pub fn_create: Option<MockFnCreate>,
        pub fn_save: Option<MockFnSave>,
        pub fn_delete: Option<MockFnDelete>,
        pub fn_delete_by_owner: Option<MockFnDeleteByOwner>,
    }

    #[async_trait]
    impl SecretRepository for SecretRepositoryMock {
        async fn find_by_owner_and_kind(&self, owner: UserID, kind: SecretKind) -> Result<Secret> {
            if let Some(find_by_owner_and_kind_fn) = self.fn_find_by_owner_and_kind {
                return find_by_owner_and_kind_fn(owner, kind);
            }

            Err(Error::Debug)
        }

        async fn create(&self, secret: &Secret) -> Result<()> {
            if let Some(create_fn) = self.fn_create {
                return create_fn(secret);
            }

            Err(Error::Debug)
        }

        async fn delete(&self, secret: &Secret) -> Result<()> {
            if let Some(delete_fn) = self.fn_delete {
                return delete_fn(secret);
            }

            Err(Error::Debug)
        }

        async fn delete_by_owner(&self, owner: &User) -> Result<()> {
            if let Some(delete_by_owner_fn) = self.fn_delete_by_owner {
                return delete_by_owner_fn(owner);
            }

            Err(Error::Debug)
        }
    }
}
