use std::error::Error;
use crate::metadata::domain::InnerMetadata;
use crate::constants::errors::ALREADY_EXISTS;

pub trait SecretRepository {
    fn find(&self, id: &str) -> Result<Secret, Box<dyn Error>>;
    fn create(&self, secret: &mut Secret) -> Result<(), Box<dyn Error>>;
    fn save(&self, secret: &Secret) -> Result<(), Box<dyn Error>>;
    fn delete(&self, secret: &Secret) -> Result<(), Box<dyn Error>>;
}

pub struct Secret {
    pub(super) id: String,
    pub(super) data: Vec<u8>, // pkey as a pem file
    pub(super) meta: InnerMetadata,
}

impl Secret {
    pub fn new(data: &[u8]) -> Self {
        Secret {
            id: "".to_string(),
            data: data.to_vec(),
            meta: InnerMetadata::new(),
        }
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// inserts the secret into the repository
    pub fn insert(&mut self) -> Result<(), Box<dyn Error>> {
        if self.id.len() != 0 {
            return Err(ALREADY_EXISTS.into());
        }

        super::get_repository().create(self)?;
        Ok(())
    }

    /// updates the secret into the repository
    pub fn _save(&self) -> Result<(), Box<dyn Error>> {
        super::get_repository().save(self)
    }

    /// deletes the secret from the repository
    pub fn delete(&self) -> Result<(), Box<dyn Error>> {
        super::get_repository().delete(self)
    }
}


#[cfg(test)]
pub mod tests {
    use crate::metadata::domain::InnerMetadata;
    use super::Secret;

    pub fn new_secret() -> Secret {
        let inner_meta = InnerMetadata::new();

        Secret {
            id: "".to_string(),
            data: "this is a secret".as_bytes().to_vec(),
            meta: inner_meta,
        }
    }

    #[test]
    fn secret_new() {
        let data = "testing".as_bytes();
        let secret = Secret::new(data);

        assert_eq!("", secret.id); 
        assert_eq!("testing".as_bytes(), secret.data);
    }
}