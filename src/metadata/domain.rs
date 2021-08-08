use std::error::Error;
use std::time::{SystemTime};

pub trait MetadataRepository {
    fn find(&self, id: i32) -> Result<Metadata, Box<dyn Error>>;
    fn create(&self, meta: &mut Metadata) -> Result<(), Box<dyn Error>>;
    fn save(&self, meta: &Metadata) -> Result<(), Box<dyn Error>>;
    fn delete(&self, meta: &Metadata) -> Result<(), Box<dyn Error>>;
}

#[derive(Clone)]
pub struct Metadata {
    pub(super) id: i32,
    pub(super) created_at: SystemTime,
    pub(super) updated_at: SystemTime,
}

impl Metadata {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let mut meta = Metadata {
            id: 0,
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
        };

        super::get_repository().create(&mut meta)?;
        Ok(meta)
    }

    pub fn get_id(&self) -> i32 {
        self.id
    }

    pub fn _touch(&mut self) {
        self.updated_at = SystemTime::now();
    }

    pub fn _save(&self) -> Result<(), Box<dyn Error>> {
        super::get_repository().save(self)
    }

    pub fn delete(&self) -> Result<(), Box<dyn Error>> {
        super::get_repository().delete(self)
    }
}

pub struct InnerMetadata {
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl InnerMetadata {
    pub fn new() -> Self {
        InnerMetadata {
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
        }
    }
}