pub mod framework;
pub mod application;
pub mod domain;

lazy_static! {
    static ref REPO_PROVIDER: framework::InMemorySessionRepository = {
        framework::InMemorySessionRepository::new()
    }; 
}   

pub fn get_repository() -> Box<&'static dyn domain::SessionRepository> {
    Box::new(&*REPO_PROVIDER)
}