pub mod framework;
pub mod application;
pub mod domain;

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::{Arc, RwLock};
    use std::time::{SystemTime, Duration};
    use std::collections::HashMap;
    use crate::metadata::domain::{Metadata, MetadataRepository};
    use crate::user::domain::{User, UserRepository};
    use super::domain::{Session, SessionRepository};

    const PWD: &str = "ABCD1234";

    lazy_static! {
        pub static ref TESTING_SESSIONS: RwLock<HashMap<String, Arc<RwLock<Session<'static>>>>> = {
            let repo = HashMap::new();
            RwLock::new(repo)
        };    
    }

    struct Mock {}

    impl UserRepository for &Mock {
        fn find(&self, _email: &str) -> Result<User, Box<dyn Error>> {
            Err("unimplemeted".into())
        }

        fn save(&self, user: &mut User) -> Result<(), Box<dyn Error>> {
            user.id = 999;
            Ok(())
        }

        fn delete(&self, _user: &User) -> Result<(), Box<dyn Error>> {
            Err("unimplemeted".into())
        }
    }
    
    impl SessionRepository for &Mock {
        fn find(&self, _cookie: &str) -> Result<Arc<RwLock<Session>>, Box<dyn Error>> {
            Err("unimplemeted".into())
        }

        fn find_by_email(&self, _email: &str) -> Result<Arc<RwLock<Session>>, Box<dyn Error>> {
            Err("unimplemeted".into())
        }

        fn save(&self, mut session: Session<'static>) -> Result<Arc<RwLock<Session<'static>>>, Box<dyn Error>> {
            session.sid = "testing".to_string();

            let mut repo = TESTING_SESSIONS.write()?;
            let email = session.user.email.clone();
            let mu = RwLock::new(session);
            let arc = Arc::new(mu);
            
            repo.insert(email.to_string(), arc);
            let sess = repo.get(email).unwrap();
            Ok(Arc::clone(sess))
        }

        fn delete(&self, _session: &Session) -> Result<(), Box<dyn Error>> {
            Err("unimplemeted".into())
        }
    }
    
    impl MetadataRepository for Mock {
        fn find(&self, _id: i32) -> Result<Metadata, Box<dyn Error>> {
            Err("unimplemeted".into())
        }

        fn save(&self, meta: &mut Metadata) -> Result<(), Box<dyn Error>> {
            meta.id = 999;
            Ok(())
        }

        fn delete(&self, _meta: &Metadata) -> Result<(), Box<dyn Error>> {
            Err("unimplemeted".into())
        }  
    }

    #[test]
    fn domain_session_new_ok() {
        const EMAIL: &str = "dummy@example.com";
        const TIMEOUT: Duration = Duration::from_secs(10);
        let mock_impl = &Mock{};

        let meta = Metadata::new(mock_impl).unwrap();
        let user = User::new(&mock_impl,
                             meta,
                             EMAIL,
                             PWD).unwrap();

        let before = SystemTime::now();
        let sess_arc = Session::new(&mock_impl,
                                    user,
                                    TIMEOUT).unwrap();

        let after = SystemTime::now();
        let sess = sess_arc.read().unwrap();
        
        assert_eq!("testing", sess.sid);
        assert!(sess.deadline < after + TIMEOUT);
        assert!(sess.deadline > before + TIMEOUT);
    }
}