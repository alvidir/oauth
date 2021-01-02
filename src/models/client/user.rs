use diesel::NotFound;
use std::error::Error;
use crate::models::client::Extension;

extern crate diesel;
use crate::diesel::prelude::*;
use crate::postgres::*;

use crate::schema::users;

pub trait Controller {
    fn get_addr(&self) -> &str;
}

#[derive(Queryable, Insertable, Associations)]
#[belongs_to(Client<'_>)]
#[derive(Clone)]
#[table_name = "users"]
pub struct User {
    pub id: i32,
    pub client_id: i32,
    pub email: String,
}

#[derive(Insertable)]
#[table_name="users"]
pub struct NewUser<'a> {
    pub client_id: i32,
    pub email: &'a str,
}

impl User {
    pub fn create<'a>(client_id: i32, email: &'a str) -> Result<Self, Box<dyn Error>> {
        let new_user = NewUser {
            client_id: client_id,
            email: email,
        };

        let connection = open_stream();
        let result = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result::<User>(connection)?;

        Ok(result)
    }

    pub fn find_by_id(target: i32) -> Result<Self, Box<dyn Error>>  {
        use crate::schema::users::dsl::*;

        let connection = open_stream();
        let results = users.filter(id.eq(target))
            .load::<User>(connection)?;

        if results.len() > 0 {
            Ok(results[0].clone())
        } else {
            Err(Box::new(NotFound))
        }
    }

    pub fn find_by_email<'a>(target: &'a str) -> Result<Self, Box<dyn Error>>  {
        use crate::schema::users::dsl::*;

        let connection = open_stream();
        let results = users.filter(email.eq(target))
            .load::<User>(connection)?;

        if results.len() > 0 {
            Ok(results[0].clone())
        } else {
            Err(Box::new(NotFound))
        }
    }

    pub fn build(&self/*, client: Box<dyn ClientController>*/) -> impl Extension {
        Wrapper::new(self.clone()/*, client*/)
    }
}

// A Wrapper stores the relation between a Client and other structs
struct Wrapper{
    data: User,
    //owner: Box<dyn ClientController>,
}

impl Wrapper{
    fn new(data: User/*, client: Box<dyn ClientController>*/) -> Self {
        Wrapper{
            data: data,
            //owner: client,
        }
    }
}

impl Extension for Wrapper {
    fn get_addr(&self) -> String {
        self.data.email.clone()
    }
}