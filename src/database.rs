use crate::error::{DatabaseError, DieselResultError, Error};
use crate::model::UserModel;
use crate::schema::{user as user_table, user::dsl::user as user_data, user::id as user_id};
use crate::user::User;
use diesel::{sqlite::Sqlite, Connection, SqliteConnection};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::collections::HashMap;
use std::error::Error as StdError;
use tracing::warn;
use uuid::Uuid;

pub const LOGS_MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

pub fn establish_connection(database_url: &String) -> SqliteConnection {
    SqliteConnection::establish(database_url).unwrap_or_else(|err| {
        panic!("Error connecting to {}. Err: {}", database_url, err);
    })
}

pub fn run_migrations(
    connection: &mut impl MigrationHarness<Sqlite>,
    embedded_migrations: EmbeddedMigrations,
) -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
    connection.run_pending_migrations(embedded_migrations)?;

    Ok(())
}

pub fn save_user(connection: &mut SqliteConnection, user: &User) -> Result<usize, Error> {
    match diesel::insert_into(user_table::table)
        .values(user.to_model())
        .execute(connection)
    {
        Ok(rows_affected) => Ok(rows_affected),
        Err(err) => Err(Error::Database(DatabaseError::DatabaseInsertUser(
            DieselResultError(err),
        ))),
    }
}

pub fn update_user(conn: &mut SqliteConnection, user: &User) -> Result<usize, Error> {
    match diesel::update(user_table::table.filter(user_id.eq(user.get_id().to_string())))
        .set(&user.to_model())
        .execute(conn)
    {
        Ok(rows_affected) => Ok(rows_affected),
        Err(err) => Err(Error::Database(DatabaseError::DatabaseUpdateUser(
            DieselResultError(err),
        ))),
    }
}

pub fn get_all_users(connection: &mut SqliteConnection) -> Result<HashMap<Uuid, User>, Error> {
    match user_data.load::<UserModel>(connection) {
        Ok(user_models) => {
            let mut users: HashMap<Uuid, User> = HashMap::new();
            for user_model in user_models {
                match user_model.to_user() {
                    Ok(user) => {
                        let _ = users.insert(*user.get_id(), user);
                    }
                    Err(err) => warn!("{}", err),
                }
            }
            Ok(users)
        }
        Err(err) => Err(Error::Database(
            DatabaseError::LoadingUserModelsFromDatabase(DieselResultError(err)),
        )),
    }
}
