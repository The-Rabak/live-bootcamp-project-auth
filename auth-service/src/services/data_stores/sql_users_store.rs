use crate::domain::data_stores::{
    BaseRepository, FindableRepository, RepositoryError, UserStore, UserStoreError,
};
use crate::domain::{Email, Password, User, UserModel};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use axum::async_trait;
use welds::connections::any::AnyClient;
use welds::prelude::DbState;

// User-specific criteria for finding users
#[derive(Clone)]
pub struct UserFindCriteria {
    pub email: Option<Email>,
    pub id: Option<i32>,
}

// SqlUserStore that implements the generic repository pattern
pub struct SqlUserStore {
    client: AnyClient,
}

impl SqlUserStore {
    pub fn new(client: AnyClient) -> Self {
        Self { client }
    }

    // Helper method to hash passwords
    async fn hash_password(&self, password: &str) -> Result<String, RepositoryError> {
        let password_clone = password.to_owned();
        tokio::task::spawn_blocking(move || {
            let argon2 = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None).map_err(|_| RepositoryError::UnexpectedError)?,
            );
            let salt = SaltString::generate(&mut OsRng);
            let password_hash = argon2
                .hash_password(password_clone.as_bytes(), &salt)
                .map_err(|_| RepositoryError::UnexpectedError)?
                .to_string();
            Ok(password_hash)
        })
        .await
        .map_err(|e| RepositoryError::UnexpectedError)?
    }

    // Helper method to verify passwords
    async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, RepositoryError> {
        let password_clone = password.to_owned();
        let hash_clone = hash.to_owned();

        tokio::task::spawn_blocking(move || {
            let parsed_hash =
                PasswordHash::new(&hash_clone).map_err(|_| RepositoryError::UnexpectedError)?;
            let argon2 = Argon2::default();
            match argon2.verify_password(password_clone.as_bytes(), &parsed_hash) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        })
        .await
        .map_err(|e| RepositoryError::UnexpectedError)?
    }

    // Convert domain User to database UserModel
    async fn to_user_model(&self, user: &User) -> Result<DbState<UserModel>, RepositoryError> {
        let hashed_password = self.hash_password(user.password.as_ref()).await?;
        let now = chrono::Utc::now().timestamp();
        let mut user_model = UserModel::new();
        user_model.email = user.email.as_ref().to_string();
        user_model.password_hash = hashed_password;
        user_model.requires_mfa = user.requires_mfa;
        user_model.created_at = now;
        user_model.updated_at = now;

        Ok(user_model)
    }

    // Convert database UserModel to domain User
    fn from_user_model(&self, user_model: UserModel) -> Result<User, RepositoryError> {
        let email = Email::parse(user_model.email)
            .map_err(|_| RepositoryError::InvalidData("Invalid email in database".to_string()))?;
        let password = Password::from_hash(user_model.password_hash);

        Ok(User {
            email,
            password,
            requires_mfa: user_model.requires_mfa,
        })
    }
}

// Implement the generic BaseRepository for User domain objects
#[async_trait]
impl BaseRepository<DbState<UserModel>, User> for SqlUserStore {
    type Id = i32;

    async fn create(&mut self, user: User) -> Result<DbState<UserModel>, RepositoryError> {
        let mut user_model = self.to_user_model(&user).await?;

        match user_model.save(&self.client).await {
            Ok(_) => Ok(user_model),
            Err(e) => {
                let e_string = e.to_string();
                eprintln!("database error {}", &e);
                Err(RepositoryError::DatabaseError(e_string))
            }
        }
    }

    async fn get_by_id(&self, id: Self::Id) -> Result<DbState<UserModel>, RepositoryError> {
        Ok(UserModel::find_by_id(&self.client, id)
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?
            .ok_or(RepositoryError::NotFound)?)
    }

    async fn update(&mut self, user: User) -> Result<DbState<UserModel>, RepositoryError> {
        let user_model = self.to_user_model(&user).await?;

        // TODO: Implement actual database update with welds
        // Example:
        // let updated_model = user_model.update(&self.client).await
        //     .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;
        // self.from_user_model(updated_model)

        println!(
            "TODO: Implement user update with welds for user: {}",
            user_model.email
        );
        Err(RepositoryError::UnexpectedError)
    }

    async fn delete(&mut self, id: Self::Id) -> Result<DbState<UserModel>, RepositoryError> {
        // TODO: Implement actual database delete with welds
        // 1. First get the user to return it
        // 2. Then delete the user
        // Example:
        // let user_model = UserModel::find_by_id(&self.client, id).await?
        //     .ok_or(RepositoryError::NotFound)?;
        // let user = self.from_user_model(user_model.clone())?;
        // user_model.delete(&self.client).await
        //     .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;
        // Ok(user)

        println!("TODO: Implement user deletion with welds for id: {}", id);
        Err(RepositoryError::NotFound)
    }

    async fn exists(&self, id: Self::Id) -> Result<bool, RepositoryError> {
        // TODO: Implement actual existence check with welds
        // Example:
        // let count = UserModel::count_where(&self.client, |u| u.id.equal(id)).await
        //     .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;
        // Ok(count > 0)

        println!(
            "TODO: Implement user existence check with welds for id: {}",
            id
        );
        Ok(false)
    }

    async fn list_all(&self) -> Result<Vec<DbState<UserModel>>, RepositoryError> {
        // TODO: Implement actual list query with welds
        // Example:
        // let user_models = UserModel::all(&self.client).await
        //     .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;
        // let users: Result<Vec<User>, _> = user_models.into_iter()
        //     .map(|model| self.from_user_model(model))
        //     .collect();
        // users

        println!("TODO: Implement list all users with welds");
        Ok(Vec::new())
    }
}

// Implement FindableRepository for custom search criteria
#[async_trait]
impl FindableRepository<DbState<UserModel>, User, UserFindCriteria> for SqlUserStore {
    async fn find_by(
        &self,
        criteria: UserFindCriteria,
    ) -> Result<DbState<UserModel>, RepositoryError> {
        if let Some(email) = criteria.email {
            return Ok(UserModel::where_col(|u| u.email.equal(email.as_ref()))
                .fetch_one(&self.client)
                .await
                .map_err(|_| RepositoryError::NotFound)?);
        }
        if let Some(id) = criteria.id {
            return Ok(UserModel::find_by_id(&self.client, id)
                .await
                .map_err(|_| RepositoryError::NotFound)?
                .unwrap());
        }
        Err(RepositoryError::InvalidData(String::from("invalid input")))
    }

    async fn find_all_by(
        &self,
        criteria: UserFindCriteria,
    ) -> Result<Vec<DbState<UserModel>>, RepositoryError> {
        // TODO: Implement search for multiple users by criteria
        println!("TODO: Implement find all users by criteria");
        Ok(Vec::new())
    }
}

// Convert RepositoryError to UserStoreError for backward compatibility
impl From<RepositoryError> for UserStoreError {
    fn from(error: RepositoryError) -> Self {
        match error {
            RepositoryError::NotFound => UserStoreError::UserNotFound,
            RepositoryError::AlreadyExists => UserStoreError::UserAlreadyExists,
            RepositoryError::InvalidData(_) => UserStoreError::UnexpectedError,
            RepositoryError::DatabaseError(_) => UserStoreError::UnexpectedError,
            RepositoryError::UnexpectedError => UserStoreError::UnexpectedError,
        }
    }
}

// Implement the specific UserStore trait using the generic repository
#[async_trait]
impl UserStore for SqlUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        self.create(user)
            .await
            .map(|_| ())
            .map_err(UserStoreError::from)
    }

    async fn get_user(&self, email: Email) -> Result<User, UserStoreError> {
        let criteria = UserFindCriteria {
            email: Some(email),
            id: None,
        };

        Ok(self
            .from_user_model(
                self.find_by(criteria)
                    .await
                    .map_err(UserStoreError::from)?
                    .into_inner(),
            )
            .map_err(UserStoreError::from)?)
    }

    async fn delete_user(&mut self, email: Email) -> Result<User, UserStoreError> {
        let criteria = UserFindCriteria {
            email: Some(email),
            id: None,
        };

        let mut user = self.find_by(criteria).await.map_err(UserStoreError::from)?;
        user.delete(&self.client)
            .await
            .map_err(|e| UserStoreError::UnexpectedError)?;

        self.from_user_model(user.into_inner())
            .map_err(UserStoreError::from)
    }

    async fn validate_user(
        &self,
        email: Email,
        password: Password,
    ) -> Result<User, UserStoreError> {
        // Get user by email
        let user = self.get_user(email).await?;

        // Verify password
        if self
            .verify_password(password.as_ref(), user.password.as_ref())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?
        {
            Ok(user)
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}
