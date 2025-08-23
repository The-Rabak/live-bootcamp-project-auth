use axum::async_trait;
use std::fmt::Debug;
use welds::connections::any::AnyClient;

// Generic error type for repository operations
#[derive(Debug, PartialEq)]
pub enum RepositoryError {
    NotFound,
    AlreadyExists,
    InvalidData(String),
    DatabaseError(String),
    UnexpectedError,
}

impl std::fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepositoryError::NotFound => write!(f, "Resource not found"),
            RepositoryError::AlreadyExists => write!(f, "Resource already exists"),
            RepositoryError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            RepositoryError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            RepositoryError::UnexpectedError => write!(f, "Unexpected error occurred"),
        }
    }
}

impl std::error::Error for RepositoryError {}

#[async_trait]
pub trait BaseRepository<T, D>: Send + Sync
where
    T: Send + Sync,
    D: Send + Sync + Clone,
{
    type Id: Send + Sync + Clone + Debug;

    // Common CRUD operations that all repositories should implement
    async fn create(&mut self, entity_dto: D) -> Result<T, RepositoryError>;
    async fn get_by_id(&self, id: Self::Id) -> Result<T, RepositoryError>;
    async fn update(&mut self, entity_dto: D) -> Result<T, RepositoryError>;
    async fn delete(&mut self, id: Self::Id) -> Result<T, RepositoryError>;
    async fn exists(&self, id: Self::Id) -> Result<bool, RepositoryError>;

    // Optional: List all entities (can be overridden for pagination)
    async fn list_all(&self) -> Result<Vec<T>, RepositoryError> {
        // Default implementation returns empty list
        // Implementing repositories can override this
        Ok(Vec::new())
    }
}

// Trait for repositories that support finding by specific criteria
#[async_trait]
pub trait FindableRepository<T, D, Criteria>: BaseRepository<T, D>
where
    T: Send + Sync,
    D: Send + Sync + Clone,
    Criteria: Send + Sync,
{
    async fn find_by(&self, criteria: Criteria) -> Result<T, RepositoryError>;
    async fn find_all_by(&self, criteria: Criteria) -> Result<Vec<T>, RepositoryError>;
}

// Generic SQL repository implementation
pub struct SqlRepository<T> {
    client: AnyClient,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> SqlRepository<T> {
    pub fn new(client: AnyClient) -> Self {
        Self {
            client,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn client(&self) -> &AnyClient {
        &self.client
    }
}

// Helper trait to convert between domain models and database models
pub trait ModelConverter<DomainModel, DatabaseModel> {
    fn to_database_model(domain: &DomainModel) -> DatabaseModel;
    fn from_database_model(db_model: DatabaseModel) -> DomainModel;
}
