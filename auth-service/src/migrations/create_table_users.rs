use welds::errors::Result;
use welds::migrations::prelude::*;

pub(super) fn step(_state: &TableState) -> Result<MigrationStep> {
    let m = create_table("users")
        .id(|c| c("id", Type::IntBig))
        .column(|c| c("email", Type::String).create_unique_index())
        .column(|c| c("password_hash", Type::String))
        .column(|c| c("created_at", Type::IntBig).is_null())
        .column(|c| c("updated_at", Type::IntBig).is_null());
    Ok(MigrationStep::new("create_table_users", m))
}
