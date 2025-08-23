use welds::errors::Result;
use welds::migrations::prelude::*;

pub async fn up(client: &dyn welds::TransactStart) -> Result<()> {
    let list: Vec<MigrationFn> = vec![create_table_users::step, add_requires_mfa_to_users::step];
    welds::migrations::up(client, list.as_slice()).await?;
    Ok(())
}

mod add_requires_mfa_to_users;
mod create_table_users;
