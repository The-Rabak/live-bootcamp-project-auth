use welds::errors::Result;
use welds::migrations::prelude::*;

pub(super) fn step(state: &TableState) -> Result<MigrationStep> {
    let alter = change_table(state, "users")?;
    let m = alter.add_column("requires_2fa", Type::Bool);
    Ok(MigrationStep::new("add_requires_mfa_to_users", m))
}
