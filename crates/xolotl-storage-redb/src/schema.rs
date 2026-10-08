//! First-format initialization. Existing stores must retain every metadata key.

use crate::{RedbHistory, RedbOptions, map_db_error};
use redb::{Database, ReadableTable, TableDefinition, TableHandle};
use std::collections::BTreeSet;
use xolotl_source::{ExternalInstallationRecord, MAX_ID_BYTES, SourceScopeAdmission};

pub(super) const STATE_VALUES_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_values");
pub(super) const STATE_LIST_ITEMS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("state_list_items_v1");
pub(super) const STATE_LIST_META_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("state_list_meta_v1");
pub(super) const STATE_HISTORY_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("state_history");
// History queries use the path-first table. Retention uses this time-first
// index so advancing a global floor visits only records before that floor.
pub(super) const STATE_HISTORY_TIME_INDEX_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("state_history_time_index_v1");
pub(super) const STATE_HISTORY_BASELINES_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_history_baselines_v1");
pub(super) const STATE_META_TABLE: TableDefinition<&str, i64> = TableDefinition::new("state_meta");
pub(super) const SOURCE_META_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("source_meta_v1");
pub(super) const SOURCE_SEQUENCE_META_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("source_sequence_meta_v1");
pub(super) const EXTERNAL_INSTALLATIONS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("external_installations_v1");
pub(super) const EXTERNAL_INSTALLATIONS_META_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("external_installations_meta_v1");
pub(super) const EXTERNAL_SOURCE_SCOPES_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("external_source_scopes_v1");
pub(super) const SOURCE_RECEIPTS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("source_receipts_v1");
pub(super) const FACTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("facts");
pub(super) const FACT_INDEX_TABLE: TableDefinition<&[u8], u64> =
    TableDefinition::new("fact_index_v1");
pub(super) const FACT_PROCESS_INDEX_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("fact_process_index");
pub(super) const FACT_META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fact_meta");
pub(super) const EXECUTION_ID_META_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("execution_id_meta");
pub(super) const IDENTITY_PATH_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("identity_paths_v1");
pub(super) const IDENTITY_REF_TABLE: TableDefinition<u64, &str> =
    TableDefinition::new("identity_refs_v1");
pub(super) const IDENTITY_META_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("identity_meta_v1");
// Federation has its own authority and delivery identities. These tables are
// initialized regardless of the optional federation adapter feature so that
// one database has one physical format across feature selections.
pub(super) const FEDERATION_NODE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("federation_node_v1");
pub(super) const FEDERATION_PEERS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_peers_v1");
pub(super) const FEDERATION_GUEST_CONTROLS_TABLE: TableDefinition<&[u8], u64> =
    TableDefinition::new("federation_guest_controls_v1");
pub(super) const FEDERATION_ADMISSIONS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_admissions_v1");
pub(super) const FEDERATION_SUBJECT_GRANTS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_subject_grants_v1");
pub(super) const FEDERATION_EXPORTS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_exports_v1");
pub(super) const FEDERATION_STREAMS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_streams_v1");
pub(super) const FEDERATION_PUBLIC_STREAMS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_public_streams_v1");
pub(super) const FEDERATION_OBJECT_GRANTS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("federation_object_grants_v1");
pub(super) const FEDERATION_OBJECT_SEND_TRANSFERS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_object_send_transfers_v1");
pub(super) const FEDERATION_OBJECT_RECEIVES_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("federation_object_receives_v1");
pub(super) const FEDERATION_OBJECT_RECEIVE_INDEX_TABLE: TableDefinition<&[u8], u64> =
    TableDefinition::new("federation_object_receive_index_v1");
pub(super) const FEDERATION_OBJECT_RECEIVE_GC_FENCES_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("federation_object_receive_gc_fences_v1");
pub(super) const FEDERATION_INVITE_ISSUERS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_invite_issuers_v1");
pub(super) const FEDERATION_INVITATIONS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_invitations_v1");
pub(super) const FEDERATION_INVITE_RECEIPTS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_invite_receipts_v1");
pub(super) const FEDERATION_RECORDS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_records_v1");
pub(super) const FEDERATION_PUBLISH_REQUESTS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_publish_requests_v1");
pub(super) const FEDERATION_SUBSCRIPTIONS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_subscriptions_v1");
pub(super) const FEDERATION_SNAPSHOT_INSTALLS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_snapshot_installs_v1");
pub(super) const FEDERATION_SNAPSHOT_OFFERS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_snapshot_offers_v1");
pub(super) const FEDERATION_SNAPSHOT_OFFER_PINS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_snapshot_offer_pins_v1");
pub(super) const FEDERATION_SNAPSHOT_RECEIPTS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_snapshot_receipts_v1");
pub(super) const FEDERATION_REPLICA_MEMBERS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_replica_members_v1");
pub(super) const FEDERATION_CONTROL_REQUESTS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_control_requests_v1");
pub(super) const FEDERATION_INBOX_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_inbox_v1");
pub(super) const FEDERATION_PUBLIC_FOLLOWERS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_public_followers_v1");
pub(super) const FEDERATION_PUBLIC_FOLLOWER_INBOX_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_public_follower_inbox_v1");
pub(super) const FEDERATION_GUEST_FOLLOWERS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_guest_followers_v1");
pub(super) const FEDERATION_GUEST_FOLLOWER_INBOX_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_guest_follower_inbox_v1");
/// Last fully projected State history timestamp for a federation stream.
pub(super) const FEDERATION_STATE_PROJECTION_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_state_projection_v1");

pub(super) const LAST_HISTORY_MILLIS: &str = "last_history_millis";
pub(super) const HISTORY_FLOOR_MILLIS: &str = "history_floor_millis";
pub(super) const STATE_HISTORY_MODE: &str = "history_mode";
pub(super) const SOURCE_STREAM_COUNT: &str = "retained_stream_count";
pub(super) const NEXT_STATE_LIST_ID: &str = "next_state_list_id";
pub(super) const NEXT_EXTERNAL_AUTHORITY_EPOCH: &str = "next_authority_epoch";
pub(super) const NEXT_FACT_CURSOR: &str = "next_cursor";
pub(super) const EXECUTION_HIGH_WATER: &str = "high_water";
pub(super) const IDENTITY_HIGH_WATER: &str = "high_water";

pub(super) fn initialize(db: &Database, history: RedbHistory) -> Result<(), redb::DatabaseError> {
    let txn = db.begin_write().map_err(map_db_error)?;
    let present: BTreeSet<_> = txn
        .list_tables()
        .map_err(map_db_error)?
        .map(|table| table.name().to_string())
        .collect();
    let fresh = present.is_empty()
        && txn
            .list_multimap_tables()
            .map_err(map_db_error)?
            .next()
            .is_none();
    if !fresh {
        for name in [
            STATE_VALUES_TABLE.name(),
            STATE_LIST_ITEMS_TABLE.name(),
            STATE_LIST_META_TABLE.name(),
            STATE_HISTORY_TABLE.name(),
            STATE_HISTORY_TIME_INDEX_TABLE.name(),
            STATE_HISTORY_BASELINES_TABLE.name(),
            STATE_META_TABLE.name(),
            SOURCE_META_TABLE.name(),
            SOURCE_SEQUENCE_META_TABLE.name(),
            EXTERNAL_INSTALLATIONS_TABLE.name(),
            EXTERNAL_INSTALLATIONS_META_TABLE.name(),
            EXTERNAL_SOURCE_SCOPES_TABLE.name(),
            SOURCE_RECEIPTS_TABLE.name(),
            FACTS_TABLE.name(),
            FACT_INDEX_TABLE.name(),
            FACT_PROCESS_INDEX_TABLE.name(),
            FACT_META_TABLE.name(),
            EXECUTION_ID_META_TABLE.name(),
            IDENTITY_PATH_TABLE.name(),
            IDENTITY_REF_TABLE.name(),
            IDENTITY_META_TABLE.name(),
            FEDERATION_NODE_TABLE.name(),
            FEDERATION_PEERS_TABLE.name(),
            FEDERATION_GUEST_CONTROLS_TABLE.name(),
            FEDERATION_ADMISSIONS_TABLE.name(),
            FEDERATION_SUBJECT_GRANTS_TABLE.name(),
            FEDERATION_EXPORTS_TABLE.name(),
            FEDERATION_STREAMS_TABLE.name(),
            FEDERATION_PUBLIC_STREAMS_TABLE.name(),
            FEDERATION_OBJECT_GRANTS_TABLE.name(),
            FEDERATION_OBJECT_SEND_TRANSFERS_TABLE.name(),
            FEDERATION_OBJECT_RECEIVES_TABLE.name(),
            FEDERATION_OBJECT_RECEIVE_INDEX_TABLE.name(),
            FEDERATION_OBJECT_RECEIVE_GC_FENCES_TABLE.name(),
            FEDERATION_INVITE_ISSUERS_TABLE.name(),
            FEDERATION_INVITATIONS_TABLE.name(),
            FEDERATION_INVITE_RECEIPTS_TABLE.name(),
            FEDERATION_RECORDS_TABLE.name(),
            FEDERATION_PUBLISH_REQUESTS_TABLE.name(),
            FEDERATION_SUBSCRIPTIONS_TABLE.name(),
            FEDERATION_SNAPSHOT_INSTALLS_TABLE.name(),
            FEDERATION_SNAPSHOT_OFFERS_TABLE.name(),
            FEDERATION_SNAPSHOT_OFFER_PINS_TABLE.name(),
            FEDERATION_SNAPSHOT_RECEIPTS_TABLE.name(),
            FEDERATION_REPLICA_MEMBERS_TABLE.name(),
            FEDERATION_CONTROL_REQUESTS_TABLE.name(),
            FEDERATION_INBOX_TABLE.name(),
            FEDERATION_PUBLIC_FOLLOWERS_TABLE.name(),
            FEDERATION_PUBLIC_FOLLOWER_INBOX_TABLE.name(),
            FEDERATION_GUEST_FOLLOWERS_TABLE.name(),
            FEDERATION_GUEST_FOLLOWER_INBOX_TABLE.name(),
            FEDERATION_STATE_PROJECTION_TABLE.name(),
        ] {
            if !present.contains(name) {
                return Err(map_db_error(format!(
                    "storage schema table missing: {name}"
                )));
            }
        }
    }

    txn.open_table(STATE_VALUES_TABLE).map_err(map_db_error)?;
    txn.open_table(STATE_LIST_ITEMS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(STATE_HISTORY_TABLE).map_err(map_db_error)?;
    txn.open_table(STATE_HISTORY_TIME_INDEX_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(STATE_HISTORY_BASELINES_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(SOURCE_META_TABLE).map_err(map_db_error)?;
    txn.open_table(SOURCE_SEQUENCE_META_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(EXTERNAL_INSTALLATIONS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(SOURCE_RECEIPTS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FACTS_TABLE).map_err(map_db_error)?;
    txn.open_table(FACT_INDEX_TABLE).map_err(map_db_error)?;
    txn.open_table(IDENTITY_PATH_TABLE).map_err(map_db_error)?;
    txn.open_table(IDENTITY_REF_TABLE).map_err(map_db_error)?;
    txn.open_table(FACT_PROCESS_INDEX_TABLE)
        .map_err(map_db_error)?;
    // The physical format is independent of which optional adapters are built.
    txn.open_table(FEDERATION_NODE_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_PEERS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_GUEST_CONTROLS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_ADMISSIONS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_SUBJECT_GRANTS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_EXPORTS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_STREAMS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_PUBLIC_STREAMS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_OBJECT_GRANTS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_OBJECT_SEND_TRANSFERS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_OBJECT_RECEIVES_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_OBJECT_RECEIVE_INDEX_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_OBJECT_RECEIVE_GC_FENCES_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_INVITE_ISSUERS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_INVITATIONS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_INVITE_RECEIPTS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_RECORDS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_PUBLISH_REQUESTS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_SNAPSHOT_INSTALLS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_SNAPSHOT_OFFERS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_SNAPSHOT_OFFER_PINS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_SNAPSHOT_RECEIPTS_TABLE)
        .map_err(map_db_error)?;
    // An empty table creates no retention commitments. Enrollment is explicit.
    txn.open_table(FEDERATION_REPLICA_MEMBERS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_CONTROL_REQUESTS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_INBOX_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_PUBLIC_FOLLOWERS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_PUBLIC_FOLLOWER_INBOX_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_GUEST_FOLLOWERS_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_GUEST_FOLLOWER_INBOX_TABLE)
        .map_err(map_db_error)?;
    txn.open_table(FEDERATION_STATE_PROJECTION_TABLE)
        .map_err(map_db_error)?;
    {
        let mut meta = txn.open_table(STATE_META_TABLE).map_err(map_db_error)?;
        if fresh {
            meta.insert(LAST_HISTORY_MILLIS, 0).map_err(map_db_error)?;
            meta.insert("absence_records_v1", 0).map_err(map_db_error)?;
            meta.insert("absence_encoded_bytes_v1", 0)
                .map_err(map_db_error)?;
            meta.insert(HISTORY_FLOOR_MILLIS, i64::MIN)
                .map_err(map_db_error)?;
            meta.insert(STATE_HISTORY_MODE, history.stored_value())
                .map_err(map_db_error)?;
        } else {
            for key in [
                LAST_HISTORY_MILLIS,
                HISTORY_FLOOR_MILLIS,
                "absence_records_v1",
                "absence_encoded_bytes_v1",
            ] {
                if meta.get(key).map_err(map_db_error)?.is_none() {
                    return Err(map_db_error(format!("state metadata missing: {key}")));
                }
            }
            for key in ["absence_records_v1", "absence_encoded_bytes_v1"] {
                if meta
                    .get(key)
                    .map_err(map_db_error)?
                    .is_some_and(|value| value.value() < 0)
                {
                    return Err(map_db_error(format!(
                        "state absence accounting invalid: {key}"
                    )));
                }
            }
        }
        if !fresh {
            let stored = meta
                .get(STATE_HISTORY_MODE)
                .map_err(map_db_error)?
                .ok_or_else(|| map_db_error("state history mode metadata missing"))?
                .value();
            if stored != history.stored_value() {
                return Err(map_db_error(
                    "state history mode does not match the database",
                ));
            }
        }
    }
    initialize_counter(&txn, FACT_META_TABLE, NEXT_FACT_CURSOR, fresh)?;
    initialize_counter(&txn, SOURCE_SEQUENCE_META_TABLE, SOURCE_STREAM_COUNT, fresh)?;
    initialize_counter(&txn, STATE_LIST_META_TABLE, NEXT_STATE_LIST_ID, fresh)?;
    validate_state_list_high_water(&txn)?;
    initialize_counter(
        &txn,
        EXTERNAL_INSTALLATIONS_META_TABLE,
        NEXT_EXTERNAL_AUTHORITY_EPOCH,
        fresh,
    )?;
    validate_external_installation_rows(&txn)?;
    validate_source_stream_rows(&txn)?;
    initialize_counter(&txn, EXECUTION_ID_META_TABLE, EXECUTION_HIGH_WATER, fresh)?;
    initialize_counter(&txn, IDENTITY_META_TABLE, IDENTITY_HIGH_WATER, fresh)?;
    crate::identity::validate_in_txn(&txn).map_err(map_db_error)?;
    txn.commit().map_err(map_db_error)
}

fn validate_state_list_high_water(txn: &redb::WriteTransaction) -> Result<(), redb::DatabaseError> {
    let high = txn
        .open_table(STATE_LIST_META_TABLE)
        .map_err(map_db_error)?
        .get(NEXT_STATE_LIST_ID)
        .map_err(map_db_error)?
        .ok_or_else(|| map_db_error("State List id metadata missing"))?
        .value();
    let items = txn
        .open_table(STATE_LIST_ITEMS_TABLE)
        .map_err(map_db_error)?;
    if let Some((key, _)) = items.last().map_err(map_db_error)? {
        let key = key.value();
        let id = key
            .get(..8)
            .and_then(|id| id.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| map_db_error("State List item key is corrupt"))?;
        if key.len() != 16 || id == 0 || id > high {
            return Err(map_db_error("State List id high water is invalid"));
        }
    }
    Ok(())
}

fn validate_external_installation_rows(
    txn: &redb::WriteTransaction,
) -> Result<(), redb::DatabaseError> {
    let high = txn
        .open_table(EXTERNAL_INSTALLATIONS_META_TABLE)
        .map_err(map_db_error)?
        .get(NEXT_EXTERNAL_AUTHORITY_EPOCH)
        .map_err(map_db_error)?
        .ok_or_else(|| map_db_error("external authority epoch metadata missing"))?
        .value();
    let table = txn
        .open_table(EXTERNAL_INSTALLATIONS_TABLE)
        .map_err(map_db_error)?;
    let scopes = txn
        .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
        .map_err(map_db_error)?;
    let mut used = BTreeSet::new();
    let mut expected_scopes = std::collections::BTreeMap::new();
    for entry in table.iter().map_err(map_db_error)? {
        let (key, value) = entry.map_err(map_db_error)?;
        let record: ExternalInstallationRecord = serde_json::from_slice(value.value())
            .map_err(|_error| map_db_error("external installation record is corrupt"))?;
        if record.definition.id != key.value() || record.definition.validate_admission().is_err() {
            return Err(map_db_error("external installation record is invalid"));
        }
        if record.installation_epoch == 0
            || record.installation_epoch > high
            || !used.insert(record.installation_epoch)
        {
            return Err(map_db_error("external installation epoch is invalid"));
        }
        let sources: BTreeSet<_> = record
            .definition
            .projections
            .iter()
            .filter(|projection| projection.emits.is_some())
            .map(|projection| projection.id.as_str())
            .collect();
        if sources.len() != record.scope_epochs.len() {
            return Err(map_db_error("external Source scope catalog is invalid"));
        }
        for (projection, epoch) in &record.scope_epochs {
            if !sources.contains(projection.as_str())
                || *epoch == 0
                || *epoch > high
                || !used.insert(*epoch)
            {
                return Err(map_db_error("external Source scope epoch is invalid"));
            }
            let source = record
                .definition
                .projection(projection)
                .and_then(|projection| projection.emits.as_ref())
                .ok_or_else(|| map_db_error("external Source declaration is missing"))?;
            expected_scopes.insert(
                format!("{}/{projection}", record.definition.id),
                SourceScopeAdmission::from_declaration(*epoch, source),
            );
        }
    }
    for entry in scopes.iter().map_err(map_db_error)? {
        let (key, epoch) = entry.map_err(map_db_error)?;
        let mut actual: SourceScopeAdmission = serde_json::from_slice(epoch.value())
            .map_err(|_error| map_db_error("external Source scope index is corrupt"))?;
        // The control revision belongs to this active scope row and changes
        // with stream opens/retirements, independently of the declaration.
        actual.stream_revision = 0;
        actual.decision_time_floor_ms = None;
        if expected_scopes.remove(key.value()) != Some(actual) {
            return Err(map_db_error("external Source scope index is invalid"));
        }
    }
    if !expected_scopes.is_empty() {
        return Err(map_db_error("external Source scope index is incomplete"));
    }
    Ok(())
}

// The counter controls admission, so silently trusting a damaged value could
// admit more positions than the configured hard limit. This scan is confined
// to the S-key range and runs only when the database is opened.
fn validate_source_stream_rows(txn: &redb::WriteTransaction) -> Result<(), redb::DatabaseError> {
    let high = txn
        .open_table(EXTERNAL_INSTALLATIONS_META_TABLE)
        .map_err(map_db_error)?
        .get(NEXT_EXTERNAL_AUTHORITY_EPOCH)
        .map_err(map_db_error)?
        .ok_or_else(|| map_db_error("external authority epoch metadata missing"))?
        .value();
    let retained = txn
        .open_table(SOURCE_SEQUENCE_META_TABLE)
        .map_err(map_db_error)?
        .get(SOURCE_STREAM_COUNT)
        .map_err(map_db_error)?
        .ok_or_else(|| map_db_error("Source stream count metadata missing"))?
        .value();
    let maximum = RedbOptions::MAX_SOURCE_STREAM_LIMIT as u64;
    if retained > maximum {
        return Err(map_db_error("Source stream count exceeds maximum"));
    }
    let table = txn.open_table(SOURCE_META_TABLE).map_err(map_db_error)?;
    let scopes = txn
        .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
        .map_err(map_db_error)?;
    let mut observed = 0u64;
    let mut stream_epochs = BTreeSet::new();
    for entry in table
        .range::<&[u8]>(b"S".as_slice()..b"T".as_slice())
        .map_err(map_db_error)?
    {
        let (key, value) = entry.map_err(map_db_error)?;
        let (installation, projection, scope_epoch) = source_stream_key_scope(key.value())
            .ok_or_else(|| map_db_error("Source stream position key is corrupt"))?;
        let bytes = value.value();
        if bytes.len() < 27 || bytes.len() > 26 + MAX_ID_BYTES {
            return Err(map_db_error("Source stream position value is corrupt"));
        }
        let epoch = u64::from_be_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_error| map_db_error("Source stream position value is corrupt"))?,
        );
        let opened_at_revision = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_error| map_db_error("Source stream position value is corrupt"))?,
        );
        let seq = u64::from_be_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_error| map_db_error("Source stream position value is corrupt"))?,
        );
        let open_id_len = u16::from_be_bytes(
            bytes[24..26]
                .try_into()
                .map_err(|_error| map_db_error("Source stream position value is corrupt"))?,
        ) as usize;
        if epoch == 0
            || epoch <= scope_epoch
            || epoch > high
            || !stream_epochs.insert(epoch)
            || opened_at_revision == u64::MAX
            || seq > i64::MAX as u64
            || open_id_len == 0
            || open_id_len > MAX_ID_BYTES
            || bytes.len() != 26 + open_id_len
            || std::str::from_utf8(&bytes[26..]).is_err()
        {
            return Err(map_db_error("Source stream position value is corrupt"));
        }
        let scope_id = format!("{installation}/{projection}");
        let active_scope = scopes
            .get(scope_id.as_str())
            .map_err(map_db_error)?
            .map(|guard| {
                serde_json::from_slice::<SourceScopeAdmission>(guard.value())
                    .map_err(|_error| map_db_error("external Source scope index is corrupt"))
            })
            .transpose()?;
        if let Some(active) = active_scope.filter(|active| active.epoch == scope_epoch)
            && opened_at_revision >= active.stream_revision
        {
            return Err(map_db_error("Source stream position revision is invalid"));
        }
        observed = observed
            .checked_add(1)
            .ok_or_else(|| map_db_error("Source stream count overflow"))?;
        if observed > maximum {
            return Err(map_db_error("Source stream rows exceed maximum"));
        }
    }
    if observed != retained {
        return Err(map_db_error(format!(
            "Source stream count mismatch: metadata {retained}, rows {observed}"
        )));
    }
    Ok(())
}

fn source_stream_key_scope(mut key: &[u8]) -> Option<(&str, &str, u64)> {
    fn segment<'a>(key: &mut &'a [u8]) -> Option<&'a str> {
        let length = u32::from_be_bytes(key.get(..4)?.try_into().ok()?) as usize;
        if length == 0 || length > MAX_ID_BYTES {
            return None;
        }
        let value = std::str::from_utf8(key.get(4..4 + length)?).ok()?;
        *key = key.get(4 + length..)?;
        Some(value)
    }
    key = key.strip_prefix(b"S")?;
    let installation = segment(&mut key)?;
    let projection = segment(&mut key)?;
    let scope_epoch = u64::from_be_bytes(key.get(..8)?.try_into().ok()?);
    if scope_epoch == 0 {
        return None;
    }
    key = key.get(8..)?;
    segment(&mut key)?;
    key.is_empty()
        .then_some((installation, projection, scope_epoch))
}

fn initialize_counter(
    txn: &redb::WriteTransaction,
    table: TableDefinition<&str, u64>,
    key: &str,
    fresh: bool,
) -> Result<(), redb::DatabaseError> {
    let mut meta = txn.open_table(table).map_err(map_db_error)?;
    if fresh {
        meta.insert(key, 0).map_err(map_db_error)?;
    } else if meta.get(key).map_err(map_db_error)?.is_none() {
        return Err(map_db_error(format!(
            "{} metadata missing: {key}",
            table.name()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
