//! Migration of a strfry relay database into nostrfy.
//!
//! The input is the JSONL produced by `strfry export`: one NIP-01 event per
//! line, ordered by `created_at` ascending. nostrfy does not read strfry's
//! LMDB schema directly (it is strfry-version specific and GPL-licensed
//! code); the export is strfry's own stable interface and works across its
//! database versions.
//!
//! Every event goes through the same storage path a live publish would take
//! ([`DbClient::put_batch_checked`]), so NIP-01 replaceable/addressable
//! semantics, the NIP-40 expiry index, the NIP-50 word index, the gift-wrap
//! recipient index and every other index are maintained. The per-event side
//! effects the relay applies *after* a store are reproduced in input order:
//!
//! - NIP-09 (`kind:5`): the deletion is applied and the deleter's gift wraps
//!   are purged, writing the tombstones that keep the deleted events from
//!   being re-published (strfry physically removes deleted events, so the
//!   export has no trace of them except the deletion requests themselves).
//! - NIP-29 (`kind:9005`): the referenced events are deleted with the group
//!   scoping check.
//! - NIP-29 (`kind:9008`): the group's stored events are purged and the
//!   purge is verified; an incomplete purge aborts the migration
//!   (fail-closed: leftover history would become world-readable if the id
//!   were re-created).
//! - NIP-62 (`kind:62`): only with [`Options::apply_vanish`], and only when
//!   the request targets this relay. Opt-in because strfry does not
//!   implement NIP-62: the events the request names were served by strfry
//!   and are part of the data being migrated.
//!
//! Derived state (NIP-29 groups, NIP-43 roles) is not rebuilt here: the
//! first relay start after the migration replays the stored events, exactly
//! like a fresh database.
//!
//! A failed write or side effect aborts with an error; re-running the same
//! export is safe (duplicates are skipped, and side effects are re-applied
//! so a crash between a store and its side effect cannot leave a tombstone
//! missing).

use std::io::BufRead;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use secp256k1::Secp256k1;

use crate::db::{DbClient, PutOutcome};
use crate::event::Event;
use crate::filter::Filter;
use crate::nips::{nip01, nip09, nip29, nip62};
use crate::util::unix_now;

/// Upper bound on one input batch's total event bytes: `Options::batch`
/// bounds the count, this bounds the transient memory when the export
/// contains large events.
const MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// Options for one migration run.
pub struct Options {
    /// Verify each event's id and signature (the default; `--no-verify`
    /// skips the Schnorr check for trusted dumps).
    pub verify: bool,
    /// Honor NIP-62 `kind:62` requests found in the input (off by default).
    pub apply_vanish: bool,
    /// Whether NIP-62 is enabled in the nostrfy config; a disabled NIP
    /// means the relay would not honor a live vanish either.
    pub nip62_enabled: bool,
    /// Whether NIP-40 is enabled in the nostrfy config: a dry run uses it
    /// to classify already-expired events like the put path would.
    pub nip40_enabled: bool,
    /// Record the first-seen timestamp of each imported author (only
    /// meaningful, and only set, when the new-pubkey gate is configured).
    pub first_seen: bool,
    /// Events per database write transaction.
    pub batch: usize,
    /// Maximum accepted input line length in bytes (the config's
    /// `max_ws_message_bytes`: a longer line cannot be an event this relay
    /// could ever accept).
    pub max_line_bytes: usize,
    /// The relay identity for NIP-62 `relay` tag matching.
    pub host: String,
    pub port: u16,
    pub public_url: String,
    /// The relay's own public key (hex), when `relay.private_key` is
    /// configured: NIP-29 moderation signed by it is authorized (the relay
    /// is the group master key).
    pub relay_pubkey: Option<String>,
    /// The configured NIP-29 group cap, for the authorization replay.
    pub max_groups: usize,
}

/// Counters for one migration run.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Non-empty input lines read.
    pub lines: u64,
    /// Lines that are not a JSON event.
    pub malformed: u64,
    /// Lines longer than `Options::max_line_bytes`.
    pub oversized: u64,
    /// Events whose id/signature verification failed.
    pub bad_signature: u64,
    /// Parsed and verified events (dry-run only: the real run reports the
    /// storage outcome instead).
    pub valid: u64,
    pub stored: u64,
    pub replaced: u64,
    pub duplicate: u64,
    pub expired: u64,
    pub ephemeral: u64,
    pub previously_deleted: u64,
    pub invalid: u64,
    /// NIP-09 deletion requests whose side effect was applied.
    pub deletions_applied: u64,
    /// Author-scoped re-publication blocks recorded for deletion targets
    /// that were already absent from the source (strfry physically removes
    /// deleted events, so the export keeps only the deletion request).
    pub deletion_blocks: u64,
    /// Gift wraps removed while applying NIP-09 deletions.
    pub gift_wrap_purges: u64,
    /// NIP-29 `kind:9005` deletions whose side effect was applied.
    pub group_deletions: u64,
    /// NIP-29 `kind:9008` group purges applied.
    pub group_purges: u64,
    /// Events removed by those purges.
    pub group_purge_removed: u64,
    /// NIP-29 moderation events (9000-9020) whose author was not an admin:
    /// they are stored (strfry kept them) but their side effects and state
    /// changes are not applied.
    pub unauthorized_moderation: u64,
    /// NIP-62 vanishes applied (only with `apply_vanish`).
    pub vanishes: u64,
    /// Events removed by those vanishes.
    pub vanished_events: u64,
    /// Newest `created_at` seen, for the resume hint.
    pub max_created_at: Option<u64>,
}

impl Stats {
    /// Events stored or already present (the migration's useful total).
    pub fn imported(&self) -> u64 {
        self.stored + self.replaced + self.duplicate
    }

    /// Input events that did not reach the database.
    pub fn skipped(&self) -> u64 {
        self.malformed
            + self.oversized
            + self.bad_signature
            + self.expired
            + self.ephemeral
            + self.previously_deleted
            + self.invalid
    }

    fn record(&mut self, outcome: &PutOutcome) {
        match outcome {
            PutOutcome::Stored => self.stored += 1,
            PutOutcome::Replaced => self.replaced += 1,
            PutOutcome::Duplicate(_) => self.duplicate += 1,
            PutOutcome::Expired => self.expired += 1,
            PutOutcome::Ephemeral => self.ephemeral += 1,
            PutOutcome::PreviouslyDeleted => self.previously_deleted += 1,
            PutOutcome::Invalid(_) => self.invalid += 1,
        }
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "read {} event line(s)", self.lines)?;
        if self.valid > 0 {
            writeln!(
                f,
                "valid {} event(s) (dry run: nothing was written)",
                self.valid
            )?;
        } else {
            writeln!(
                f,
                "imported {} event(s): {} stored, {} replaced, {} duplicate",
                self.imported(),
                self.stored,
                self.replaced,
                self.duplicate
            )?;
        }
        writeln!(
            f,
            "skipped {} event(s): {} malformed, {} oversized, {} bad signature, \
             {} expired, {} ephemeral, {} previously deleted, {} rejected",
            self.skipped(),
            self.malformed,
            self.oversized,
            self.bad_signature,
            self.expired,
            self.ephemeral,
            self.previously_deleted,
            self.invalid
        )?;
        if self.unauthorized_moderation > 0 {
            writeln!(
                f,
                "ignored {} NIP-29 moderation event(s) (not applied)",
                self.unauthorized_moderation
            )?;
        }
        write!(
            f,
            "side effects: {} NIP-09 deletion(s) ({} absent-target block(s)), \
             {} gift-wrap purge(s), {} NIP-29 deletion(s), {} group purge(s) \
             ({} events), {} vanish(es) ({} events)",
            self.deletions_applied,
            self.deletion_blocks,
            self.gift_wrap_purges,
            self.group_deletions,
            self.group_purges,
            self.group_purge_removed,
            self.vanishes,
            self.vanished_events
        )
    }
}

/// Runs the migration. `db` is `None` for a dry run: the input is parsed and
/// verified and nothing is written. `on_progress` is called after every
/// flushed batch so the caller can throttle its output.
pub async fn run(
    db: Option<&DbClient>,
    reader: impl BufRead,
    opts: &Options,
    mut on_progress: impl FnMut(&Stats),
) -> Result<Stats> {
    let secp = Secp256k1::new();
    let identity = nip62::RelayIdentity::new(&opts.host, opts.port, &opts.public_url);
    let now = unix_now();
    let mut stats = Stats::default();
    // The configured batch bounds the count; cap the pre-allocation so an
    // absurd `--batch` cannot ask for a huge buffer up front (the byte cap
    // flushes long before it is reached anyway).
    let mut batch: Vec<(Arc<Event>, u64)> = Vec::with_capacity(opts.batch.clamp(1, 4096));
    let mut batch_bytes = 0usize;
    let mut first_seen: Vec<([u8; 32], u64)> = Vec::new();
    let mut previous_created: Option<u64> = None;
    let mut out_of_order_warned = false;
    let mut reader = reader;
    let mut line: Vec<u8> = Vec::new();
    let mut first_line = true;
    loop {
        // Bounded read: a hostile or corrupt line must not exhaust memory
        // (the cap leaves room for the trailing `\r\n`).
        let (bytes_read, truncated) = read_line_capped(
            &mut reader,
            opts.max_line_bytes.saturating_add(2),
            &mut line,
        )
        .context("reading the strfry export")?;
        if bytes_read == 0 {
            break;
        }
        if truncated {
            // Longer than the cap: it cannot be an acceptable event.
            stats.lines += 1;
            stats.oversized += 1;
            continue;
        }
        // A UTF-8 BOM on the very first line (a Windows-edited file) is not
        // part of the JSON.
        let bytes = if first_line {
            first_line = false;
            strip_bom(&line)
        } else {
            &line[..]
        };
        let Ok(text) = std::str::from_utf8(bytes) else {
            stats.lines += 1;
            stats.malformed += 1;
            continue;
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        stats.lines += 1;
        if trimmed.len() > opts.max_line_bytes {
            stats.oversized += 1;
            continue;
        }
        let event: Event = match serde_json::from_str(trimmed) {
            Ok(event) => event,
            Err(_) => {
                stats.malformed += 1;
                continue;
            }
        };
        // strfry export is ascending by created_at; a different source can
        // break the replaceable/deletion replay order. Warn once instead of
        // buffering the whole input to sort it (the export is the supported
        // input, and a huge file cannot be sorted in memory).
        if let Some(previous) = previous_created
            && event.created_at < previous
            && !out_of_order_warned
        {
            log::warn!(
                "migration input is not ordered by created_at ({} after {}); \
                 replaceable and deletion semantics may differ from the source relay",
                event.created_at,
                previous
            );
            out_of_order_warned = true;
        }
        previous_created = Some(event.created_at);
        stats.max_created_at = Some(
            stats
                .max_created_at
                .map_or(event.created_at, |max| max.max(event.created_at)),
        );
        if opts.verify && nip01::verify(&event, &secp).is_err() {
            stats.bad_signature += 1;
            continue;
        }
        batch_bytes = batch_bytes.saturating_add(trimmed.len());
        // A honored NIP-62 vanish blocks the author permanently: flush it on
        // its own so the events that follow in the export meet the marker at
        // put time instead of being committed in the same batch and staying
        // visible.
        let vanish = event.kind == nip62::VANISH_KIND
            && opts.apply_vanish
            && opts.nip62_enabled
            && nip62::is_vanish(&event)
            && nip62::targets_us(&event, &identity);
        batch.push((Arc::new(event), now));
        if vanish || batch.len() >= opts.batch.max(1) || batch_bytes >= MAX_BATCH_BYTES {
            flush(
                db,
                &mut batch,
                &mut batch_bytes,
                &mut stats,
                opts,
                &identity,
                &mut first_seen,
            )
            .await?;
            on_progress(&stats);
        }
    }
    flush(
        db,
        &mut batch,
        &mut batch_bytes,
        &mut stats,
        opts,
        &identity,
        &mut first_seen,
    )
    .await?;
    on_progress(&stats);
    // NIP-29 `9005`/`9008` side effects are applied after the import, in the
    // same rank order the startup rebuild uses. strfry's export orders
    // same-second events by id, so deciding (and deleting) during the
    // stream would disagree with the first restart: a delete the export
    // placed before its group's create would be refused, while the rebuild
    // (create first) applies it. Applying them here keeps the two
    // consistent by construction, and the purge is bounded by the 9008's
    // own timestamp so a re-created group's later events survive.
    if let Some(db) = db {
        // NIP-09 gift-wrap purges first (they are author-scoped and
        // order-independent), then the NIP-29 actions.
        apply_gift_wrap_purges(db, &mut stats).await?;
        apply_group_side_effects(db, opts, &mut stats).await?;
    }
    Ok(stats)
}

/// Reads one line (up to and including `\n`) into `out`, keeping at most
/// `max` bytes and discarding the rest of the line. Returns
/// `(bytes_read, truncated)`, where `bytes_read` counts the whole line
/// including the discarded tail. A hostile or corrupt export line must not
/// exhaust memory; the tail is thrown away and the caller rejects the line.
fn read_line_capped<R: BufRead>(
    reader: &mut R,
    max: usize,
    out: &mut Vec<u8>,
) -> std::io::Result<(usize, bool)> {
    out.clear();
    let mut total = 0usize;
    let mut truncated = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((total, truncated));
        }
        let (take, has_newline) = match available.iter().position(|byte| *byte == b'\n') {
            Some(pos) => (pos + 1, true),
            None => (available.len(), false),
        };
        if !truncated {
            let room = max.saturating_sub(out.len());
            if take <= room {
                out.extend_from_slice(&available[..take]);
            } else {
                out.extend_from_slice(&available[..room]);
                truncated = true;
            }
        }
        total = total.saturating_add(take);
        reader.consume(take);
        if has_newline {
            return Ok((total, truncated));
        }
    }
}

/// Strips a UTF-8 byte-order mark from the start of a line, when present.
fn strip_bom(line: &[u8]) -> &[u8] {
    line.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(line)
}

/// Writes one batch and applies its per-event side effects in input order.
#[allow(clippy::too_many_arguments)]
async fn flush(
    db: Option<&DbClient>,
    batch: &mut Vec<(Arc<Event>, u64)>,
    batch_bytes: &mut usize,
    stats: &mut Stats,
    opts: &Options,
    identity: &nip62::RelayIdentity<'_>,
    first_seen: &mut Vec<([u8; 32], u64)>,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let events = std::mem::take(batch);
    *batch_bytes = 0;
    let Some(db) = db else {
        // Dry run: no database, so classify with the same rules the put
        // path would apply before storage (ephemeral kinds and NIP-40
        // expiry are never stored) and count the rest as valid. Deletion
        // side effects cannot be predicted without the database.
        for (event, now) in &events {
            if (20000..30000).contains(&event.kind) {
                stats.ephemeral += 1;
            } else if opts.nip40_enabled
                && crate::nips::nip40::expiry(event).is_some_and(|exp| exp <= *now)
            {
                stats.expired += 1;
            } else {
                stats.valid += 1;
            }
        }
        return Ok(());
    };
    let outcomes = db.put_batch_checked(events.clone()).await.ok_or_else(|| {
        anyhow!("database writer unavailable; the migration did not complete (re-run it)")
    })?;
    if outcomes.len() != events.len() {
        bail!(
            "database returned {} outcome(s) for {} event(s); the migration did not \
             complete (re-run it)",
            outcomes.len(),
            events.len()
        );
    }
    for ((event, _), outcome) in events.iter().zip(outcomes.iter()) {
        stats.record(outcome);
        let accepted = matches!(
            outcome,
            PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Duplicate(_)
        );
        if !accepted {
            continue;
        }
        // First-seen uses the event's own timestamp: with the ascending
        // export order, the first accepted event of an author records their
        // arrival (the insert is first-wins, so later batches cannot move
        // it). Only written when the new-pubkey gate is configured: with
        // the gate disabled the table is never reaped, and populating it
        // would grow it without bound.
        if opts.first_seen
            && let Some(pubkey) = event.pubkey_bytes()
        {
            first_seen.push((pubkey, event.created_at));
        }
        match event.kind {
            nip09::DELETION_KIND => apply_nip09(db, event, stats).await?,
            nip62::VANISH_KIND
                if opts.apply_vanish
                    && opts.nip62_enabled
                    && nip62::is_vanish(event)
                    && nip62::targets_us(event, identity) =>
            {
                apply_vanish(db, event, stats).await?
            }
            _ => {}
        }
    }
    if opts.first_seen && !first_seen.is_empty() {
        db.touch_first_seen_batch(std::mem::take(first_seen)).await;
    }
    Ok(())
}

/// Replays one event into the NIP-29 authorization state, returning whether
/// a moderation event's author is allowed to act. The rule mirrors the live
/// write path: the relay's own key is the group master key, an existing
/// group requires an admin, and an unknown group only accepts a create.
fn replay_moderation(
    groups: &mut crate::nips::nip29::GroupStore,
    event: &Event,
    relay_pubkey: Option<&str>,
) -> bool {
    if (crate::nips::nip29::MOD_MIN..=crate::nips::nip29::MOD_MAX).contains(&event.kind)
        && !relay_pubkey.is_some_and(|pk| pk.eq_ignore_ascii_case(&event.pubkey))
    {
        let authorized = match crate::nips::nip29::group_id(event).and_then(|gid| groups.group(gid))
        {
            Some(group) => group.is_admin(&event.pubkey),
            None => event.kind == crate::nips::nip29::CREATE_GROUP,
        };
        if !authorized {
            return false;
        }
    }
    groups.apply(event, relay_pubkey.unwrap_or(""), unix_now(), false, true);
    true
}

/// Replays the NIP-09 gift-wrap purges from the stored deletion requests:
/// one purge per author, bounded by their newest request's timestamp (the
/// live relay purges the recipient's wraps when a request arrives). The
/// replay covers the whole stored history, so a resumed run (`--since`)
/// still purges the wraps of requests imported by an earlier run, and the
/// per-author aggregation bounds memory.
async fn apply_gift_wrap_purges(db: &DbClient, stats: &mut Stats) -> Result<()> {
    let mut by_author: std::collections::HashMap<[u8; 32], u64> = std::collections::HashMap::new();
    const PAGE: usize = 50_000;
    let mut since: Option<u64> = None;
    loop {
        let mut filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({ "kinds": [nip09::DELETION_KIND] }))
                .expect("static filter");
        filter.since = since;
        let boundary_filter = filter.clone();
        let Some((page, more)) = db
            .query_full_startup(vec![filter], PAGE, unix_now(), true)
            .await
        else {
            bail!(
                "could not read the stored NIP-09 requests for the gift-wrap purge; the \
                 migration did not complete (re-run it)"
            );
        };
        if page.is_empty() {
            break;
        }
        let max_created = page.last().map(|event| event.created_at);
        let boundary_count = page
            .iter()
            .filter(|event| Some(event.created_at) == max_created)
            .count();
        for event in &page {
            if let Some(pubkey) = event.pubkey_bytes() {
                let entry = by_author.entry(pubkey).or_insert(0);
                *entry = (*entry).max(event.created_at);
            }
        }
        if !more {
            break;
        }
        // The collector can cut a second at its caps while still reporting
        // `more`: verify the boundary before stepping past it, or a
        // request in the cut second would be skipped (fail open).
        let Some(boundary) = max_created else {
            break;
        };
        if !crate::nips::nip29::boundary_second_complete(
            db,
            boundary_filter,
            boundary,
            boundary_count,
        )
        .await
        {
            bail!(
                "the stored NIP-09 boundary second {boundary} is not fully collected; \
                 the migration did not complete (re-run it)"
            );
        }
        if boundary == u64::MAX {
            break;
        }
        since = Some(boundary.saturating_add(1));
    }
    for (pubkey, until) in by_author {
        match db.delete_gift_wraps_to_checked(pubkey, until).await {
            Some(purged) => stats.gift_wrap_purges += purged as u64,
            None => bail!(
                "NIP-59 gift-wrap purge was not applied; the migration did not \
                 complete (re-run it)"
            ),
        }
    }
    Ok(())
}

/// Applies the NIP-29 `9005`/`9008` side effects the startup rebuild will
/// honor: replays the stored moderation events in the rebuild's order
/// (the relay's live write path only lets a group admin or the relay key
/// moderate, but strfry stores every signed event) and applies each
/// authorized action.
async fn apply_group_side_effects(db: &DbClient, opts: &Options, stats: &mut Stats) -> Result<()> {
    // A `9005` that removes a state event changes the state later actions
    // are authorized against, and the startup rebuild sees the post-delete
    // database: reconcile to a fixpoint so the two cannot disagree. Each
    // round applies only actions not yet applied, and only a round that
    // removed a state event repeats (a purge always can, so it repeats
    // once); the replay is then exactly what the restart will do.
    let mut applied: std::collections::HashSet<String> = std::collections::HashSet::new();
    loop {
        let mut groups = crate::nips::nip29::GroupStore::with_cap(opts.max_groups);
        let (actions, refused) =
            replay_stored_moderation(db, &mut groups, opts.relay_pubkey.as_deref()).await?;
        // The last round replays the final database: its refusal count is
        // exactly what the startup rebuild will ignore (accumulating over
        // rounds would double-count).
        stats.unauthorized_moderation = refused;
        let mut fresh = Vec::new();
        for event in actions {
            if applied.insert(event.id.clone()) {
                fresh.push(event);
            }
        }
        if fresh.is_empty() {
            break;
        }
        let mut state_changed = false;
        for event in &fresh {
            match event.kind {
                9005 => state_changed |= apply_group_deletion(db, event, stats).await?,
                9008 => {
                    apply_group_purge(db, event, stats).await?;
                    state_changed = true;
                }
                _ => {}
            }
        }
        if !state_changed {
            break;
        }
    }
    Ok(())
}

/// Replays the stored NIP-29 moderation events in the same
/// `(created_at, group_rank, kind, id)` order as the startup rebuild,
/// returning the authorized `9005`/`9008` events in order and how many
/// moderation events the gate refused.
///
/// The replay covers the whole stored history, so a resumed migration
/// (`--since`) or a merge into an existing database authorizes against the
/// state its predecessors built. A cut page boundary is verified like the
/// rebuild: a silently dropped second would authorize against an
/// incomplete state.
async fn replay_stored_moderation(
    db: &DbClient,
    groups: &mut crate::nips::nip29::GroupStore,
    relay_pubkey: Option<&str>,
) -> Result<(Vec<Event>, u64)> {
    let kinds: Vec<u64> = (crate::nips::nip29::MOD_MIN..=crate::nips::nip29::MOD_MAX)
        .chain([crate::nips::nip29::JOIN, crate::nips::nip29::LEAVE])
        .collect();
    // The rebuild skips joins by vanished authors and strips their `p`
    // tags from 9000 grants; the replay must do the same or it would
    // authorize against a state the restart will not reproduce.
    let mut vanished: std::collections::HashSet<String> = std::collections::HashSet::new();
    if db
        .vanish_pubkeys_each(|key| {
            vanished.insert(hex::encode(key));
            vanished.insert(hex::encode_upper(key));
        })
        .await
        .is_none()
    {
        bail!(
            "could not read the vanished-pubkey list for the moderation replay; the \
             migration did not complete (re-run it)"
        );
    }
    const PAGE: usize = 50_000;
    let mut since: Option<u64> = None;
    let mut actions = Vec::new();
    let mut refused = 0u64;
    loop {
        let mut filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({ "kinds": kinds })).expect("static filter");
        filter.since = since;
        let boundary_filter = filter.clone();
        let Some((mut page, more)) = db
            .query_full_startup(vec![filter], PAGE, unix_now(), true)
            .await
        else {
            bail!(
                "could not read the stored NIP-29 state for the moderation replay; the \
                 migration did not complete (re-run it)"
            );
        };
        if page.is_empty() {
            break;
        }
        page.sort_by(|a, b| {
            (
                a.created_at,
                crate::nips::nip29::group_rank(a.kind),
                a.kind,
                &a.id,
            )
                .cmp(&(
                    b.created_at,
                    crate::nips::nip29::group_rank(b.kind),
                    b.kind,
                    &b.id,
                ))
        });
        let max_created = page.last().map(|event| event.created_at);
        let boundary_count = page
            .iter()
            .filter(|event| Some(event.created_at) == max_created)
            .count();
        for mut event in page {
            if event.kind == crate::nips::nip29::JOIN && vanished.contains(&event.pubkey) {
                continue;
            }
            if event.kind == 9000 {
                event
                    .tags
                    .retain(|tag| tag.len() < 2 || tag[0] != "p" || !vanished.contains(&tag[1]));
                if event.tags.is_empty() {
                    continue;
                }
            }
            if replay_moderation(groups, &event, relay_pubkey) {
                if matches!(event.kind, 9005 | 9008) {
                    actions.push(event);
                }
            } else {
                refused += 1;
            }
        }
        if !more {
            break;
        }
        // The collector can cut a second at its byte/tie caps while still
        // reporting `more`. Advancing past an unverified boundary would
        // silently drop stored moderation events (and authorize against an
        // incomplete state); fail the migration instead.
        let Some(boundary) = max_created else {
            break;
        };
        if !crate::nips::nip29::boundary_second_complete(
            db,
            boundary_filter,
            boundary,
            boundary_count,
        )
        .await
        {
            bail!(
                "the stored NIP-29 state boundary second {boundary} is not fully collected; \
                 the migration did not complete (re-run it)"
            );
        }
        if boundary == u64::MAX {
            break;
        }
        since = Some(boundary.saturating_add(1));
    }
    Ok((actions, refused))
}

/// NIP-09: apply the deletion and purge the deleter's gift wraps (the relay
/// does both after storing the request).
async fn apply_nip09(db: &DbClient, event: &Event, stats: &mut Stats) -> Result<()> {
    let targets = nip09::deletion_targets(event);
    let (removed, _state_removed) = db
        .apply_deletion_checked(
            targets.clone(),
            nip09::deletion_addresses(event),
            Some(event.pubkey.clone()),
            event.created_at,
        )
        .await;
    if removed.is_none() {
        bail!(
            "NIP-09 deletion side effect was not applied; the migration did not \
             complete (re-run it)"
        );
    }
    stats.deletions_applied += 1;
    if let Some(pubkey) = event.pubkey_bytes() {
        // strfry removes deleted events physically, so the export has no
        // trace of a target its author deleted and the walk above cannot
        // write the ordinary tombstone for it. Record the author-scoped
        // re-publication block strfry kept (its `(id, pubkey)` deletion
        // record) so the deleted event cannot be re-published here.
        match db.record_absent_deletion_targets(pubkey, targets).await {
            Some(recorded) => stats.deletion_blocks += recorded as u64,
            None => bail!(
                "could not record the NIP-09 re-publication blocks; the migration did \
                 not complete (re-run it)"
            ),
        }
        // The wrap purge is replayed from the stored deletion requests
        // after the import (see `apply_gift_wrap_purges`): deciding it
        // during the stream made a same-second wrap's fate depend on the
        // batch boundary, and a resumed run must still purge the wraps of
        // deletion requests imported earlier.
    }
    Ok(())
}

/// NIP-29 `kind:9005`: delete the referenced events, scoped to the group.
/// Returns whether a NIP-29/43 state event was removed: only then does the
/// authorization replay need to run again (the live relay marks the derived
/// state stale for the same reason).
async fn apply_group_deletion(db: &DbClient, event: &Event, stats: &mut Stats) -> Result<bool> {
    let Some(gid) = nip29::group_id(event) else {
        return Ok(false);
    };
    let (removed, state_removed) = db
        .apply_group_deletion_checked(nip29::delete_targets(event), gid.to_string())
        .await;
    if removed.is_none() {
        bail!(
            "NIP-29 9005 deletion side effect for group {gid} was not applied; the \
             migration did not complete (re-run it)"
        );
    }
    stats.group_deletions += 1;
    Ok(state_removed)
}

/// NIP-29 `kind:9008`: purge the group's stored events and verify the purge
/// completed. An incomplete purge must abort the migration: the leftover
/// history would be served (or exposed by a re-created group) even though
/// the source relay deleted the group.
async fn apply_group_purge(db: &DbClient, event: &Event, stats: &mut Stats) -> Result<()> {
    let Some(gid) = nip29::group_id(event) else {
        return Ok(());
    };
    // The cut is the 9008's own created_at, not the migration's wall clock:
    // the marker must block re-publication of the history the deletion
    // removed (everything up to the 9008), while events imported after it —
    // a re-created group's posts — must stay acceptable. The live relay
    // uses `now()` because it processes the event when it arrives; a
    // historical import must use the event's own time.
    // Bounded by the 9008's own created_at: events imported after it (a
    // re-created group) survive, and the marker's cut is its timestamp. A
    // historical merge must not remove newer already-stored events either.
    let removed = db
        .group_purge_until(gid.to_string(), event.created_at, event.created_at)
        .await;
    stats.group_purges += 1;
    stats.group_purge_removed += removed as u64;
    // The purge reports a failure as zero removed (indistinguishable from
    // "nothing to purge"), so completion is confirmed by the absence of any
    // stored event tagged with the group id up to the cut — including the
    // 9008 itself. Events after the cut (a re-created group) may remain.
    // A failed query stays fail-closed: it must not be mistaken for a
    // completed purge.
    let mut filter: Filter =
        serde_json::from_value(serde_json::json!({ "#h": [gid] })).expect("static filter");
    filter.until = Some(event.created_at);
    let Some((remaining, _)) = db
        .query_full_startup(vec![filter], 1, unix_now(), false)
        .await
    else {
        bail!(
            "could not verify the group purge for {gid}; the migration did not \
             complete (re-run it)"
        );
    };
    if !remaining.is_empty() {
        bail!(
            "group purge for {gid} did not complete ({} event(s) remain); the \
             migration did not complete (re-run it)",
            remaining.len()
        );
    }
    log::info!("migrate-strfry: purged group {gid} ({removed} event(s))");
    Ok(())
}

/// NIP-62: delete the author's history and record the permanent vanish
/// marker (only reached with `Options::apply_vanish`).
async fn apply_vanish(db: &DbClient, event: &Event, stats: &mut Stats) -> Result<()> {
    let Some(pubkey) = event.pubkey_bytes() else {
        return Ok(());
    };
    match db.apply_vanish_checked(pubkey, event.created_at).await {
        Some((removed, _state_removed)) => {
            stats.vanishes += 1;
            stats.vanished_events += removed as u64;
        }
        None => bail!(
            "NIP-62 vanish side effect was not applied; the migration did not \
             complete (re-run it)"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;
    use crate::db::PutOutcome;
    use secp256k1::Keypair;

    fn test_db(name: &str) -> DbClient {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cfg = DatabaseConfig {
            path: std::env::temp_dir()
                .join("nostrfy-migrate-test")
                .join(format!("{name}-{id}")),
            // Small mappings: the test VM cannot afford several
            // default-sized LMDB reservations at once.
            map_size: 16 * 1024 * 1024,
            max_map_size: 64 * 1024 * 1024,
            disabled_fsync: true,
            ..Default::default()
        };
        let _ = std::fs::remove_dir_all(&cfg.path);
        DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            0,
            512,
            4096,
            262_144,
        )
        .expect("test database must open")
    }

    fn options() -> Options {
        Options {
            verify: true,
            apply_vanish: false,
            nip62_enabled: true,
            nip40_enabled: true,
            first_seen: false,
            batch: 3,
            max_line_bytes: 1024 * 1024,
            host: "127.0.0.1".into(),
            port: 8080,
            public_url: String::new(),
            relay_pubkey: None,
            max_groups: 0,
        }
    }

    fn keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        Keypair::from_seckey_slice(&secp, &[seed; 32]).unwrap()
    }

    fn signed(seed: u8, kind: u64, created: u64, tags: Vec<Vec<String>>, content: &str) -> Event {
        let secp = Secp256k1::new();
        let mut event = Event {
            id: String::new(),
            pubkey: keypair(seed).x_only_public_key().0.to_string(),
            created_at: created,
            kind,
            tags,
            content: content.to_string(),
            sig: String::new(),
        };
        nip01::sign(&mut event, &keypair(seed), &secp).unwrap();
        event
    }

    fn jsonl(events: &[Event]) -> String {
        let mut out = String::new();
        for event in events {
            out.push_str(&serde_json::to_string(event).unwrap());
            out.push('\n');
        }
        out
    }

    fn run_str(db: &DbClient, input: &str, opts: &Options) -> Stats {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            run(Some(db), std::io::Cursor::new(input), opts, |_| {})
                .await
                .expect("migration must succeed")
        })
    }

    fn visible(db: &DbClient, filter: serde_json::Value) -> Vec<Event> {
        let filter: Filter = serde_json::from_value(filter).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (events, _) = db.query(vec![filter], 100, unix_now()).await;
            events
        })
    }

    #[test]
    fn migrates_events_and_keeps_replaceable_semantics() {
        let db = test_db("replaceable");
        let now = unix_now();
        let first = signed(1, 10000, now - 10, vec![], "first");
        let second = signed(1, 10000, now - 5, vec![], "second");
        let addressable = signed(
            1,
            30000,
            now - 4,
            vec![vec!["d".into(), "x".into()]],
            "addr",
        );
        let stats = run_str(&db, &jsonl(&[first, second, addressable]), &options());
        assert_eq!(stats.stored, 2, "the first version is replaced");
        assert_eq!(stats.replaced, 1);
        let events = visible(&db, serde_json::json!({"kinds": [10000]}));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].content, "second");
        assert_eq!(visible(&db, serde_json::json!({"kinds": [30000]})).len(), 1);
        db.shutdown();
    }

    #[test]
    fn nip09_deletion_writes_tombstones() {
        let db = test_db("nip09");
        let now = unix_now();
        let target = signed(1, 1, now - 10, vec![], "delete me");
        let deletion = signed(
            1,
            nip09::DELETION_KIND,
            now - 5,
            vec![vec!["e".into(), target.id.clone()]],
            "",
        );
        let stats = run_str(&db, &jsonl(&[target.clone(), deletion]), &options());
        assert_eq!(stats.deletions_applied, 1);
        assert!(
            visible(&db, serde_json::json!({"ids": [target.id]})).is_empty(),
            "the deleted event must not be visible"
        );
        // Re-publishing it (a later copy, as a client retry would) is
        // rejected by the tombstone.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let outcome = rt.block_on(db.put(target, unix_now()));
        assert!(
            matches!(outcome, PutOutcome::PreviouslyDeleted),
            "the tombstone must block re-publication, got {outcome:?}"
        );
        db.shutdown();
    }

    #[test]
    fn nip09_address_deletion_bounds_versions() {
        let db = test_db("nip09-address");
        let now = unix_now();
        let old = signed(
            1,
            30001,
            now - 10,
            vec![vec!["d".into(), "s".into()]],
            "old",
        );
        let deletion = signed(
            1,
            nip09::DELETION_KIND,
            now - 5,
            vec![vec!["a".into(), format!("30001:{}:s", old.pubkey)]],
            "",
        );
        let newer = signed(
            1,
            30001,
            now - 1,
            vec![vec!["d".into(), "s".into()]],
            "newer",
        );
        let stats = run_str(
            &db,
            &jsonl(&[old.clone(), deletion, newer.clone()]),
            &options(),
        );
        assert_eq!(stats.deletions_applied, 1);
        let events = visible(&db, serde_json::json!({"kinds": [30001]}));
        assert_eq!(events.len(), 1, "only the version above the cut survives");
        assert_eq!(events[0].content, "newer");
        db.shutdown();
    }

    #[test]
    fn expired_ephemeral_and_bad_signature_are_skipped() {
        let db = test_db("skips");
        let now = unix_now();
        let expired = signed(
            1,
            1,
            now - 10,
            vec![vec!["expiration".into(), "1".into()]],
            "expired",
        );
        let ephemeral = signed(1, 20_000, now - 1, vec![], "ephemeral");
        let mut bad = signed(1, 1, now - 1, vec![], "bad sig");
        bad.sig = "00".repeat(64);
        let good = signed(1, 1, now - 1, vec![], "good");
        let input = format!(
            "not json\n{}\n{}\n{}\n{}\n",
            serde_json::to_string(&expired).unwrap(),
            serde_json::to_string(&ephemeral).unwrap(),
            serde_json::to_string(&bad).unwrap(),
            serde_json::to_string(&good).unwrap(),
        );
        let stats = run_str(&db, &input, &options());
        assert_eq!(stats.malformed, 1);
        assert_eq!(stats.bad_signature, 1);
        assert_eq!(stats.expired, 1);
        assert_eq!(stats.ephemeral, 1);
        assert_eq!(stats.stored, 1);
        assert_eq!(visible(&db, serde_json::json!({})).len(), 1);
        db.shutdown();
    }

    #[test]
    fn oversized_lines_are_skipped() {
        let db = test_db("oversized");
        let now = unix_now();
        let mut opts = options();
        opts.max_line_bytes = 200;
        let event = signed(1, 1, now - 1, vec![], "content");
        let line = serde_json::to_string(&event).unwrap();
        assert!(line.len() > 200);
        let stats = run_str(&db, &format!("{line}\n"), &opts);
        assert_eq!(stats.oversized, 1);
        assert_eq!(stats.stored, 0);
        db.shutdown();
    }

    #[test]
    fn re_running_the_same_export_is_idempotent() {
        let db = test_db("idempotent");
        let now = unix_now();
        let note = signed(1, 1, now - 10, vec![], "hello");
        let deletion = signed(
            1,
            nip09::DELETION_KIND,
            now - 5,
            vec![vec!["e".into(), note.id.clone()]],
            "",
        );
        let input = jsonl(&[note.clone(), deletion.clone()]);
        let first = run_str(&db, &input, &options());
        assert_eq!(first.stored, 2, "the note and the deletion request store");
        assert_eq!(first.deletions_applied, 1);
        let second = run_str(&db, &input, &options());
        assert_eq!(
            second.duplicate, 1,
            "the deletion request is a duplicate on the re-run"
        );
        assert_eq!(
            second.previously_deleted, 1,
            "the deleted note is rejected by its tombstone on the re-run"
        );
        assert_eq!(
            second.deletions_applied, 1,
            "the side effect is re-applied so a crash cannot leave it missing"
        );
        assert!(visible(&db, serde_json::json!({"ids": [note.id]})).is_empty());
        db.shutdown();
    }

    #[test]
    fn group_delete_event_writes_tombstones() {
        let db = test_db("group-9005");
        let now = unix_now();
        let create = signed(1, 9007, now - 20, vec![vec!["h".into(), "g1".into()]], "");
        let post = signed(1, 9, now - 10, vec![vec!["h".into(), "g1".into()]], "post");
        let delete = signed(
            1,
            9005,
            now - 5,
            vec![
                vec!["h".into(), "g1".into()],
                vec!["e".into(), post.id.clone()],
            ],
            "",
        );
        let stats = run_str(&db, &jsonl(&[create, post.clone(), delete]), &options());
        assert_eq!(stats.group_deletions, 1);
        assert!(visible(&db, serde_json::json!({"ids": [post.id]})).is_empty());
        db.shutdown();
    }

    #[test]
    fn unauthorized_group_moderation_is_not_applied() {
        // strfry stores every signed event, so the export can contain
        // moderation events nostrfy's write path would have rejected. A
        // non-admin's 9005/9008 must not delete or purge (the events stay
        // stored; the startup rebuild ignores them too).
        let db = test_db("unauthorized-moderation");
        let now = unix_now();
        let create = signed(1, 9007, now - 40, vec![vec!["h".into(), "g".into()]], "");
        let post = signed(1, 9, now - 30, vec![vec!["h".into(), "g".into()]], "post");
        let bad_delete = signed(
            2,
            9005,
            now - 20,
            vec![
                vec!["h".into(), "g".into()],
                vec!["e".into(), post.id.clone()],
            ],
            "",
        );
        let bad_purge = signed(2, 9008, now - 10, vec![vec!["h".into(), "g".into()]], "");
        let stats = run_str(
            &db,
            &jsonl(&[create, post.clone(), bad_delete, bad_purge]),
            &options(),
        );
        assert_eq!(stats.group_deletions, 0);
        assert_eq!(stats.group_purges, 0);
        assert_eq!(stats.unauthorized_moderation, 2);
        assert_eq!(
            visible(&db, serde_json::json!({"ids": [post.id]})).len(),
            1,
            "an unauthorized 9005 must not delete the post"
        );
        assert_eq!(
            visible(&db, serde_json::json!({"kinds": [9007]})).len(),
            1,
            "an unauthorized 9008 must not purge the group"
        );
        // The relay's own key is the master key: its 9005 applies.
        let relay_key = keypair(3);
        let relay_pubkey = relay_key.x_only_public_key().0.to_string();
        let relay_delete = signed(
            3,
            9005,
            now - 5,
            vec![
                vec!["h".into(), "g".into()],
                vec!["e".into(), post.id.clone()],
            ],
            "",
        );
        let stats = run_str(
            &db,
            &jsonl(&[relay_delete]),
            &Options {
                relay_pubkey: Some(relay_pubkey),
                ..options()
            },
        );
        assert_eq!(stats.group_deletions, 1, "the relay-signed 9005 applies");
        assert!(visible(&db, serde_json::json!({"ids": [post.id]})).is_empty());
        db.shutdown();
    }

    #[test]
    fn group_purge_removes_the_group_history() {
        let db = test_db("group-9008");
        let now = unix_now();
        let create = signed(1, 9007, now - 20, vec![vec!["h".into(), "g2".into()]], "");
        let post = signed(1, 9, now - 10, vec![vec!["h".into(), "g2".into()]], "post");
        let delete = signed(1, 9008, now - 5, vec![vec!["h".into(), "g2".into()]], "");
        let stats = run_str(&db, &jsonl(&[create, post, delete]), &options());
        assert_eq!(stats.group_purges, 1);
        assert_eq!(stats.unauthorized_moderation, 0);
        assert!(
            visible(&db, serde_json::json!({})).is_empty(),
            "every h-tagged event (including the 9008) must be purged"
        );
        db.shutdown();
    }

    #[test]
    fn gift_wraps_are_purged_with_the_deletion() {
        let db = test_db("gift-wrap");
        let now = unix_now();
        let author = keypair(1).x_only_public_key().0.to_string();
        // A wrap from another key addressed to the author (content and
        // signature validity do not matter for the recipient index).
        let wrap = signed(
            2,
            1059,
            now - 10,
            vec![vec!["p".into(), author.clone()]],
            "wrap",
        );
        let deletion = signed(1, nip09::DELETION_KIND, now - 5, vec![], "");
        let stats = run_str(&db, &jsonl(&[wrap.clone(), deletion]), &options());
        assert_eq!(stats.gift_wrap_purges, 1);
        assert!(visible(&db, serde_json::json!({"ids": [wrap.id]})).is_empty());
        db.shutdown();
    }

    #[test]
    fn vanish_is_opt_in_and_targets_this_relay() {
        // Off by default: the author's events stay (strfry served them).
        let db = test_db("vanish-off");
        let now = unix_now();
        let note = signed(1, 1, now - 10, vec![], "note");
        let vanish = signed(
            1,
            nip62::VANISH_KIND,
            now - 5,
            vec![vec!["relay".into(), "ALL_RELAYS".into()]],
            "",
        );
        let stats = run_str(&db, &jsonl(&[note.clone(), vanish.clone()]), &options());
        assert_eq!(stats.vanishes, 0);
        assert_eq!(visible(&db, serde_json::json!({"ids": [note.id]})).len(), 1);
        db.shutdown();

        // On: the history is deleted and the marker blocks the author.
        let db = test_db("vanish-on");
        let mut opts = options();
        opts.apply_vanish = true;
        let stats = run_str(&db, &jsonl(&[note.clone(), vanish]), &opts);
        assert_eq!(stats.vanishes, 1);
        assert_eq!(
            stats.vanished_events, 2,
            "the note and the vanish request itself (created_at <= until) are removed"
        );
        assert!(visible(&db, serde_json::json!({"ids": [note.id]})).is_empty());
        db.shutdown();
    }

    #[test]
    fn vanish_blocks_later_events_in_the_same_batch() {
        // The export is oldest-first; with a large batch the events after
        // the request used to be committed before the vanish marker was
        // written and stayed visible (the live relay blocks the author
        // permanently).
        let db = test_db("vanish-order");
        let now = unix_now();
        let before = signed(1, 1, now - 10, vec![], "before");
        let vanish = signed(
            1,
            nip62::VANISH_KIND,
            now - 5,
            vec![vec!["relay".into(), "ALL_RELAYS".into()]],
            "",
        );
        let after = signed(1, 1, now - 1, vec![], "after");
        let mut opts = options();
        opts.apply_vanish = true;
        opts.batch = 512;
        let stats = run_str(&db, &jsonl(&[before, vanish, after]), &opts);
        assert_eq!(stats.vanishes, 1);
        assert_eq!(
            stats.invalid, 1,
            "the post-request event must be blocked by the marker"
        );
        assert!(
            visible(&db, serde_json::json!({})).is_empty(),
            "nothing of the vanished author stays visible"
        );
        db.shutdown();
    }

    #[test]
    fn first_seen_records_the_earliest_event() {
        let db = test_db("first-seen");
        let now = unix_now();
        let early = signed(1, 1, now - 100, vec![], "early");
        let late = signed(1, 1, now - 10, vec![], "late");
        let mut opts = options();
        opts.first_seen = true;
        run_str(&db, &jsonl(&[early.clone(), late]), &opts);
        let pk = early.pubkey_bytes().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (created, ts) = rt.block_on(async { db.first_seen_batch(vec![pk]).await })[0];
        assert!(!created, "the author must be recorded");
        assert_eq!(ts, early.created_at, "the earliest event's time wins");
        db.shutdown();
    }

    #[test]
    fn nip09_blocks_an_absent_target_for_its_author() {
        // strfry removes a deleted event physically, so the export carries
        // only the deletion request. The migration must still record the
        // re-publication block, or the deleted event could come back.
        let db = test_db("nip09-absent");
        let now = unix_now();
        let target = signed(1, 1, now - 10, vec![], "gone");
        let deletion = signed(
            1,
            nip09::DELETION_KIND,
            now - 5,
            vec![vec!["e".into(), target.id.clone()]],
            "",
        );
        let stats = run_str(&db, &jsonl(&[deletion]), &options());
        assert_eq!(stats.deletions_applied, 1);
        assert_eq!(
            stats.deletion_blocks, 1,
            "the absent target must be blocked"
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let outcome = rt.block_on(db.put(target, unix_now()));
        assert!(
            matches!(outcome, PutOutcome::PreviouslyDeleted),
            "the author's re-publication must be rejected, got {outcome:?}"
        );
        db.shutdown();
    }

    #[test]
    fn a_scoped_block_does_not_censor_another_author() {
        // A deletion request naming someone else's event must not block
        // that author: the recorded block is scoped to the deletion's
        // author, exactly like strfry's `(id, pubkey)` deletion record.
        let db = test_db("nip09-scope");
        let now = unix_now();
        let victim = signed(2, 1, now - 10, vec![], "victim");
        let deletion = signed(
            1,
            nip09::DELETION_KIND,
            now - 5,
            vec![vec!["e".into(), victim.id.clone()]],
            "",
        );
        let stats = run_str(&db, &jsonl(&[deletion]), &options());
        assert_eq!(stats.deletion_blocks, 1);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let outcome = rt.block_on(db.put(victim.clone(), unix_now()));
        assert!(
            matches!(outcome, PutOutcome::Stored),
            "another author's event must not be blocked, got {outcome:?}"
        );
        assert_eq!(
            visible(&db, serde_json::json!({"ids": [victim.id]})).len(),
            1,
            "a scoped block must not hide another author's event"
        );
        db.shutdown();
    }

    #[test]
    fn multiple_deleters_of_an_absent_target_are_all_recorded() {
        // The first deletion request naming an absent id may not be the
        // author's (a third party can e-tag any id); a later request by the
        // real author must extend the scoped block, or the author's
        // re-publication would slip through.
        let db = test_db("nip09-multi");
        let now = unix_now();
        let target = signed(2, 1, now - 10, vec![], "gone");
        let third_party = signed(
            1,
            nip09::DELETION_KIND,
            now - 5,
            vec![vec!["e".into(), target.id.clone()]],
            "",
        );
        let author = signed(
            2,
            nip09::DELETION_KIND,
            now - 4,
            vec![vec!["e".into(), target.id.clone()]],
            "",
        );
        let stats = run_str(&db, &jsonl(&[third_party, author]), &options());
        assert_eq!(stats.deletion_blocks, 2, "both deleters are recorded");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let outcome = rt.block_on(db.put(target, unix_now()));
        assert!(
            matches!(outcome, PutOutcome::PreviouslyDeleted),
            "the author's block must be effective, got {outcome:?}"
        );
        db.shutdown();
    }

    #[test]
    fn a_tombstone_overflow_falls_back_to_an_unconditional_block() {
        // More deleters than the scoped list holds: dropping the extra one
        // would fail open when it is the author's own deletion (the target
        // is absent precisely because strfry deleted it on the author's
        // request), so the marker becomes unconditional.
        let db = test_db("nip09-overflow");
        let now = unix_now();
        let target = signed(9, 1, now - 20, vec![], "gone");
        let mut events = Vec::new();
        for seed in 1..=4u8 {
            events.push(signed(
                seed,
                nip09::DELETION_KIND,
                now - 10 + u64::from(seed),
                vec![vec!["e".into(), target.id.clone()]],
                "",
            ));
        }
        events.push(signed(
            9,
            nip09::DELETION_KIND,
            now - 4,
            vec![vec!["e".into(), target.id.clone()]],
            "",
        ));
        let stats = run_str(&db, &jsonl(&events), &options());
        assert_eq!(stats.deletion_blocks, 5);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let outcome = rt.block_on(db.put(target, unix_now()));
        assert!(
            matches!(outcome, PutOutcome::PreviouslyDeleted),
            "the author's block must be effective after the overflow, got {outcome:?}"
        );
        db.shutdown();
    }

    #[test]
    fn seed_replays_same_second_grants_in_rank_order() {
        // A resumed/merged migration seeds its authorization replay from the
        // stored moderation events. The replay must order them like the
        // startup rebuild (create before a same-second grant), or the grant
        // is dropped and a legitimate 9005 by the granted admin is skipped.
        let db = test_db("seed-rank-order");
        let now = unix_now();
        let create = signed(1, 9007, now - 40, vec![vec!["h".into(), "g".into()]], "");
        let grant = signed(
            1,
            9000,
            now - 40,
            vec![
                vec!["h".into(), "g".into()],
                vec![
                    "p".into(),
                    keypair(2).x_only_public_key().0.to_string(),
                    "admin".into(),
                ],
            ],
            "",
        );
        let post = signed(1, 9, now - 30, vec![vec!["h".into(), "g".into()]], "post");
        let stats = run_str(&db, &jsonl(&[create, grant, post.clone()]), &options());
        assert_eq!(stats.unauthorized_moderation, 0);

        // The second run authorizes the new admin's 9005 from the stored
        // create+grant (same second).
        let delete = signed(
            2,
            9005,
            now - 20,
            vec![
                vec!["h".into(), "g".into()],
                vec!["e".into(), post.id.clone()],
            ],
            "",
        );
        let stats = run_str(&db, &jsonl(&[delete]), &options());
        assert_eq!(stats.group_deletions, 1, "the seeded admin is authorized");
        assert!(visible(&db, serde_json::json!({"ids": [post.id]})).is_empty());
        db.shutdown();
    }

    #[test]
    fn a_same_second_delete_before_create_is_applied_in_rank_order() {
        // strfry's export orders same-second events by id, so a delete can
        // precede its group's create. The startup rebuild ranks the create
        // first and applies the delete; the migration's deferred pass uses
        // the same order and purges up to the delete's timestamp, so the
        // first restart does not change the state.
        let db = test_db("rank-order-purge");
        let now = unix_now();
        let delete = signed(1, 9008, now - 30, vec![vec!["h".into(), "g".into()]], "");
        let create = signed(1, 9007, now - 30, vec![vec!["h".into(), "g".into()]], "");
        let post = signed(1, 9, now - 30, vec![vec!["h".into(), "g".into()]], "post");
        let recreate = signed(1, 9007, now - 20, vec![vec!["h".into(), "g".into()]], "");
        let new_post = signed(1, 9, now - 10, vec![vec!["h".into(), "g".into()]], "new");
        let stats = run_str(
            &db,
            &jsonl(&[
                delete.clone(),
                create.clone(),
                post.clone(),
                recreate.clone(),
                new_post.clone(),
            ]),
            &options(),
        );
        assert_eq!(
            stats.group_purges, 1,
            "the rank replay authorizes the delete"
        );
        assert_eq!(stats.unauthorized_moderation, 0);
        assert!(visible(&db, serde_json::json!({"ids": [delete.id]})).is_empty());
        assert!(
            visible(&db, serde_json::json!({"ids": [post.id]})).is_empty(),
            "history up to the delete's timestamp is purged"
        );
        assert_eq!(
            visible(&db, serde_json::json!({"ids": [recreate.id]})).len(),
            1,
            "a later re-create survives the bounded purge"
        );
        assert_eq!(
            visible(&db, serde_json::json!({"ids": [new_post.id]})).len(),
            1
        );
        // A re-run must not resurrect the purged create: the marker
        // records its id, which the same-second re-create exception would
        // otherwise let back in.
        let stats = run_str(
            &db,
            &jsonl(&[delete, create, post, recreate.clone(), new_post.clone()]),
            &options(),
        );
        assert_eq!(stats.group_purges, 0, "the purge was already applied");
        assert_eq!(
            visible(&db, serde_json::json!({"ids": [recreate.id]})).len(),
            1,
            "a legitimate later re-create still passes"
        );
        db.shutdown();
    }

    #[test]
    fn a_deletion_from_an_earlier_run_still_purges_later_wraps() {
        // The wrap purge is replayed from the stored deletion requests, so
        // a resumed run (`--since`) purges the wraps of requests imported
        // by an earlier run instead of losing them with the in-memory queue.
        let db = test_db("wrap-resume");
        let now = unix_now();
        let recipient = keypair(1).x_only_public_key().0.to_string();
        let deletion = signed(1, nip09::DELETION_KIND, now - 5, vec![], "");
        run_str(&db, &jsonl(&[deletion]), &options());
        let wrap = signed(
            2,
            nip62::GIFT_WRAP_KIND,
            now - 10,
            vec![vec!["p".into(), recipient]],
            "",
        );
        let stats = run_str(&db, &jsonl(std::slice::from_ref(&wrap)), &options());
        assert_eq!(stats.gift_wrap_purges, 1, "the stored request is replayed");
        assert!(visible(&db, serde_json::json!({"ids": [wrap.id]})).is_empty());
        db.shutdown();
    }

    #[test]
    fn a_deletion_that_changes_admin_state_is_reconciled() {
        // A 9005 that removes an admin-removal event changes the state the
        // later actions are authorized against: the pass must reconcile to
        // the state the restart rebuilds, or a 9008 the restart applies
        // would be skipped (fail-open).
        let db = test_db("fixpoint");
        let now = unix_now();
        let b_pk = keypair(2).x_only_public_key().0.to_string();
        let create = signed(1, 9007, now - 40, vec![vec!["h".into(), "g".into()]], "");
        let post = signed(1, 9, now - 35, vec![vec!["h".into(), "g".into()]], "post");
        let grant = signed(
            1,
            9000,
            now - 30,
            vec![
                vec!["h".into(), "g".into()],
                vec!["p".into(), b_pk.clone(), "admin".into()],
            ],
            "",
        );
        let remove = signed(
            1,
            9001,
            now - 25,
            vec![vec!["h".into(), "g".into()], vec!["p".into(), b_pk.clone()]],
            "",
        );
        let del_remove = signed(
            1,
            9005,
            now - 20,
            vec![
                vec!["h".into(), "g".into()],
                vec!["e".into(), remove.id.clone()],
            ],
            "",
        );
        let purge = signed(2, 9008, now - 10, vec![vec!["h".into(), "g".into()]], "");
        let stats = run_str(
            &db,
            &jsonl(&[create, post, grant, remove, del_remove, purge]),
            &options(),
        );
        assert_eq!(stats.group_deletions, 1);
        assert_eq!(
            stats.group_purges, 1,
            "the 9008 is authorized once the 9001 it depended on is deleted"
        );
        db.shutdown();
    }

    #[test]
    fn a_wrap_imported_after_the_deletion_survives() {
        // The live relay purges only the wraps stored when the request
        // arrives; a wrap imported later must survive regardless of the
        // batch size. The purge is deferred, so a same-second wrap is
        // deterministic too.
        for batch in [1usize, 512] {
            let db = test_db("wrap-order");
            let now = unix_now();
            let recipient = keypair(1).x_only_public_key().0.to_string();
            let deletion = signed(1, nip09::DELETION_KIND, now - 10, vec![], "");
            let later = signed(
                2,
                nip62::GIFT_WRAP_KIND,
                now - 5,
                vec![vec!["p".into(), recipient.clone()]],
                "",
            );
            let same_second = signed(
                3,
                nip62::GIFT_WRAP_KIND,
                now - 10,
                vec![vec!["p".into(), recipient]],
                "",
            );
            let stats = run_str(
                &db,
                &jsonl(&[deletion, same_second.clone(), later.clone()]),
                &Options { batch, ..options() },
            );
            assert_eq!(stats.gift_wrap_purges, 1, "batch {batch}");
            assert_eq!(
                visible(&db, serde_json::json!({"ids": [later.id]})).len(),
                1,
                "a later wrap survives (batch {batch})"
            );
            assert!(
                visible(&db, serde_json::json!({"ids": [same_second.id]})).is_empty(),
                "a same-second wrap is purged deterministically (batch {batch})"
            );
            db.shutdown();
        }
    }

    #[test]
    fn a_historical_purge_does_not_remove_newer_stored_events() {
        // A merge into an existing database: the re-created group's events
        // were imported by an earlier run, and a later run's historical
        // 9008 must purge only up to its own timestamp (the unbounded walk
        // used to remove them and raise the cut past them).
        let db = test_db("historical-purge");
        let now = unix_now();
        let recreate = signed(1, 9007, now - 10, vec![vec!["h".into(), "g".into()]], "");
        let new_post = signed(1, 9, now - 5, vec![vec!["h".into(), "g".into()]], "new");
        run_str(&db, &jsonl(&[recreate, new_post.clone()]), &options());
        let create = signed(1, 9007, now - 30, vec![vec!["h".into(), "g".into()]], "");
        let old_post = signed(1, 9, now - 20, vec![vec!["h".into(), "g".into()]], "old");
        let delete = signed(1, 9008, now - 15, vec![vec!["h".into(), "g".into()]], "");
        let stats = run_str(&db, &jsonl(&[create, old_post, delete.clone()]), &options());
        assert_eq!(stats.group_purges, 1);
        assert!(visible(&db, serde_json::json!({"ids": [delete.id]})).is_empty());
        assert_eq!(
            visible(&db, serde_json::json!({"ids": [new_post.id]})).len(),
            1,
            "the newer re-created post survives the bounded purge"
        );
        db.shutdown();
    }

    #[test]
    fn group_recreate_after_purge_keeps_the_new_posts() {
        // The purge marker's cut must be the 9008's created_at: a group
        // re-created after the deletion has its own, newer events, and the
        // marker must not block them (the live relay compares against the
        // arrival time, which is later than every historical event).
        let db = test_db("group-recreate");
        let now = unix_now();
        let create = signed(1, 9007, now - 40, vec![vec!["h".into(), "g".into()]], "");
        let old_post = signed(1, 9, now - 30, vec![vec!["h".into(), "g".into()]], "old");
        let delete = signed(1, 9008, now - 20, vec![vec!["h".into(), "g".into()]], "");
        let recreate = signed(1, 9007, now - 10, vec![vec!["h".into(), "g".into()]], "");
        let new_post = signed(1, 9, now - 5, vec![vec!["h".into(), "g".into()]], "new");
        let stats = run_str(
            &db,
            &jsonl(&[create, old_post, delete, recreate, new_post]),
            // A batch large enough to hold the whole input: the 9008 must
            // still be flushed on its own, or the re-created group's events
            // (later in the export) would be purged with the old history.
            &Options {
                batch: 512,
                ..options()
            },
        );
        assert_eq!(stats.group_purges, 1);
        let posts = visible(&db, serde_json::json!({"kinds": [9]}));
        assert_eq!(posts.len(), 1, "only the re-created group's post survives");
        assert_eq!(posts[0].content, "new");
        assert_eq!(
            visible(&db, serde_json::json!({"kinds": [9007]})).len(),
            1,
            "the re-create event itself survives"
        );
        db.shutdown();
    }

    #[test]
    fn fried_exports_migrate() {
        // `strfry export --fried` adds a precomputed `fried` field to each
        // line; the event fields are unchanged and the extra field must be
        // ignored.
        let db = test_db("fried");
        let now = unix_now();
        let event = signed(1, 1, now - 1, vec![], "fried");
        let mut line = serde_json::to_value(&event).unwrap();
        line["fried"] = serde_json::json!("deadbeef");
        let stats = run_str(&db, &format!("{line}\n"), &options());
        assert_eq!(stats.stored, 1);
        assert_eq!(
            visible(&db, serde_json::json!({"ids": [event.id]})).len(),
            1
        );
        db.shutdown();
    }

    #[test]
    fn a_recipients_deletion_blocks_the_gift_wrap() {
        // strfry records a wrap deletion as `(wrap id, recipient)`: the
        // wrap's (random) author differs from the deleter, so the block
        // must match the `p`-tag recipient, not just the author.
        let db = test_db("wrap-block");
        let now = unix_now();
        let recipient = keypair(1).x_only_public_key().0.to_string();
        let wrap = signed(
            2,
            nip62::GIFT_WRAP_KIND,
            now - 10,
            vec![vec!["p".into(), recipient.clone()]],
            "wrap",
        );
        let deletion = signed(
            1,
            nip09::DELETION_KIND,
            now - 5,
            vec![vec!["e".into(), wrap.id.clone()]],
            "",
        );
        // The wrap is absent from the export (strfry deleted it), so only
        // the deletion request is imported.
        let stats = run_str(&db, &jsonl(&[deletion]), &options());
        assert_eq!(stats.deletion_blocks, 1);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let outcome = rt.block_on(db.put(wrap, unix_now()));
        assert!(
            matches!(outcome, PutOutcome::PreviouslyDeleted),
            "the recipient's deletion must block the wrap, got {outcome:?}"
        );
        db.shutdown();
    }

    #[test]
    fn capped_reader_bounds_a_huge_line() {
        let mut input = Vec::new();
        input.extend_from_slice(b"short\n");
        input.extend(std::iter::repeat_n(b'x', 10_000));
        input.push(b'\n');
        input.extend_from_slice(b"after\n");
        let mut reader = std::io::Cursor::new(input);
        let mut line = Vec::new();
        let (n, truncated) = read_line_capped(&mut reader, 16, &mut line).unwrap();
        assert_eq!(n, 6);
        assert!(!truncated);
        assert_eq!(&line, b"short\n");
        // The huge line is consumed whole (the tail discarded) and flagged.
        let (n, truncated) = read_line_capped(&mut reader, 16, &mut line).unwrap();
        assert_eq!(n, 10_001);
        assert!(truncated);
        assert_eq!(line.len(), 16);
        // The next line is unaffected.
        let (_, truncated) = read_line_capped(&mut reader, 16, &mut line).unwrap();
        assert!(!truncated);
        assert_eq!(&line, b"after\n");
        let (n, _) = read_line_capped(&mut reader, 16, &mut line).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn bom_and_non_utf8_lines_are_handled() {
        let db = test_db("bom");
        let now = unix_now();
        let event = signed(1, 1, now - 1, vec![], "bom");
        let mut input = Vec::new();
        input.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        input.extend_from_slice(serde_json::to_string(&event).unwrap().as_bytes());
        input.push(b'\n');
        // An invalid UTF-8 line is counted as malformed, not a hard error.
        input.extend_from_slice(&[0xff, 0xfe, b'\n']);
        input.extend_from_slice(b"not json\n");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let stats = rt.block_on(async {
            run(Some(&db), std::io::Cursor::new(input), &options(), |_| {})
                .await
                .unwrap()
        });
        assert_eq!(stats.stored, 1, "the BOM-prefixed event must import");
        assert_eq!(stats.malformed, 2);
        assert_eq!(
            visible(&db, serde_json::json!({"ids": [event.id]})).len(),
            1
        );
        db.shutdown();
    }

    #[test]
    fn random_input_never_panics_and_accounts_every_line() {
        use crate::fuzz_tests::Rng;
        let mut rng = Rng::new(0x5eed_1234);
        let mut input: Vec<u8> = Vec::new();
        for _ in 0..500 {
            match rng.below(7) {
                0 => input.push(b'\n'),
                1 => input.extend_from_slice(b"   \t \n"),
                2 => {
                    let len = rng.below(300);
                    for _ in 0..len {
                        input.push(rng.next_u64() as u8);
                    }
                    input.push(b'\n');
                }
                3 => input.extend_from_slice(b"{\"kind\":1,\"content\":\"x\"}\n"),
                4 => input.extend_from_slice(b"not json\n"),
                5 => {
                    let len = rng.below(2000);
                    input.extend(std::iter::repeat_n(b'a', len));
                    input.push(b'\n');
                }
                _ => input.extend_from_slice(&[0xEF, 0xBB, 0xBF, b'\n']),
            }
        }
        let opts = options();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let stats = rt.block_on(async {
            run(None, std::io::Cursor::new(input), &opts, |_| {})
                .await
                .expect("random input must not fail")
        });
        assert_eq!(
            stats.lines,
            stats.valid + stats.malformed + stats.oversized,
            "every non-blank line must be accounted exactly once: {stats:?}"
        );
        assert_eq!(stats.imported(), 0, "a dry run stores nothing");
    }

    #[test]
    fn the_line_cap_boundary_is_exact() {
        let db = test_db("line-cap");
        let now = unix_now();
        let event = signed(1, 1, now - 1, vec![], "cap");
        let line = serde_json::to_string(&event).unwrap();
        // A line exactly at the cap is accepted...
        let mut opts = options();
        opts.max_line_bytes = line.len();
        let stats = run_str(&db, &format!("{line}\n"), &opts);
        assert_eq!(stats.stored, 1, "a line at the cap must import");
        // ...and one byte over is rejected as oversized.
        let db2 = test_db("line-cap-over");
        let mut opts = options();
        opts.max_line_bytes = line.len() - 1;
        let stats = run_str(&db2, &format!("{line}\n"), &opts);
        assert_eq!(stats.oversized, 1);
        assert_eq!(stats.stored, 0);
        db.shutdown();
        db2.shutdown();
    }

    #[test]
    fn dry_run_writes_nothing() {
        let now = unix_now();
        let event = signed(1, 1, now - 1, vec![], "dry");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let stats = rt.block_on(async {
            run(
                None,
                std::io::Cursor::new(jsonl(&[event])),
                &options(),
                |_| {},
            )
            .await
            .unwrap()
        });
        assert_eq!(stats.valid, 1);
        assert_eq!(stats.imported(), 0);
    }
}
