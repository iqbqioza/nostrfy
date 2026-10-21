//! Event removal operations: NIP-09 deletions, NIP-86 bans, NIP-62
//! vanish and the NIP-40 expiration purge.

use std::sync::Arc;

use super::db_error;
#[cfg(test)]
use super::store::take_chunk_fault;
use super::store::{
    CREATED_LEN, GIFT_WRAP_INDEX, ID_LEN, StateRemoved, Store, TAG_INDEX_VALUE_MAX, created_key,
    decode_pending_purge, decode_purged_group_marker, delegated_by, deleted_address_key,
    dtag_key_safe, encode_pending_deletion, encode_pending_purge, encode_purged_group_marker,
    pending_deletion_key, pubkey_key, purged_group_key, replaceable_key, replaceable_key_range_end,
    tag_key,
};
use crate::error::Result;
use crate::event::Event;
use crate::nips::nip09;

/// Bounds how many index entries a removal pass materializes at once: a
/// vanished pubkey's full history, every expired id or every version of
/// a deleted addressable event must never pin the writer thread's memory
/// in one `Vec`. The walks below resume just past the last collected key,
/// so entries the caller leaves in place cannot loop forever.
const REMOVAL_CHUNK: usize = 4096;

/// How many deleter pubkeys one absent-target tombstone keeps. Bounds the
/// marker value when many deletion requests name the same missing id.
/// Past the bound the extra deleter is dropped on the live path (keeping
/// the marker scoped) so a handful of keys cannot promote an arbitrary
/// absent id to an unconditional, cross-author block; the migration, which
/// replays operator-controlled history, may still promote (see
/// [`Store::extend_absent_deletion_marker`]).
pub(crate) const SCOPED_TOMBSTONE_MAX: usize = 4;

/// The partial outcome of a chunked removal walk: what was removed before
/// the walk ended, which derived-state families the removed events feed
/// (NIP-29 group state / NIP-43 role state), and the failure that stopped
/// it (if any). The counters stay meaningful when `error` is `Some`: a
/// later chunk that failed must not hide the state events an earlier chunk
/// already removed (the derived state still needs the rebuild), nor the
/// events it already removed.
pub(crate) struct RemovalReport {
    pub removed: usize,
    pub state_removed: StateRemoved,
    pub error: Option<anyhow::Error>,
}

impl RemovalReport {
    /// Whether the walk completed cleanly.
    pub(crate) fn is_clean(&self) -> bool {
        self.error.is_none()
    }

    /// The removed count for a successful walk, `None` on failure: the
    /// checked callers must not report a partial removal as a clean one.
    pub(crate) fn checked_removed(&self) -> Option<usize> {
        self.is_clean().then_some(self.removed)
    }
}

/// Compares two hex pubkeys/ids on decoded bytes (case-insensitive like
/// the scan's hex decode), falling back to exact match when either side
/// is not valid hex.
fn pubkeys_equal(a: &str, b: &str) -> bool {
    match (hex::decode(a), hex::decode(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// One [`REMOVAL_CHUNK`]-sized page of `(index key, event id)` pairs from
/// `db`, resuming inside `bounds`. Iteration errors propagate: a swallowed
/// cursor error used to end the walk early while the caller reported
/// success (and wrote its vanish/purge marker) with the rest of the
/// history still stored. A corrupt short key (bitrot/hand edit) is skipped
/// instead of sliced — `key.len() - ID_LEN` would underflow and panic the
/// writer, silently aborting the removal.
fn removal_chunk(
    db: heed::Database<heed::types::Bytes, heed::types::Bytes>,
    wtxn: &heed::RwTxn,
    bounds: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>),
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut entries = Vec::new();
    for item in db.range(wtxn, &bounds)? {
        let (key, _) = item?;
        if key.len() < ID_LEN {
            log::warn!(
                "skipping corrupt {}-byte index key during removal",
                key.len()
            );
            continue;
        }
        entries.push((key.to_vec(), key[key.len() - ID_LEN..].to_vec()));
        if entries.len() == REMOVAL_CHUNK {
            break;
        }
    }
    Ok(entries)
}

/// Whether a scoped [`DELETED`] marker lists `pubkey` as one of its
/// deleters. An unconditional (empty) or corrupt marker is not scoped and
/// never matches: it already blocks the id outright.
fn scoped_marker_covers(marker: &[u8], pubkey: &[u8]) -> bool {
    !marker.is_empty()
        && marker.len().is_multiple_of(ID_LEN)
        && marker.chunks(ID_LEN).any(|chunk| chunk == pubkey)
}

impl Store {
    /// Records NIP-09 re-publication blocks for deletion targets that are
    /// *absent* from the database, scoped to the deletion's author. The
    /// migration uses this to replay a strfry export: strfry removes deleted
    /// events physically, so the export has no trace of a target its author
    /// deleted and replaying the deletion request cannot write the ordinary
    /// per-id tombstone. The live deletion walk records the same marker for
    /// absent targets (see `apply_deletion_walk`), so a live database and a
    /// migrated one agree. Present targets are left to the walk (which
    /// checks ownership and writes the unconditional tombstone), and ids
    /// that already carry an unconditional tombstone are untouched.
    ///
    /// The value is one or more 32-byte deleter pubkeys (at most
    /// [`SCOPED_TOMBSTONE_MAX`]), so only those authors' re-publication is
    /// blocked — the event id commits to its author, and this mirrors
    /// strfry's `(id, pubkey)` deletion record. A full scoped list drops the
    /// extra deleter instead of promoting to an unconditional tombstone, so
    /// neither live traffic nor migrated history can censor an arbitrary
    /// absent id (M-3).
    /// Returns how many absent targets carry a re-publication block after
    /// the pass (the live deletion walk records the same scoped marker while
    /// replaying the request, so this pass is then usually a no-op).
    pub(crate) fn record_absent_deletion_targets(
        &self,
        pubkey: &[u8],
        targets: &[String],
    ) -> Result<usize> {
        self.disk_full_error()?;
        if pubkey.len() != ID_LEN {
            return Ok(0);
        }
        let mut wtxn = self.env.write_txn()?;
        let mut recorded = 0usize;
        for target in targets {
            let Ok(id) = hex::decode(target) else {
                continue;
            };
            if id.len() != ID_LEN {
                continue;
            }
            if self.events.get(&wtxn, &id)?.is_some() {
                // Present: the deletion walk decides by ownership.
                continue;
            }
            // Record the marker — the live deletion walk recorded the same
            // one while replaying the request, so this is usually a no-op —
            // and count the target: either way the block is in place.
            self.extend_absent_deletion_marker(&mut wtxn, &id, pubkey)?;
            recorded += 1;
        }
        wtxn.commit()?;
        Ok(recorded)
    }

    /// Extends the [`DELETED`] marker of a deletion target with one deleter
    /// pubkey, creating the marker when none exists: the scoped
    /// re-publication block shared by the live deletion walk,
    /// [`Self::record_absent_deletion_targets`] and
    /// [`Self::remove_gift_wraps_for`] (a wrap's marker scopes to the
    /// recipient, which `deletion_marker_blocks` matches by `p` tag). An
    /// unconditional (empty) or corrupt marker already blocks the id and is
    /// left as is; a scoped marker gains the deleter unless it is already
    /// covered.
    ///
    /// When the scoped list is full the extra deleter is dropped, even for
    /// migration: promoting it to an unconditional tombstone would let
    /// `SCOPED_TOMBSTONE_MAX + 1` keys censor any absent event id
    /// regardless of its author (M-3). The price is that the extra deleter's
    /// own re-publication is not blocked, which fails open only for that
    /// deleter.
    fn extend_absent_deletion_marker(
        &self,
        wtxn: &mut heed::RwTxn,
        id: &[u8],
        pubkey: &[u8],
    ) -> Result<()> {
        match self.deleted.get(wtxn, id)? {
            Some(existing) => {
                if existing.is_empty() || !existing.len().is_multiple_of(ID_LEN) {
                    // An unconditional or corrupt marker already blocks the
                    // id: nothing to add.
                    return Ok(());
                }
                if scoped_marker_covers(existing, pubkey) {
                    return Ok(());
                }
                if existing.len() >= ID_LEN * SCOPED_TOMBSTONE_MAX {
                    // Keep the block scoped. An unconditional marker here
                    // would let SCOPED_TOMBSTONE_MAX + 1 keys censor any
                    // absent event id regardless of its author. Debug, not
                    // warn: a client can trigger this with many deleters, so
                    // a warn would be a log-flood vector.
                    log::debug!(
                        "deletion target {} already has {SCOPED_TOMBSTONE_MAX} \
                         deleters; keeping the re-publication block scoped",
                        hex::encode(id)
                    );
                    return Ok(());
                }
                let mut merged = existing.to_vec();
                merged.extend_from_slice(pubkey);
                self.deleted.put(wtxn, id, &merged)?;
                Ok(())
            }
            None => {
                self.deleted.put(wtxn, id, pubkey)?;
                Ok(())
            }
        }
    }

    /// NIP-59: deletes every stored `kind:1059` event addressed to `pubkey`.
    ///
    /// Walks the reserved [`GIFT_WRAP_INDEX`] namespace — one narrow range
    /// keyed by the decoded pubkey — instead of the whole `p` tag namespace.
    /// The visible tag index stores values verbatim, so the previous
    /// implementation had to scan every `p` entry (the store's most expensive
    /// deletion path, reachable from any NIP-09 deletion request) just to
    /// catch hex case variants.
    fn remove_gift_wraps_for(&self, pubkey: &[u8], until: u64, removed: &mut usize) -> Result<()> {
        // The recipient index is backfilled once at startup; when its
        // marker is missing (the rebuild failed or never ran) the range
        // walk below would silently miss every pre-index wrap. Refuse
        // loudly instead: the vanish caller then skips its marker (so a
        // re-delivered request retries the wraps) and the NIP-09 caller
        // reports the deletion as failed.
        if self.gift_wrap_index_needs_rebuild()? {
            return Err(anyhow::anyhow!("gift-wrap recipient index is not built"));
        }
        let start = tag_key(GIFT_WRAP_INDEX, pubkey, 0, &[0u8; ID_LEN]);
        let end = crate::db::store::range_end(
            tag_key(
                GIFT_WRAP_INDEX,
                pubkey,
                until.saturating_add(1),
                &[0u8; ID_LEN],
            ),
            until,
        );
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            if self.cancelled() {
                // A SIGTERM mid-walk stops at the chunk boundary like every
                // other removal walk: the vanish caller keeps its pending
                // record and resumes at the next startup (fail-closed).
                return Err(anyhow::anyhow!(
                    "gift-wrap removal cancelled during shutdown"
                ));
            }
            // A fresh write transaction per chunk: one pubkey's wrap index
            // can hold an unbounded number of entries, and a single
            // transaction across the whole walk pinned the writer (a
            // MapFull also aborted the entire purge instead of one chunk).
            let mut wtxn = self.env.write_txn()?;
            let lower = match &last_key {
                Some(key) => std::ops::Bound::Excluded(key.as_slice()),
                None => std::ops::Bound::Included(start.as_slice()),
            };
            let entries = removal_chunk(
                self.by_tag,
                &wtxn,
                (lower, std::ops::Bound::Excluded(end.as_slice())),
            )?;
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().expect("non-empty chunk").0.clone());
            for (key, id) in entries {
                if self.events.get(&wtxn, &id)?.is_none() {
                    // A dangling index entry (the event is already gone):
                    // drop it so later deletions do not keep revisiting it.
                    self.by_tag.delete(&mut wtxn, &key)?;
                    continue;
                }
                // The index is only written for kind:1059 events, so the
                // entry cannot point at any other kind.
                //
                // Record the recipient-scoped re-publication block before
                // removing: a wrap's author is a random key, so the
                // author-scoped marker the `e`-tag walk writes would never
                // match it (`deletion_marker_blocks` matches gift wraps by
                // their `p`-tag recipients). Without it a re-broadcast of
                // the same wrap is stored again and undoes the recipient's
                // deletion; the migration records the same marker, so live
                // and migrated databases agree.
                self.extend_absent_deletion_marker(&mut wtxn, &id, pubkey)?;
                self.remove_event(&mut wtxn, &id)?;
                *removed += 1;
            }
            wtxn.commit()?;
        }
        Ok(())
    }

    /// Applies a deletion request.
    ///
    /// `request_pubkey` is the hex pubkey of the deletion event: only events
    /// authored by the same pubkey are removed (NIP-09). Deletion requests
    /// themselves are never removed. `request_created` bounds only the
    /// `addresses` (NIP-09's created_at cut applies to `a`/addressable
    /// targets); `e` targets are removed regardless of their timestamp.
    /// Like [`Self::apply_deletion_group`] with no group scope (NIP-09).
    pub(crate) fn apply_deletion_group(
        &self,
        targets: &[String],
        addresses: &[nip09::Address],
        request_pubkey: Option<&str>,
        request_created: u64,
        group: Option<&str>,
        purge_wraps: bool,
    ) -> RemovalReport {
        let mut removed = 0usize;
        let mut state_removed = StateRemoved::default();
        let error = self
            .apply_deletion_walk(
                targets,
                addresses,
                request_pubkey,
                request_created,
                group,
                purge_wraps,
                &mut removed,
                &mut state_removed,
            )
            .err();
        RemovalReport {
            removed,
            state_removed,
            error,
        }
    }

    /// The chunked walk behind [`Self::apply_deletion_group`]. Records the
    /// request in [`DELETE_PENDING`] before the first removal chunk and
    /// clears it only after every chunk committed: an error mid-walk (or a
    /// shutdown cancellation) leaves the record for the startup resume. The
    /// out-parameters carry the partial counters to the caller's report.
    #[allow(clippy::too_many_arguments)]
    fn apply_deletion_walk(
        &self,
        targets: &[String],
        addresses: &[nip09::Address],
        request_pubkey: Option<&str>,
        request_created: u64,
        group: Option<&str>,
        purge_wraps: bool,
        removed: &mut usize,
        state_removed: &mut StateRemoved,
    ) -> Result<()> {
        // Disk-full guard: a removal still writes (the deleted marker),
        // so the same free-space margin as the put path applies.
        self.disk_full_error()?;
        // Fail closed: a deletion must be scoped to a requester (author /
        // delegator) or to a group. The old signature allowed both to be
        // `None`, which skipped every authorization check and would delete
        // arbitrary events if a future caller passed neither.
        if request_pubkey.is_none() && group.is_none() {
            return Ok(());
        }
        // Record the request before the first removal chunk. A request with
        // only a wrap purge is a chunked walk too (it can hit a cancellation
        // or a store error), so it must leave the pending record like the
        // `e`/`a` walks; a request with nothing at all to walk writes none.
        let pending_encoded = encode_pending_deletion(
            targets,
            addresses,
            request_pubkey,
            request_created,
            group,
            purge_wraps,
        );
        let pending_key = pending_deletion_key(&pending_encoded);
        let has_work = !targets.is_empty() || !addresses.is_empty() || purge_wraps;
        if has_work {
            self.put_pending_deletion(&pending_key, &pending_encoded)?;
        }

        // The `e`-tag targets are bounded by the deletion request's own tag
        // list, but the batch is still split into REMOVAL_CHUNK-sized write
        // transactions so a huge request never pins one commit.
        for chunk in targets.chunks(REMOVAL_CHUNK) {
            if self.cancelled() {
                // A SIGTERM mid-walk stops at the chunk boundary: the
                // pending record stays and the next startup resumes the
                // walk (fail-closed). Reporting the partial removal here
                // is not needed — the record is the durable statement.
                return Err(anyhow::anyhow!(
                    "NIP-09 deletion cancelled during shutdown; resuming at next startup"
                ));
            }
            #[cfg(test)]
            if take_chunk_fault(&self.fail_chunk_after) {
                return Err(anyhow::anyhow!("test-only removal chunk failure"));
            }
            let mut wtxn = self.env.write_txn()?;
            let mut chunk_state_removed = StateRemoved::default();
            for target in chunk {
                let Ok(id) = hex::decode(target) else {
                    continue;
                };
                if id.len() != ID_LEN {
                    continue;
                }
                let Some(raw) = self.events.get(&wtxn, &id)? else {
                    // The target is not held: ownership cannot be checked, so
                    // no unconditional tombstone may be written. Record the
                    // author-scoped re-publication block instead — the same
                    // marker the migration writes — so the deleted event is
                    // still refused when it reaches this relay later (B-9:
                    // live and migrated databases must agree). The event id
                    // commits to its author, so the block is exact and a
                    // malicious deleter cannot suppress another author's
                    // event; a delegated deletion scopes to the delegator,
                    // exactly like the migration. Group-scoped moderation
                    // (9005) is excluded: its targets belong to other authors,
                    // so an admin-scoped marker would be inert, and an admin
                    // must not block a member's future event by id.
                    if group.is_none()
                        && let Some(pubkey) = request_pubkey
                        && let Ok(pubkey) = hex::decode(pubkey)
                        && pubkey.len() == ID_LEN
                    {
                        self.extend_absent_deletion_marker(&mut wtxn, &id, &pubkey)?;
                    }
                    continue;
                };
                let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                    continue;
                };
                // NIP-09: only events authored by the request's pubkey are
                // deleted, and deletion requests cannot be deleted. NIP-26:
                // the delegator may also delete events published on their
                // behalf; delegated_by revalidates the target's delegation
                // signature and conditions before allowing that exception.
                if event.kind == nip09::DELETION_KIND {
                    continue;
                }
                // NIP-09's created_at cut applies to `a` (addressable)
                // targets only: an `e` target is deleted regardless of its
                // timestamp. The relay accepts events up to 3600 s in the
                // future, so applying the cut here made a clock-skewed post
                // undeletable while its deletion was acknowledged.
                if let Some(pubkey) = request_pubkey
                    && !pubkeys_equal(&event.pubkey, pubkey)
                    && !delegated_by(&event, pubkey)
                {
                    continue;
                }
                // NIP-29 9005 moderation: restrict to events of the admin's own
                // group, so a group admin cannot delete another group's content
                // (or the relay's metadata) by referencing its id.
                if let Some(gid) = group
                    && crate::nips::nip29::group_id_any(&event)
                        .map(str::to_string)
                        .as_deref()
                        != Some(gid)
                {
                    continue;
                }
                // NIP-29's relay-signed metadata (39000-39005) is managed by
                // the relay: a group admin's 9005 must not delete it even
                // within their own group (the group check above would pass for
                // its own gid).
                if group.is_some()
                    && (crate::nips::nip29::GROUP_META..=crate::nips::nip29::GROUP_PINS)
                        .contains(&event.kind)
                {
                    continue;
                }
                self.deleted.put(&mut wtxn, &id, b"")?;
                // The derived NIP-29/NIP-43 state is built from these kinds
                // (`state_kind_family`): the stamp must advance in the
                // same removal transaction, or a crash after this commit
                // could restore a snapshot that still authorizes the
                // deleted grant. The event's group scopes the stale mark
                // (`None` keeps the whole store in scope).
                chunk_state_removed.observe(event.kind, crate::nips::nip29::group_id_any(&event));
                self.remove_event(&mut wtxn, &id)?;
                *removed += 1;
            }
            if !chunk_state_removed.is_empty() {
                self.bump_state_stamp(&mut wtxn)?;
            }
            wtxn.commit()?;
            state_removed.merge(chunk_state_removed);
            // Test-only: fail after the chunk committed, so the resume
            // path runs over a genuinely partial walk.
            #[cfg(test)]
            if self
                .fail_next_delete_chunk
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(anyhow::anyhow!("test-only delete chunk failure"));
            }
        }

        // NIP-09 `a` tags: remove every version of the referenced
        // addressable events published up to the deletion request. Never
        // scoped to a group: NIP-29 `kind:9005` carries only `e` tags, so a
        // group-scoped request with addresses would delete another group's
        // addressable content without the `e`-tag path's group check above.
        // No caller passes both today; skip the walk (fail closed) if one
        // ever does, but still clear the pending record below.
        let group_scoped_addrs = group.is_some() && !addresses.is_empty();
        if group_scoped_addrs {
            log::warn!("ignoring NIP-09 a-tag targets of a group-scoped deletion request");
        }
        for address in addresses {
            if group_scoped_addrs {
                continue;
            }
            // The author may delete their own address; a NIP-26 delegator
            // may delete versions published on their behalf (checked per
            // version below, mirroring the `e`-tag path). Compare decoded
            // bytes (case-insensitive like the scan's hex decode) so an
            // uppercase `a` value still matches the author.
            let author_owns = request_pubkey.is_none_or(|pubkey| {
                hex::decode(&address.pubkey)
                    .ok()
                    .zip(hex::decode(pubkey).ok())
                    .is_some_and(|(a, b)| a == b)
            });
            let mut delegated_any = false;
            // Whether the delegated address tombstone already rode along in
            // a committed chunk transaction below: crash-safe without waiting
            // for the post-walk merge (which stays as the idempotent
            // backstop). Unmatched delegations never set it, so they still
            // leave no tombstone.
            let mut delegated_tombstoned = false;
            let Ok(pubkey) = hex::decode(&address.pubkey) else {
                continue;
            };
            if pubkey.len() != ID_LEN {
                continue;
            }
            // NIP-09: tombstone the address up to the request's created_at
            // *before* removing the versions, so a later re-publication of
            // an older version cannot resurrect the address even if a crash
            // or a MapFull interrupts the walk (mirrors `purge_group`'s
            // marker-first ordering). The per-id tombstones below only cover
            // the versions that exist right now. Merged with an existing
            // tombstone by keeping the furthest cut.
            let akey = deleted_address_key(address.kind, &pubkey, &address.d);
            if author_owns {
                self.merge_address_tombstone(&akey, request_created)?;
            }
            // Bound the walk on the `dlen` field, not on `kind`: `replaceable_key` is
            // `kind(8) || pubkey(32) || dlen(4) || d`, so an upper bound built
            // from `kind + 1` would leave every slot of the same kind written
            // by a higher pubkey inside the range (LMDB compares keys
            // bytewise) and turn one deletion into a full scan of that kind on
            // the single writer thread.
            let start = replaceable_key(address.kind, &pubkey, "");
            let end = replaceable_key_range_end(address.kind, &pubkey);
            let mut last_key: Option<Vec<u8>> = None;
            loop {
                if self.cancelled() {
                    return Err(anyhow::anyhow!(
                        "NIP-09 deletion cancelled during shutdown; resuming at next startup"
                    ));
                }
                #[cfg(test)]
                if take_chunk_fault(&self.fail_chunk_after) {
                    return Err(anyhow::anyhow!("test-only removal chunk failure"));
                }
                // A fresh write transaction per chunk: one address's version
                // history is unbounded, and a single transaction across it
                // pinned the writer while a MapFull aborted the whole
                // deletion. A replay after a crash re-walks the remaining
                // versions (the removed ones are already gone).
                let mut wtxn = self.env.write_txn()?;
                let lower = match &last_key {
                    Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                    None => std::ops::Bound::Included(start.as_slice()),
                };
                // The slot values (not the keys) carry the removed id, so
                // this walk cannot use `removal_chunk`; iteration errors
                // still propagate so a cursor failure cannot report a
                // partial removal as a clean one.
                let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                for item in self
                    .replaceable
                    .range(&wtxn, &(lower, std::ops::Bound::Excluded(end.as_slice())))?
                {
                    let (k, v) = item?;
                    entries.push((k.to_vec(), v.to_vec()));
                    if entries.len() == REMOVAL_CHUNK {
                        break;
                    }
                }
                if entries.is_empty() {
                    break;
                }
                #[cfg(test)]
                self.removal_scanned
                    .fetch_add(entries.len() as u64, std::sync::atomic::Ordering::SeqCst);
                last_key = Some(entries.last().unwrap().0.clone());
                let mut chunk_state_removed = StateRemoved::default();
                for (key, value) in entries {
                    // key = kind(8) + pubkey(32) + dlen(4) + d
                    if key.len() < CREATED_LEN + ID_LEN + 4 {
                        continue;
                    }
                    if key[CREATED_LEN..CREATED_LEN + ID_LEN] != pubkey {
                        continue;
                    }
                    let dlen = u32::from_be_bytes(
                        key[CREATED_LEN + ID_LEN..CREATED_LEN + ID_LEN + 4]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    if key.len() != CREATED_LEN + ID_LEN + 4 + dlen {
                        continue;
                    }
                    let d = &key[CREATED_LEN + ID_LEN + 4..];
                    // The stored slot key truncates over-long `d` tags (see
                    // `dtag_key_safe`), so compare against the truncated form.
                    if d != dtag_key_safe(&address.d).as_bytes() {
                        continue;
                    }
                    if value.len() < CREATED_LEN + ID_LEN {
                        continue;
                    }
                    let created = u64::from_be_bytes(value[..CREATED_LEN].try_into().unwrap());
                    if created > request_created {
                        continue;
                    }
                    let id = &value[CREATED_LEN..CREATED_LEN + ID_LEN];
                    if !author_owns {
                        let requester = request_pubkey.expect("not author_owns implies Some");
                        let delegated = self
                            .events
                            .get(&wtxn, id)?
                            .and_then(|raw| serde_json::from_slice::<Event>(raw).ok())
                            .is_some_and(|event| delegated_by(&event, requester));
                        if !delegated {
                            continue;
                        }
                        delegated_any = true;
                        // Commit the address guard atomically with its first
                        // removal: a crash after this chunk commits leaves the
                        // tombstone behind, so the resume (finding zero
                        // versions) no longer loses the guard and old
                        // versions stay blocked. Same cut as the post-walk
                        // merge, which stays idempotent.
                        if !delegated_tombstoned {
                            self.merge_address_tombstone_in(&mut wtxn, &akey, request_created)?;
                            delegated_tombstoned = true;
                        }
                    }
                    self.deleted.put(&mut wtxn, id, b"")?;
                    // Every slot under this range is keyed by `address.kind`
                    // (the walk only filters pubkey/d), so its kind decides
                    // whether the derived state must be invalidated. Bumped
                    // in the same transaction as the removal (see the
                    // `e`-tag path). An address names a kind, not an event,
                    // so the group cannot be resolved: `None` keeps the
                    // whole store in scope.
                    chunk_state_removed.observe(address.kind, None);
                    self.remove_event(&mut wtxn, id)?;
                    *removed += 1;
                }
                if !chunk_state_removed.is_empty() {
                    self.bump_state_stamp(&mut wtxn)?;
                }
                wtxn.commit()?;
                state_removed.merge(chunk_state_removed);
                // See the `e`-tag walk: fail after a committed chunk so the
                // resume runs over a partial removal.
                #[cfg(test)]
                if self
                    .fail_next_delete_chunk
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(anyhow::anyhow!("test-only delete chunk failure"));
                }
            }
            // A delegated requester may only tombstone when a version
            // actually matched (the walk above authorizes each version): an
            // unmatched delegation must not leave a tombstone that blocks
            // the author's future publications up to the cut. Author-owned
            // addresses were already tombstoned before the walk.
            if !author_owns && delegated_any {
                self.merge_address_tombstone(&akey, request_created)?;
            }
        }

        // NIP-59: the deletion walk also revokes the gift wraps addressed
        // to the requester. This runs inside the same resumable unit as the
        // walk, so a failure here propagates like a walk failure and the
        // deletion's pending record (recorded above) is NOT cleared — the
        // startup resume re-attempts the whole walk, purge included. This
        // is why the purge lives here and not only at the event handler.
        // `request_pubkey` is the deleter's own hex key, and a 9005 group
        // delete passes `None`, so moderated deletes never touch another
        // user's wraps (matching the handler's previous behaviour).
        //
        // `purge_wraps` is true only for the live NIP-09 path. The
        // migration passes false and owns the bounded purge separately
        // (it must not remove wraps imported after the request's own
        // timestamp); a 9005 group delete has `request_pubkey == None`.
        if purge_wraps
            && let Some(pk) = request_pubkey
            && let Ok(bytes) = hex::decode(pk)
            && bytes.len() == ID_LEN
        {
            self.remove_gift_wraps_for(&bytes, u64::MAX, removed)?;
        }

        // The whole walk committed cleanly: the request no longer needs a
        // resume record. A failed clear leaves the record, and the next
        // startup replays the (idempotent) walk.
        if has_work {
            self.clear_pending_deletion(&pending_key)?;
        }
        Ok(())
    }

    /// Merges the NIP-09 `a`-tag tombstone at `akey` with the request's
    /// `cut`, keeping the furthest cut, into the given transaction (no
    /// commit): lets a chunk commit removals and their re-publication guard
    /// atomically (see the delegated path in `apply_deletion_walk`).
    fn merge_address_tombstone_in(
        &self,
        wtxn: &mut heed::RwTxn,
        akey: &[u8],
        cut: u64,
    ) -> Result<()> {
        let merged = match self.deleted.get(wtxn, akey)? {
            Some(old) if old.len() >= CREATED_LEN => {
                cut.max(u64::from_be_bytes(old[..CREATED_LEN].try_into().unwrap()))
            }
            _ => cut,
        };
        self.deleted.put(wtxn, akey, &merged.to_be_bytes())?;
        Ok(())
    }

    /// Merges the NIP-09 `a`-tag tombstone at `akey` with the request's
    /// `cut`, keeping the furthest cut, and commits it. A tombstone written
    /// before the versions are removed keeps a crash or MapFull mid-walk
    /// from leaving the removals without their re-publication guard.
    fn merge_address_tombstone(&self, akey: &[u8], cut: u64) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.merge_address_tombstone_in(&mut wtxn, akey, cut)?;
        wtxn.commit()?;
        Ok(())
    }

    /// NIP-86 banevent: marks the event as banned, removes it from storage
    /// and rejects future re-publication. Like every other removal path, a
    /// removed NIP-29/NIP-43 state event advances the derived-state stamp
    /// in the same transaction (otherwise a restart restores the banned
    /// grant from a still-current snapshot), and reports it so the caller
    /// rebuilds the live derived state.
    pub(crate) fn apply_ban(&self, id: &[u8], reason: &str) -> Result<(bool, StateRemoved)> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        self.banned.put(&mut wtxn, id, reason.as_bytes())?;
        // NIP-86: a ban removes the event from the allow list, in the
        // same transaction so the two markers can never disagree.
        self.allowed.delete(&mut wtxn, id)?;
        let mut state_removed = StateRemoved::default();
        let removed = match self.events.get(&wtxn, id)? {
            Some(raw) => {
                // Classify before removing: only a stored NIP-29/NIP-43
                // state event invalidates the derived state (an event that
                // fails to parse is still removed, but, like the e-tag
                // path, cannot be classified as state).
                if let Ok(event) = serde_json::from_slice::<Event>(raw) {
                    let gid = crate::nips::nip29::group_id_any(&event);
                    state_removed.observe(event.kind, gid);
                }
                self.remove_event(&mut wtxn, id)?;
                if !state_removed.is_empty() {
                    self.bump_state_stamp(&mut wtxn)?;
                }
                true
            }
            None => false,
        };
        wtxn.commit()?;
        Ok((removed, state_removed))
    }

    pub(crate) fn apply_unban(&self, id: &[u8]) -> Result<bool> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        let removed = self.banned.delete(&mut wtxn, id)?;
        wtxn.commit()?;
        Ok(removed)
    }

    /// NIP-86 allowevent: records the event on the allow list and removes
    /// it from the ban list in the same transaction (the spec's mutual
    /// exclusion). Allowing re-enables future publication of the id; it
    /// does not restore an already-removed event. Beyond the ban/allow
    /// coupling the marker carries no enforcement — the relay defines no
    /// allow-gated read path, and none is invented here.
    pub(crate) fn apply_allow(&self, id: &[u8], reason: &str) -> Result<bool> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        self.allowed.put(&mut wtxn, id, reason.as_bytes())?;
        let unbanned = self.banned.delete(&mut wtxn, id)?;
        wtxn.commit()?;
        Ok(unbanned)
    }

    /// NIP-86 unallowevent: removes the event from the allow list.
    /// Returns whether a marker existed (a missing marker is a no-op
    /// success at the RPC layer).
    pub(crate) fn apply_unallow(&self, id: &[u8]) -> Result<bool> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        let removed = self.allowed.delete(&mut wtxn, id)?;
        wtxn.commit()?;
        Ok(removed)
    }

    /// NIP-86 listallowedevents: allowed event ids with reasons.
    pub(crate) fn list_allowed(&self) -> Result<Vec<(String, String)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.allowed.iter(&rtxn)? {
            let (id, reason) = item?;
            out.push((
                hex::encode(id),
                String::from_utf8_lossy(reason).into_owned(),
            ));
        }
        Ok(out)
    }

    pub(crate) fn list_banned(&self) -> Result<Vec<(String, String)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.banned.iter(&rtxn)? {
            let (id, reason) = item?;
            out.push((
                hex::encode(id),
                String::from_utf8_lossy(reason).into_owned(),
            ));
        }
        Ok(out)
    }
    /// NIP-29: deletes every stored event tagged with the deleted group
    /// `gid` (the `h` tag). A fresh create on the same id installs a public
    /// group, so without the purge the old (possibly private) history would
    /// suddenly be served under the new settings.
    ///
    /// `now` is the purge time recorded in [`PURGED_GROUPS`]: `h`-tagged
    /// re-publications with `created_at <= cut` are rejected at the put
    /// path, so the purged history cannot re-enter the database after a
    /// re-create, and a `kind:9007` re-create is rejected only while its
    /// `created_at` is before `now`. One marker covers the whole group (a
    /// create/purge cycle no longer writes a tombstone per purged event,
    /// which grew the database by the group's whole history). The marker is
    /// written and committed *first*: a put queued behind the purge sees it,
    /// and a crash mid-purge leaves the (fail-closed) cut rather than a
    /// window where re-published events are accepted.
    ///
    /// The same commit records the purge in [`PURGE_PENDING`]: a crash or
    /// `MapFull` after the marker but before the walk completes would
    /// otherwise leave a ghosted group whose marker rejects every event —
    /// including a re-issued `kind:9008` — while the old history stays
    /// stored. [`Self::pending_purges`] reports the record so the caller
    /// re-issues the purge, which is idempotent and keeps the furthest cut.
    /// The completion commit folds the newest removed timestamp into the
    /// cut, clears the in-progress record and bumps the derived-state stamp.
    #[cfg(test)]
    pub(crate) fn purge_group(&self, gid: &str, now: u64) -> Result<usize> {
        self.purge_group_until(gid, now, u64::MAX)
    }

    /// [`Self::purge_group`] bounded to events with `created_at <= until`.
    /// The migration uses it with the `9008`'s own timestamp so a group
    /// re-created after the deletion keeps its newer events; the live relay
    /// passes `u64::MAX` (it removes every stored `h`-tagged event,
    /// including future-dated re-publications, and raises the cut).
    ///
    /// The marker records the id of the purged `kind:9007` create (when one
    /// was removed) so an exact replay of it stays blocked: the re-create
    /// exception (`created_at >= purge_now` passes) would otherwise let a
    /// re-imported original create resurrect the group. A pending record
    /// from an interrupted purge is merged, never narrowed: a crashed live
    /// purge keeps its unbounded recovery, and the create id found so far
    /// survives the resume.
    pub(crate) fn purge_group_until(&self, gid: &str, now: u64, until: u64) -> Result<usize> {
        self.disk_full_error()?;
        let key = purged_group_key(gid);
        // Merge with an earlier purge of the same id: the furthest purge
        // time (for the re-create exception) and the furthest cut cover
        // every already-rejected generation.
        let (mut purge_now, mut cut, mut create_id, effective_until) = {
            let mut wtxn = self.env.write_txn()?;
            let (old_now, old_cut, old_create) = self
                .purged_groups
                .get(&wtxn, &key)?
                .map(decode_purged_group_marker)
                .unwrap_or((0, 0, None));
            // An interrupted purge's record may carry a wider bound (a
            // crashed live purge is unbounded) and the create id found so
            // far: keep both.
            // A present-but-undecodable record fails closed: silently
            // treating it as "no pending" and overwriting it with the
            // caller's bound could narrow an interrupted live purge.
            let pending = match self.purge_pending.get(&wtxn, &key)? {
                Some(raw) => Some(decode_pending_purge(raw).ok_or_else(|| {
                    anyhow::anyhow!("corrupt pending group purge record ({} bytes)", raw.len())
                })?),
                None => None,
            };
            let effective_until = pending
                .as_ref()
                .map(|(_, _, _, pending_until, _)| (*pending_until).max(until))
                .unwrap_or(until);
            // The pending record's cut covers events an interrupted walk
            // already removed (whose timestamps are gone): merging it keeps
            // the marker's cut from regressing on the resume.
            let pending_cut = pending
                .as_ref()
                .map(|(_, _, pending_cut, _, _)| *pending_cut)
                .unwrap_or(0);
            let create_id = pending
                .as_ref()
                .and_then(|(_, _, _, _, create)| *create)
                .or(old_create);
            if effective_until != until {
                log::warn!(
                    "group purge {gid}: an interrupted purge's wider bound                      ({effective_until}) is honoured over the requested {until}"
                );
            }
            let purge_now = old_now.max(now);
            // The initial cut covers `now`; each chunk below raises it to
            // the newest removed event, and the final commit merges it.
            let cut = old_cut.max(pending_cut).max(now);
            self.purged_groups.put(
                &mut wtxn,
                &key,
                &encode_purged_group_marker(purge_now, cut, create_id.as_ref()),
            )?;
            self.purge_pending.put(
                &mut wtxn,
                &key,
                &encode_pending_purge(gid, purge_now, cut, effective_until, create_id.as_ref()),
            )?;
            wtxn.commit()?;
            (purge_now, cut, create_id, effective_until)
        };
        let h_start = tag_key(b'h', gid.as_bytes(), 0, &[0u8; ID_LEN]);
        let h_end = crate::db::store::range_end(
            tag_key(
                b'h',
                gid.as_bytes(),
                effective_until.saturating_add(1),
                &[0u8; ID_LEN],
            ),
            effective_until,
        );
        // The relay-generated metadata events (39000-39005) carry the group
        // id in `d`, not `h` (see `nip29::group_id_any`): without this second
        // range the purge leaves the old member roster and settings behind,
        // and a re-create exposes them under the new public group.
        let d_start = tag_key(b'd', gid.as_bytes(), 0, &[0u8; ID_LEN]);
        let d_end = crate::db::store::range_end(
            tag_key(
                b'd',
                gid.as_bytes(),
                effective_until.saturating_add(1),
                &[0u8; ID_LEN],
            ),
            effective_until,
        );
        // Ids beyond the index key limit are stored but never tag-indexed
        // (the write path skips over-long keys instead of aborting the
        // batch): the tag-index ranges above cannot see them, so the walk
        // falls back to a bounded time-range scan with an in-memory match
        // (`h`, or `d` on a metadata kind), mirroring the query engine's
        // fallback for the same ids.
        let overlong = gid.len() > TAG_INDEX_VALUE_MAX;
        let created_start = created_key(0, &[0u8; ID_LEN]);
        let created_end = created_key(effective_until, &[0xffu8; ID_LEN]);
        // One walk per tag namespace: `h` for user and moderation events,
        // `d` for the relay-generated metadata (39000-39005, which carry no
        // `h` tag). The `d` range also matches ordinary addressable events
        // whose `d` happens to equal the group id, so that phase
        // additionally requires a metadata kind. An over-long id is indexed
        // under neither tag: the single time-range scan below covers both
        // namespaces at once through its in-memory predicate.
        enum PurgePhase {
            ByTag {
                start: Vec<u8>,
                end: Vec<u8>,
                meta_only: bool,
            },
            ByCreated,
        }
        let phases: Vec<PurgePhase> = if overlong {
            vec![PurgePhase::ByCreated]
        } else {
            vec![
                PurgePhase::ByTag {
                    start: h_start,
                    end: h_end,
                    meta_only: false,
                },
                PurgePhase::ByTag {
                    start: d_start,
                    end: d_end,
                    meta_only: true,
                },
            ]
        };
        let mut removed = 0usize;
        let mut max_created = 0u64;
        for phase in &phases {
            let mut last_key: Option<Vec<u8>> = None;
            loop {
                if self.cancelled() {
                    // SIGTERM mid-walk: stop at the chunk boundary and leave the
                    // pending record (written above) for the next startup.
                    return Err(anyhow::anyhow!(
                        "NIP-29 group purge cancelled during shutdown; resuming at next startup"
                    ));
                }
                #[cfg(test)]
                if take_chunk_fault(&self.fail_chunk_after) {
                    return Err(anyhow::anyhow!("test-only removal chunk failure"));
                }
                // Test-only: fail after the marker and in-progress record
                // committed, so the resume path runs with real crash state.
                #[cfg(test)]
                if self
                    .fail_next_purge_chunk
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(anyhow::anyhow!("test-only purge chunk failure"));
                }
                // A fresh write transaction per chunk: a group's history is
                // unbounded, and one transaction across the whole purge pinned
                // the writer while a MapFull aborted everything.
                let mut wtxn = self.env.write_txn()?;
                let entries = match phase {
                    PurgePhase::ByCreated => {
                        let lower = match &last_key {
                            Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                            None => std::ops::Bound::Included(created_start.as_slice()),
                        };
                        removal_chunk(
                            self.by_created,
                            &wtxn,
                            (lower, std::ops::Bound::Included(created_end.as_slice())),
                        )?
                    }
                    PurgePhase::ByTag { start, end, .. } => {
                        let lower = match &last_key {
                            Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                            None => std::ops::Bound::Included(start.as_slice()),
                        };
                        removal_chunk(
                            self.by_tag,
                            &wtxn,
                            (lower, std::ops::Bound::Excluded(end.as_slice())),
                        )?
                    }
                };
                if entries.is_empty() {
                    break;
                }
                last_key = Some(entries.last().unwrap().0.clone());
                for (_, id) in entries {
                    let Some(raw) = self.events.get(&wtxn, &id)? else {
                        continue;
                    };
                    // The removed event's timestamp raises the cut: without it
                    // a same-second or future-dated event would be removed by
                    // this purge and then accepted again on replay.
                    let matched = match phase {
                        PurgePhase::ByCreated => {
                            // The time range is unscoped, so match in memory (an
                            // event that fails to parse cannot be classified and
                            // stays): `h`-tagged history, or relay-generated
                            // metadata naming the group in `d`.
                            let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                                continue;
                            };
                            let history = event
                                .tags
                                .iter()
                                .any(|t| t.len() >= 2 && t[0] == "h" && t[1].as_str() == gid);
                            let metadata =
                                (crate::nips::nip29::GROUP_META..=crate::nips::nip29::GROUP_PINS)
                                    .contains(&event.kind)
                                    && event.tags.iter().any(|t| {
                                        t.len() >= 2 && t[0] == "d" && t[1].as_str() == gid
                                    });
                            if !history && !metadata {
                                continue;
                            }
                            max_created = max_created.max(event.created_at);
                            if event.kind == crate::nips::nip29::CREATE_GROUP && id.len() == ID_LEN
                            {
                                create_id = Some(id.as_slice().try_into().expect("checked length"));
                            }
                            true
                        }
                        PurgePhase::ByTag { meta_only, .. } if *meta_only => {
                            // The `d` range is shared with ordinary addressable
                            // events: only relay-generated metadata naming the
                            // group in `d` may go (an event that fails to parse
                            // cannot be classified and stays).
                            let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                                continue;
                            };
                            if !(crate::nips::nip29::GROUP_META..=crate::nips::nip29::GROUP_PINS)
                                .contains(&event.kind)
                            {
                                continue;
                            }
                            if !event
                                .tags
                                .iter()
                                .any(|t| t.len() >= 2 && t[0] == "d" && t[1].as_str() == gid)
                            {
                                continue;
                            }
                            max_created = max_created.max(event.created_at);
                            true
                        }
                        PurgePhase::ByTag { .. } => {
                            if let Ok(event) = serde_json::from_slice::<Event>(raw) {
                                max_created = max_created.max(event.created_at);
                                if event.kind == crate::nips::nip29::CREATE_GROUP
                                    && id.len() == ID_LEN
                                {
                                    create_id =
                                        Some(id.as_slice().try_into().expect("checked length"));
                                }
                            }
                            true
                        }
                    };
                    if !matched {
                        continue;
                    }
                    self.remove_event(&mut wtxn, &id)?;
                    removed += 1;
                }
                // Persist the raised cut (and any create id) with the chunk
                // that produced it: a crash before completion must not lose
                // either (the cut would regress and a future-dated removed
                // event would be accepted again; the create id would let an
                // exact replay resurrect the group).
                cut = cut.max(max_created);
                self.purge_pending.put(
                    &mut wtxn,
                    &key,
                    &encode_pending_purge(gid, purge_now, cut, effective_until, create_id.as_ref()),
                )?;
                wtxn.commit()?;
            }
        }
        // Completion commit: re-merge the marker (a legacy 8-byte marker was
        // upgraded by the initial commit above), clear the in-progress
        // record and bump the derived-state stamp in one transaction. The
        // stamp bump always happens here: every purge removes (or confirms
        // the absence of) group history, and the derived state must be
        // rebuilt from the surviving events.
        let mut wtxn = self.env.write_txn()?;
        let (old_now, old_cut, old_create) = self
            .purged_groups
            .get(&wtxn, &key)?
            .map(decode_purged_group_marker)
            .unwrap_or((0, 0, None));
        purge_now = purge_now.max(old_now);
        cut = cut.max(old_cut).max(max_created);
        if create_id.is_none() {
            create_id = old_create;
        }
        self.purged_groups.put(
            &mut wtxn,
            &key,
            &encode_purged_group_marker(purge_now, cut, create_id.as_ref()),
        )?;
        self.purge_pending.delete(&mut wtxn, &key)?;
        self.bump_state_stamp(&mut wtxn)?;
        wtxn.commit()?;
        Ok(removed)
    }

    /// Started-but-unfinished group purges as `(gid, purge_now, until)`:
    /// each was recorded before its first removal chunk and not cleared, so
    /// the caller re-runs `purge_group_until(gid, purge_now, until)` to
    /// finish it (the walk is idempotent and the marker keeps the furthest
    /// cut). A malformed record is an error, so a caller that fails closed
    /// never treats a corrupt pending table as "nothing to resume".
    pub(crate) fn pending_purges(&self) -> Result<Vec<(String, u64, u64)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.purge_pending.iter(&rtxn)? {
            let (_, raw) = item?;
            let (gid, purge_now, _, until, _) = decode_pending_purge(raw).ok_or_else(|| {
                anyhow::anyhow!("corrupt pending purge record ({} bytes)", raw.len())
            })?;
            out.push((gid, purge_now, until));
        }
        Ok(out)
    }

    /// NIP-62: deletes every event authored by `pubkey` (including NIP-09
    /// deletion requests and NIP-59 gift wraps that p-tag it) and records the
    /// pubkey so that no future event from it is accepted.
    ///
    /// Replays are cheap: the stored marker keeps the furthest `until_created`
    /// already honored, and a request covered by it removes nothing (NIP-62
    /// requests are signed, re-broadcastable events, so an unchecked replay
    /// would re-walk the author's whole history and rewrite the NIP-29/43
    /// snapshots on every delivery). Only the *completed* marker
    /// short-circuits: an in-progress record means the walk was interrupted
    /// and must be retried.
    pub(crate) fn apply_vanish(
        &self,
        pubkey: &[u8],
        until_created: u64,
    ) -> Result<(usize, StateRemoved)> {
        self.disk_full_error()?;
        // Replay check: a completed marker covering this request means every
        // event up to its cut was already removed, so there is nothing to do.
        {
            let rtxn = self.env.read_txn()?;
            // Legacy entries (written before the marker carried the timestamp)
            // have an empty value and count as `until_created = 0`, so they are
            // upgraded by the next request.
            if self
                .vanished_until(&rtxn, pubkey)?
                .is_some_and(|covered| covered >= until_created)
            {
                return Ok((0, StateRemoved::default()));
            }
        }
        // Persist the in-progress record *before* the first removal chunk:
        // a crash or a store error mid-walk is then resumed at startup (or
        // by a re-delivered request) instead of leaving removed events with
        // no marker and no cursor. The merged cut is returned so a
        // re-delivered older request never walks a shorter bound than the
        // interrupted one.
        let until_created = self.record_pending_vanish(pubkey, until_created)?;
        self.finish_vanish(pubkey, until_created)
    }

    /// Completes every interrupted vanish before the writer serves its first
    /// message (called from the writer thread at startup, so no put can
    /// interleave and no `DbClient` round trip is needed — which would
    /// deadlock the writer against itself). Idempotent: already-removed
    /// events are simply not found, and a crash between the marker and the
    /// pending clear re-writes the same (furthest) marker. A failed record
    /// is logged and left in place for the next restart or re-delivery.
    pub(crate) fn resume_pending_vanishes(
        &self,
        errors: &Arc<std::sync::atomic::AtomicU64>,
    ) -> usize {
        let pending = match self.pending_vanishes() {
            Ok(pending) => pending,
            Err(e) => {
                db_error(errors, &e);
                return 0;
            }
        };
        let mut completed = 0usize;
        for (pubkey, until_created) in pending {
            match self.finish_vanish(&pubkey, until_created) {
                Ok(_) => completed += 1,
                Err(e) => db_error(errors, &e),
            }
        }
        completed
    }

    /// Completes every interrupted NIP-09 deletion before the writer serves
    /// its first message (same startup/atomicity reasoning as
    /// [`Self::resume_pending_vanishes`]). Each record is replayed through
    /// the ordinary (idempotent) walk, which re-records and, on a clean
    /// completion, clears it. The returned flag is true when any resumed
    /// deletion removed a NIP-29/NIP-43 state event: the relay must mark
    /// the derived state stale (the persistent state stamp is bumped in the
    /// same removal transactions, and this flag surfaces the fact directly
    /// to the startup path).
    pub(crate) fn resume_pending_deletions(
        &self,
        errors: &Arc<std::sync::atomic::AtomicU64>,
    ) -> (usize, StateRemoved) {
        let pending = match self.pending_deletions_and_keys() {
            Ok(pending) => pending,
            Err(e) => {
                db_error(errors, &e);
                return (0, StateRemoved::default());
            }
        };
        let mut completed = 0usize;
        let mut state_removed = StateRemoved::default();
        for (record_key, request) in pending {
            if self.cancelled() {
                break;
            }
            // A record with neither a requester nor a group scope can never
            // authorize a removal (the walk refuses it): drop it so it does
            // not block every startup forever. Legitimate records always
            // carry one of the two. Clear it by its literal key: for a
            // record written by an older binary, re-deriving the key from
            // the current encoding would not match.
            if request.request_pubkey.is_none() && request.group.is_none() {
                if let Err(e) = self.clear_pending_deletion(&record_key) {
                    db_error(errors, &e);
                }
                continue;
            }
            let report = self.apply_deletion_group(
                &request.targets,
                &request.addresses,
                request.request_pubkey.as_deref(),
                request.request_created,
                request.group.as_deref(),
                request.purge_wraps,
            );
            state_removed.merge(report.state_removed);
            match report.error {
                Some(e) => db_error(errors, &e),
                None => {
                    completed += 1;
                    // The walk cleared its own record under the key of the
                    // current encoding; for a pre-flag record that key
                    // differs from the stored one, so clear it literally.
                    if let Err(e) = self.clear_pending_deletion(&record_key) {
                        db_error(errors, &e);
                    }
                }
            }
        }
        (completed, state_removed)
    }

    /// Every started-but-unfinished vanish as `(pubkey, until_created)`,
    /// used by the startup resume. A malformed record (bitrot) is skipped
    /// with a warning: the completed-marker path still fails closed for the
    /// pubkey once its marker exists, and a skipped record must not abort
    /// the resume of the healthy ones.
    pub(crate) fn pending_vanishes(&self) -> Result<Vec<(Vec<u8>, u64)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.vanish_pending.iter(&rtxn)? {
            let (key, raw) = item?;
            match raw.get(..8) {
                Some(bytes) => out.push((
                    key.to_vec(),
                    u64::from_be_bytes(bytes.try_into().expect("checked length")),
                )),
                None => log::warn!(
                    "skipping corrupt pending vanish record ({} bytes)",
                    raw.len()
                ),
            }
        }
        Ok(out)
    }

    /// The completed vanish bound for `pubkey`, if any (see [`VANISH`]).
    fn vanished_until(&self, rtxn: &heed::RoTxn, pubkey: &[u8]) -> Result<Option<u64>> {
        Ok(self
            .vanish
            .get(rtxn, pubkey)?
            .and_then(|raw| raw.get(..8))
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("checked length"))))
    }

    /// Persists the in-progress vanish record (pubkey -> furthest
    /// `until_created`) and returns the merged bound, so a re-delivered
    /// older request resumes the interrupted one's full cut.
    fn record_pending_vanish(&self, pubkey: &[u8], until_created: u64) -> Result<u64> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        let until = self
            .vanish_pending
            .get(&wtxn, pubkey)?
            .and_then(|raw| raw.get(..8))
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("checked length")))
            .unwrap_or(0)
            .max(until_created);
        self.vanish_pending
            .put(&mut wtxn, pubkey, &until.to_be_bytes())?;
        wtxn.commit()?;
        Ok(until)
    }

    /// Walks and removes `pubkey`'s history up to `until_created`, drops the
    /// addressed gift wraps, then writes the completed marker and clears the
    /// pending record in the same commit. The walk is idempotent, so both a
    /// re-delivered request and the startup resume can call it. The
    /// derived-state stamp is bumped inside each chunk's transaction that
    /// removed a NIP-29/NIP-43 state event, so a crash later in the walk
    /// cannot lose the fact that the derived state changed.
    fn finish_vanish(&self, pubkey: &[u8], until_created: u64) -> Result<(usize, StateRemoved)> {
        // The resume path enters here directly: refuse to write to a full
        // disk like every other write path (free-space margin).
        self.disk_full_error()?;
        let mut removed = 0usize;
        // Which derived-state families the removed events feed (NIP-29
        // moderation/join/leave vs NIP-43 role state): the two stores are
        // marked stale and rebuilt separately, because a role rebuild drops
        // the NIP-86 invite codes (they have no events behind them).
        // Deleting a member's ordinary posts must not trigger a
        // full-history scan.
        let mut state_removed = StateRemoved::default();
        let start = pubkey_key(pubkey, 0, &[0u8; ID_LEN]);
        // NIP-62: the request deletes the pubkey's history *until its
        // `.created_at`* — events published (timestamped) after the request
        // are not covered by it.
        // Exclusive `(until + 1, 0..)`: covers every event with
        // `created_at <= until`, including the maximal id at exactly `until`.
        let end = crate::db::store::range_end(
            pubkey_key(pubkey, until_created.saturating_add(1), &[0u8; ID_LEN]),
            until_created,
        );
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            if self.cancelled() {
                // SIGTERM mid-walk: stop at the chunk boundary; the pending
                // record stays and the next startup finishes the vanish.
                return Err(anyhow::anyhow!(
                    "NIP-62 vanish cancelled during shutdown; resuming at next startup"
                ));
            }
            #[cfg(test)]
            if take_chunk_fault(&self.fail_chunk_after) {
                return Err(anyhow::anyhow!("test-only removal chunk failure"));
            }
            // Test-only: fail after the in-progress record committed (the
            // caller wrote it), so the resume path runs with real crash
            // state instead of hand-written table entries.
            #[cfg(test)]
            if self
                .fail_next_vanish_chunk
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(anyhow::anyhow!("test-only vanish chunk failure"));
            }
            // A fresh write transaction per chunk: the author's history is
            // unbounded, and one transaction across it pinned the writer
            // while a MapFull aborted the whole vanish. The pending record
            // (written by the caller) makes a partial pass resumable.
            let mut wtxn = self.env.write_txn()?;
            let lower = match &last_key {
                Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                None => std::ops::Bound::Included(start.as_slice()),
            };
            let entries = removal_chunk(
                self.by_pubkey,
                &wtxn,
                (lower, std::ops::Bound::Excluded(end.as_slice())),
            )?;
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().unwrap().0.clone());
            let pubkey_hex = hex::encode(pubkey);
            let mut chunk_state_removed = StateRemoved::default();
            for (key, id) in entries {
                let Some(raw) = self.events.get(&wtxn, &id)? else {
                    continue;
                };
                let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                    continue;
                };
                // NIP-62: only events *authored* by the vanished pubkey are
                // removed. NIP-26 delegatee events are indexed under the
                // delegator's pubkey too, but they belong to the delegatee and
                // must survive a delegator's request to vanish. Their
                // delegator-side index entry is dropped nevertheless, so the
                // vanished identity's feed is not revived by the delegation.
                // Compared case-insensitively: history stored with an
                // uppercase author hex must vanish like lowercase history.
                if !pubkeys_equal(&event.pubkey, &pubkey_hex) {
                    if crate::nips::nip26::delegation(&event).is_some() {
                        self.by_pubkey.delete(&mut wtxn, &key)?;
                    }
                    continue;
                }
                chunk_state_removed.observe(event.kind, crate::nips::nip29::group_id_any(&event));
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
            if !chunk_state_removed.is_empty() {
                // The stamp and the state-event removals commit atomically.
                self.bump_state_stamp(&mut wtxn)?;
            }
            state_removed.merge(chunk_state_removed);
            wtxn.commit()?;
        }

        // NIP-59 gift wraps addressed to the vanished pubkey: the reserved
        // recipient index (keyed by the decoded pubkey) finds every hex case
        // variant with one narrow range. Bounded by the request like the
        // authored history above: a wrap created after the request is not
        // part of the vanished history. A failure here must not write the
        // marker below: the re-delivered request (or the startup resume)
        // has to finish the wraps.
        self.remove_gift_wraps_for(pubkey, until_created, &mut removed)?;

        // The completed marker and the pending clear commit together: a
        // crash between them would otherwise leave a pending record whose
        // request is already covered, and the startup resume would never
        // finish. The marker is written last, and the furthest honored
        // bound is preserved so a replay or resume never regresses it. The
        // writer thread handles one message at a time, so no put can
        // interleave between the walk and the marker: every put queued
        // behind this vanish still sees the marker (or the pending record
        // in between).
        let mut wtxn = self.env.write_txn()?;
        let covered = self.vanished_until(&wtxn, pubkey)?.unwrap_or(0);
        self.vanish
            .put(&mut wtxn, pubkey, &covered.max(until_created).to_be_bytes())?;
        self.vanish_pending.delete(&mut wtxn, pubkey)?;
        wtxn.commit()?;

        Ok((removed, state_removed))
    }

    /// NIP-59: relays SHOULD delete `kind:1059` gift wraps addressed to a
    /// pubkey when that pubkey signs a NIP-09 deletion request. Wraps are
    /// signed by random keys, so they cannot be deleted by their recipient
    /// through the normal deletion flow.
    pub(crate) fn delete_gift_wraps_to(&self, pubkey: &[u8], until: u64) -> Result<usize> {
        self.disk_full_error()?;
        let mut removed = 0usize;
        self.remove_gift_wraps_for(pubkey, until, &mut removed)?;
        Ok(removed)
    }

    /// Removes every stored event whose NIP-40 expiration has arrived, then
    /// reaps `first_seen` entries whose last activity is older than
    /// `first_seen_retention` seconds (0 disables the reap): reaping bounds
    /// the table, at the cost of re-arming the new-pubkey gate for a
    /// returning *idle* pubkey (its next event passes once as "new" and
    /// re-establishes the clock, so an event immediately after may be gated
    /// for `min_age` seconds). Entries refreshed by an accepted event inside
    /// the retention are never reaped, so an account that still posts keeps
    /// its original clock and is not re-gated.
    ///
    /// The returned report carries the partial counters on a failed chunk
    /// (the backlog is unbounded, so a MapFull mid-pass must not hide the
    /// state events an earlier chunk already removed), and its
    /// `state_removed` families report which derived stores changed so the
    /// caller rebuilds exactly those.
    pub(crate) fn purge_expired(&self, now: u64, first_seen_retention: u64) -> RemovalReport {
        let mut removed = 0usize;
        let mut state_removed = StateRemoved::default();
        let error = self
            .purge_expired_walk(now, &mut removed, &mut state_removed)
            .and_then(|()| self.reap_first_seen(now, first_seen_retention))
            .err();
        RemovalReport {
            removed,
            state_removed,
            error,
        }
    }

    /// The expiry walk behind [`Self::purge_expired`]. A shutdown
    /// cancellation stops the walk cleanly at the chunk boundary (the next
    /// periodic purge resumes; NIP-40 has no pending record to keep).
    fn purge_expired_walk(
        &self,
        now: u64,
        removed: &mut usize,
        state_removed: &mut StateRemoved,
    ) -> Result<()> {
        self.disk_full_error()?;
        // NIP-40 disabled: nothing is expired. Stale entries written while
        // it was enabled are removed by `remove_event` (which deletes the
        // entry regardless of the toggle), so re-enabling the feature can
        // never resurrect a purged event through a stale key.
        if !self
            .expiry_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(());
        }
        let since_key = created_key(0, &[0u8; ID_LEN]);
        // NIP-40 semantics are `expiration <= now`: include every key at the
        // current second by using the largest possible event id as the
        // inclusive upper bound.
        let until_key = created_key(now, &[0xff; ID_LEN]);
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            if self.cancelled() {
                break;
            }
            // Test-only: fail before the nth chunk, i.e. after the first
            // committed chunk for a countdown of `2` (a middle-chunk
            // failure; see `take_chunk_fault`). Expiry has no pending
            // record: the next periodic pass resumes the backlog.
            #[cfg(test)]
            if take_chunk_fault(&self.fail_chunk_after) {
                return Err(anyhow::anyhow!("test-only removal chunk failure"));
            }
            // A fresh write transaction per chunk: the expired backlog is
            // unbounded, and one transaction across it pinned the writer
            // while a MapFull aborted the whole purge. Purges run
            // periodically, so a partial pass simply resumes next time.
            let mut wtxn = self.env.write_txn()?;
            let lower = match &last_key {
                Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                None => std::ops::Bound::Included(since_key.as_slice()),
            };
            let entries = removal_chunk(
                self.expiry,
                &wtxn,
                (lower, std::ops::Bound::Included(until_key.as_slice())),
            )?;
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().unwrap().0.clone());
            let mut chunk_state_removed = StateRemoved::default();
            for (key, id) in entries {
                if let Some(raw) = self.events.get(&wtxn, &id)? {
                    if let Ok(event) = serde_json::from_slice::<Event>(raw) {
                        chunk_state_removed
                            .observe(event.kind, crate::nips::nip29::group_id_any(&event));
                    }
                    self.remove_event(&mut wtxn, &id)?;
                    *removed += 1;
                } else {
                    // The event is already gone (removed outside the normal
                    // path or corrupt data): drop the orphaned expiry key
                    // too, or every purge would re-examine it forever.
                    self.expiry.delete(&mut wtxn, &key)?;
                }
            }
            if !chunk_state_removed.is_empty() {
                // The stamp and the state-event removals commit atomically
                // (a separate bump transaction would let a crash lose the
                // fact that the derived state changed).
                self.bump_state_stamp(&mut wtxn)?;
            }
            wtxn.commit()?;
            state_removed.merge(chunk_state_removed);
        }
        Ok(())
    }

    /// Reaps `first_seen` entries whose timestamp is older than `min_age`
    /// Reaps `first_seen` entries whose *last activity* is older than
    /// `retention` seconds (see [`Self::purge_expired`]). `0` disables the
    /// reap. The reaper keys on the last-seen time, not the first-seen
    /// clock: reaping an entry makes its pubkey read as brand new on the
    /// next event, which re-arms the age gate, so an account that still
    /// posts must never be reaped — only one idle past the retention is.
    /// Legacy first-seen-only entries are upgraded in place with
    /// `last_seen = now` instead of being reaped, so an upgrade does not
    /// re-gate accounts that were active under the old layout. The walk is
    /// chunked so a table with millions of accounts never pins one
    /// write transaction, and a shutdown cancellation stops at the chunk
    /// boundary (the next periodic purge finishes the reap).
    fn reap_first_seen(&self, now: u64, retention: u64) -> Result<()> {
        if retention == 0 {
            return Ok(());
        }
        let cutoff = now.saturating_sub(retention);
        let mut last: Option<Vec<u8>> = None;
        loop {
            if self.cancelled() {
                break;
            }
            let mut wtxn = self.env.write_txn()?;
            let lower = match &last {
                Some(key) => std::ops::Bound::Excluded(key.as_slice()),
                None => std::ops::Bound::Unbounded,
            };
            let mut doomed: Vec<Vec<u8>> = Vec::new();
            let mut upgrades: Vec<(Vec<u8>, [u8; 16])> = Vec::new();
            let mut scanned = 0usize;
            let mut last_scanned: Option<Vec<u8>> = None;
            for item in self
                .first_seen
                .range(&wtxn, &(lower, std::ops::Bound::Unbounded))?
            {
                let (key, raw) = item?;
                scanned += 1;
                last_scanned = Some(key.to_vec());
                if raw.len() >= 16 {
                    let last_seen =
                        u64::from_be_bytes(raw[8..16].try_into().expect("checked length"));
                    if last_seen < cutoff {
                        doomed.push(key.to_vec());
                    }
                } else if raw.len() >= 8 {
                    // Legacy first-seen-only entry: upgrade in place with the
                    // activity stamped as now (see the function doc).
                    let mut buf = [0u8; 16];
                    buf[..8].copy_from_slice(&raw[..8]);
                    buf[8..].copy_from_slice(&now.to_be_bytes());
                    upgrades.push((key.to_vec(), buf));
                } else if 0 < cutoff {
                    // A corrupt short entry has no usable timestamp: treat it
                    // as ancient (it can never satisfy the gate) and reap it.
                    doomed.push(key.to_vec());
                }
                if scanned == REMOVAL_CHUNK {
                    break;
                }
            }
            for (key, buf) in &upgrades {
                self.first_seen.put(&mut wtxn, key, buf)?;
            }
            for key in &doomed {
                self.first_seen.delete(&mut wtxn, key)?;
            }
            wtxn.commit()?;
            if scanned < REMOVAL_CHUNK {
                break;
            }
            last = last_scanned;
        }
        Ok(())
    }
}
