//! Integration tests for the database layer, exercised through the
//! public [`DbClient`] API.

use super::*;
use crate::config::DatabaseConfig;
use crate::event::Event;
use crate::nips::nip01;
use crate::util::unix_now;

fn config() -> DatabaseConfig {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join("nostrfy-db-test")
        .join(format!("{:x}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    DatabaseConfig {
        path,
        // Small memory map for the parallel test run (see the ws tests).
        map_size: 16 * 1024 * 1024,
        max_map_size: 256 * 1024 * 1024,
        ..Default::default()
    }
}

fn event(kind: u64, content: &str, created: u64, tags: Vec<Vec<String>>) -> Event {
    let mut ev = Event {
        id: String::new(),
        pubkey: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        created_at: created,
        kind,
        tags,
        content: content.to_string(),
        sig: "00".repeat(64),
    };
    ev.id = nip01::compute_id(&ev);
    ev
}

#[test]

// ----- storage and query -----
fn insert_and_query() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let e1 = event(1, "hello world", now, vec![]);
        let e2 = event(1, "foo bar", now, vec![vec!["t".into(), "rust".into()]]);
        let e3 = event(2, "another", now - 10, vec![]);

        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(
            db.put(e1.clone(), now).await,
            PutOutcome::Duplicate("duplicate: event already stored".into())
        );
        assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(e3, now).await, PutOutcome::Stored);

        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2);

        let f: Filter = serde_json::from_value(serde_json::json!({"#t": ["rust"]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, e2.id);

        let f: Filter = serde_json::from_value(serde_json::json!({"search": "foo"})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, e2.id);
    });
}

#[test]
fn maximal_timestamp_is_included_by_indexed_queries() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let max = event(
            777,
            "maximal timestamp searchable",
            u64::MAX,
            vec![vec!["t".into(), "boundary".into()]],
        );
        assert_eq!(db.put(max.clone(), u64::MAX).await, PutOutcome::Stored);

        for filter in [
            serde_json::json!({}),
            serde_json::json!({"kinds": [777]}),
            serde_json::json!({"authors": [max.pubkey]}),
            serde_json::json!({"#t": ["boundary"]}),
            serde_json::json!({"search": "searchable"}),
        ] {
            let filter: Filter = serde_json::from_value(filter).unwrap();
            let (events, _) = db.query(vec![filter], 10, u64::MAX).await;
            assert!(
                events.iter().any(|event| event.id == max.id),
                "maximal-timestamp event missing from filter result"
            );
        }
    });
}

#[test]
fn replaceable_and_deletion() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let d = vec![vec!["d".to_string(), "post-1".to_string()]];
        let e1 = event(30023, "v1", now, d.clone());
        let e2 = event(30023, "v2", now + 5, d.clone());

        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Replaced);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [30023]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].content, "v2");

        let targets = vec![e2.id.clone()];
        assert_eq!(db.apply_deletion(targets, vec![], None, u64::MAX).await, 1);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [30023]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty());
    });
}

#[test]

// ----- expiration (NIP-40) -----
fn expired_events_are_filtered() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut e = event(1, "ephemeral", now - 100, vec![]);
        e.tags = vec![vec!["expiration".into(), (now - 50).to_string()]];
        assert_eq!(db.put(e, now).await, PutOutcome::Expired);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty());

        let equal = event(
            1,
            "expires exactly now",
            now,
            vec![vec!["expiration".into(), now.to_string()]],
        );
        db.set_expiry_enabled(false);
        assert_eq!(db.put(equal.clone(), now).await, PutOutcome::Stored);
        db.set_expiry_enabled(true);
        let (res, _) = db
            .query(
                vec![serde_json::from_value(serde_json::json!({"ids": [equal.id]})).unwrap()],
                500,
                now,
            )
            .await;
        assert!(res.is_empty());
        assert_eq!(db.purge_expired(now).await, 1);

        // Query filtering must use the earliest value when multiple
        // expiration tags are present, matching storage and purge semantics.
        let mut multi = event(1, "multiple expirations", now, vec![]);
        multi.tags = vec![
            vec!["expiration".into(), (now + 3600).to_string()],
            vec!["expiration".into(), (now - 1).to_string()],
        ];
        db.set_expiry_enabled(false);
        assert_eq!(db.put(multi.clone(), now).await, PutOutcome::Stored);
        db.set_expiry_enabled(true);
        let (res, _) = db
            .query(
                vec![serde_json::from_value(serde_json::json!({"ids": [multi.id]})).unwrap()],
                500,
                now,
            )
            .await;
        assert!(res.is_empty());
        assert_eq!(db.purge_expired(now).await, 1);
    });
}

#[test]

// ----- deletion (NIP-09) -----
fn deletion_by_address_and_author() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let d = vec![vec!["d".to_string(), "post-1".to_string()]];
        let e1 = event(30023, "v1", now, d.clone());
        let e2 = event(30023, "v2", now + 5, d.clone());
        // A third event by a different author must survive.
        let mut e3 = event(30023, "other", now + 6, d.clone());
        e3.pubkey = "1111111111111111111111111111111111111111111111111111111111111111".into();
        e3.id = nip01::compute_id(&e3);

        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Replaced);
        assert_eq!(db.put(e3.clone(), now).await, PutOutcome::Stored);

        let address = crate::nips::nip09::Address {
            kind: 30023,
            pubkey: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            d: "post-1".into(),
        };
        // Only the current version of an addressable event is stored (the
        // older one was removed by replacement), and it is only deleted
        // when its created_at is up to the request's timestamp.
        assert_eq!(
            db.apply_deletion(
                vec![],
                vec![address.clone()],
                Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
                now + 4,
            )
            .await,
            0,
            "the current version is newer than the deletion request"
        );
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [30023]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2, "v2 and the other author's event remain");

        // A deletion with a later timestamp removes the remaining version.
        assert_eq!(
            db.apply_deletion(
                vec![],
                vec![address],
                Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
                u64::MAX,
            )
            .await,
            1
        );
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [30023]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, e3.id, "other author's event is untouched");
    });
}

#[test]
fn deleted_address_rejects_older_republication() {
    // NIP-09: an `a`-tag deletion must stop the relay from publishing older
    // versions of the address afterwards ("stop publishing any referenced
    // events"). The per-id tombstones only cover the versions present at
    // deletion time; the address tombstone covers any later older version.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pk = "0000000000000000000000000000000000000000000000000000000000000000";
        let d = vec![vec!["d".to_string(), "post-1".to_string()]];
        let v1 = event(30023, "v1", now - 10, d.clone());
        assert_eq!(db.put(v1.clone(), now).await, PutOutcome::Stored);
        let address = crate::nips::nip09::Address {
            kind: 30023,
            pubkey: pk.into(),
            d: "post-1".into(),
        };
        assert_eq!(
            db.apply_deletion(vec![], vec![address], Some(pk.into()), now)
                .await,
            1
        );

        // The deleted version stays deleted...
        assert_eq!(db.put(v1.clone(), now).await, PutOutcome::PreviouslyDeleted);
        // ...and so does any other version timestamped up to the request.
        let older = event(30023, "older", now - 20, d.clone());
        assert_eq!(db.put(older, now).await, PutOutcome::PreviouslyDeleted);
        let equal = event(30023, "equal", now, d.clone());
        assert_eq!(db.put(equal, now).await, PutOutcome::PreviouslyDeleted);
        // A version timestamped after the request is admitted: the deletion
        // only covers history up to its own created_at.
        let newer = event(30023, "newer", now + 10, d);
        assert_eq!(db.put(newer, now).await, PutOutcome::Stored);
    });
    db.shutdown();
}

#[test]
fn deletion_by_address_with_empty_d() {
    // NIP-09 `a`-tag deletion of a *replaceable* event (kind 0/3, empty `d`)
    // must work: the replaceable slot key is kind(8)+pubkey(32)+dlen(4)+d(0)
    // = 44 bytes, and the deletion walk used to skip keys < 48 bytes.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // A replaceable profile event (kind 0) with an empty `d` tag.
        let e1 = event(0, "profile", now, vec![]);
        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);

        let address = crate::nips::nip09::Address {
            kind: 0,
            pubkey: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            d: String::new(),
        };
        let removed = db
            .apply_deletion(
                vec![],
                vec![address],
                Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
                u64::MAX,
            )
            .await;
        assert_eq!(
            removed, 1,
            "kind 0 with empty d must be deletable by address"
        );
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [0]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert!(res.is_empty());
    });
}

#[test]
fn deletion_requests_are_never_deleted() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let target = event(1, "note", now, vec![]);
        let deletion = event(5, "del", now, vec![vec!["e".into(), target.id.clone()]]);
        assert_eq!(db.put(target.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(deletion.clone(), now).await, PutOutcome::Stored);

        let pk = "0000000000000000000000000000000000000000000000000000000000000000";
        // A deletion of the deletion request must not remove it.
        assert_eq!(
            db.apply_deletion(vec![deletion.id.clone()], vec![], Some(pk.into()), u64::MAX)
                .await,
            0,
            "deletion requests cannot be deleted"
        );
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [5]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        // ...and the original deletion still works.
        assert_eq!(
            db.apply_deletion(vec![target.id.clone()], vec![], Some(pk.into()), u64::MAX)
                .await,
            1
        );
    });
}

#[test]
fn is_replaceable() {
    assert!(super::store::is_replaceable(&event(10000, "", 1, vec![])));
    assert!(super::store::is_replaceable(&event(30023, "", 1, vec![])));
    assert!(!super::store::is_replaceable(&event(1, "", 1, vec![])));
}

#[test]
fn metadata_and_follows_are_replaceable() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let older = event(0, "{\"name\":\"old\"}", now, vec![]);
        let newer = event(0, "{\"name\":\"new\"}", now + 10, vec![]);
        assert_eq!(db.put(older, now).await, PutOutcome::Stored);
        assert_eq!(db.put(newer.clone(), now).await, PutOutcome::Replaced);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [0]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].content, "{\"name\":\"new\"}");
        assert_eq!(res[0].id, newer.id);
    });
}

#[test]
fn equal_timestamp_replaceable_keeps_lowest_id() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Two kind-1... no — two replaceable events with the SAME
        // created_at: NIP-01 keeps the one with the lowest id.
        let mut high = event(10000, "high-id", now, vec![]);
        let mut low = event(10000, "low-id", now, vec![]);
        // Force a known id ordering by flipping the last content char
        // (the id is a hash, so instead craft ids directly).
        low.id = "00".repeat(32);
        high.id = "ff".repeat(32);
        // compute_id would overwrite; emulate by using valid-length ids
        // (the db only checks length and hex).
        // Put the high id first: the tie-break must replace it with the
        // lower id (a "first one wins" implementation would wrongly keep
        // the high id here).
        assert_eq!(db.put(high.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(low.clone(), now).await, PutOutcome::Replaced);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [10000]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, low.id, "lowest id must be retained");
    });
}

#[test]

// ----- bans (NIP-86) -----
fn banned_events_are_removed_and_rejected() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ev = event(1, "to be banned", now, vec![]);
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        let id = ev.id_bytes().unwrap();
        assert!(db.ban_event(id, "spam").await);
        // Removed from queries.
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty());
        // Re-publication is rejected.
        assert!(matches!(db.put(ev, now).await, PutOutcome::Invalid(_)));
        // Listed with the reason.
        let banned = db.list_banned_events().await;
        assert_eq!(banned, vec![(hex::encode(id), "spam".to_string())]);
        // Unbanning restores publication.
        assert!(db.unban_event(id).await);
        let (res, _) = db.query(vec![Filter::default()], 500, now).await;
        assert!(res.is_empty(), "the event itself was removed");
    });
}

#[test]

// ----- ephemeral and gift wraps (NIP-01/59) -----
fn ephemeral_events_are_not_stored() {
    // NIP-01: kinds 20000-29999 must not be stored (NIP-59 requires
    // kind 21059 in particular to never be stored).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ev = event(
            21059,
            "gift wrap",
            now,
            vec![vec!["p".into(), "a".repeat(64)]],
        );
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Ephemeral);
        // Nothing was stored: queries return nothing and re-publication
        // is not a duplicate.
        let (res, _) = db.query(vec![Filter::default()], 500, now).await;
        assert!(res.is_empty());
        assert_eq!(db.put(ev, now).await, PutOutcome::Ephemeral);
    });
}

#[test]
fn gift_wraps_to_are_deleted() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let recipient = "b83130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
        let other = "c83130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
        let wrap = event(
            1059,
            "encrypted",
            now,
            vec![vec!["p".into(), recipient.into()]],
        );
        let other_wrap = event(
            1059,
            "encrypted2",
            now,
            vec![vec!["p".into(), other.into()]],
        );
        assert_eq!(db.put(wrap.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(other_wrap.clone(), now).await, PutOutcome::Stored);
        let recipient_bytes = hex::decode(recipient).unwrap();
        let removed = db
            .delete_gift_wraps_to(recipient_bytes.try_into().unwrap())
            .await;
        assert_eq!(removed, 1, "only the wrap addressed to the recipient");
        let (res, _) = db
            .query(
                vec![serde_json::from_value(serde_json::json!({"kinds": [1059]})).unwrap()],
                500,
                now,
            )
            .await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, other_wrap.id, "the other wrap survives");
    });
}

#[test]
fn gift_wraps_with_uppercase_p_are_deleted() {
    // The `by_tag` index stores values verbatim: an uppercase `p` value
    // lives under a different key range, so both cases must be walked.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let recipient = "b83130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
        let wrap = event(
            1059,
            "encrypted",
            now,
            vec![vec!["p".into(), recipient.to_ascii_uppercase()]],
        );
        assert_eq!(db.put(wrap.clone(), now).await, PutOutcome::Stored);
        let recipient_bytes = hex::decode(recipient).unwrap();
        let removed = db
            .delete_gift_wraps_to(recipient_bytes.try_into().unwrap())
            .await;
        assert_eq!(removed, 1, "an uppercase p-tagged wrap must be found");
    });
}

#[test]

// ----- database growth -----
fn map_grows_beyond_initial_size() {
    // The database must keep accepting writes beyond a small configured map
    // size: the map is opened at the ceiling (map_max_size) up front as a
    // sparse virtual reservation, so `map_size` only acts as a floor.
    let cfg = DatabaseConfig {
        map_size: 256 * 1024,
        max_map_size: 32 * 1024 * 1024,
        ..config()
    };
    let db = DbClient::open(
        &cfg,
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let n = 3000;
        for i in 0..n {
            let ev = event(
                1,
                &format!("bulk-{i}"),
                now - i as u64,
                vec![vec!["t".into(), format!("tag-{i}")]],
            );
            let out = db.put(ev.clone(), now).await;
            assert!(
                matches!(out, PutOutcome::Stored | PutOutcome::Duplicate(_)),
                "event {i} failed: {out:?}"
            );
        }
        // Every event is readable back.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [1], "limit": n})).unwrap();
        let (res, _) = db.query(vec![f], n, now).await;
        assert_eq!(res.len(), n, "all events must be queryable");
        // And the map grew beyond the initial size.
        assert!(db.map_size_now().await > 256 * 1024, "map must have grown");
    });
}

#[test]
fn ids_filter_checks_every_id_regardless_of_limit() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let e1 = event(1, "first", now, vec![]);
        let e2 = event(1, "second", now - 1, vec![]);
        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Stored);
        // With `limit: 1` the scan must still look past the first id: if
        // the first id does not exist but a later one does, it is found.
        let missing = "00".repeat(32);
        let f: Filter = serde_json::from_value(serde_json::json!({
            "ids": [missing, e2.id],
            "limit": 1
        }))
        .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the existing id must be found");
        assert_eq!(res[0].id, e2.id);
        // Without a limit every id is checked too.
        let f: Filter =
            serde_json::from_value(serde_json::json!({ "ids": [e1.id, e2.id] })).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2);
    });
}

#[test]
fn ids_filter_limit_returns_the_newest() {
    // NIP-01: `limit: n` selects the last n events ordered by `created_at`,
    // not the first n entries of the `ids` array. The events database is
    // keyed by id, so the ids path must sort its candidates by created_at
    // before the limit cuts them. A later filter also keeps its own quota
    // after the ids filter fills up.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let old = event(1, "old", now - 10, vec![]);
        let new = event(1, "new", now, vec![]);
        for ev in [&old, &new] {
            assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        }
        // The older id comes first in the filter: the newer event must win.
        let f: Filter = serde_json::from_value(serde_json::json!({
            "ids": [old.id, new.id],
            "limit": 1
        }))
        .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, new.id, "the newest id must win the limit");

        // The ids filter's quota does not abort a later filter.
        let k7 = event(7, "kind 7", now - 5, vec![]);
        assert_eq!(db.put(k7.clone(), now).await, PutOutcome::Stored);
        let f: Vec<Filter> = serde_json::from_value(serde_json::json!([
            {"ids": [old.id, new.id], "limit": 1},
            {"kinds": [7], "limit": 1}
        ]))
        .unwrap();
        let (res, _) = db.query(f, 500, now).await;
        let ids: Vec<String> = res.iter().map(|e| e.id.clone()).collect();
        assert_eq!(res.len(), 2);
        assert!(ids.contains(&new.id));
        assert!(ids.contains(&k7.id));
        assert!(!ids.contains(&old.id), "the older id is over quota");
    });
    db.shutdown();
}

#[test]
fn nip28_channel_queries_use_e_tag_index() {
    // NIP-28 channel messages reference their channel with an `e` tag; the
    // generic tag index must serve `{"#e": [channel_id]}` queries.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // The channel itself (kind 40) and its messages (kind 42).
        let channel = event(
            40,
            "channel about",
            now,
            vec![vec!["name".into(), "nostrfy".into()]],
        );
        assert_eq!(db.put(channel.clone(), now).await, PutOutcome::Stored);
        for i in 0..3 {
            let msg = event(
                42,
                &format!("message {i}"),
                now - i as u64,
                vec![vec!["e".into(), channel.id.clone()]],
            );
            assert_eq!(db.put(msg.clone(), now).await, PutOutcome::Stored);
        }
        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [42], "#e": [channel.id]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 3, "channel messages must be served via #e");
        // Messages referencing another channel are not returned.
        let other: Filter =
            serde_json::from_value(serde_json::json!({"#e": ["ff".repeat(32)]})).unwrap();
        let (res, _) = db.query(vec![other], 500, now).await;
        assert!(res.is_empty());
    });
}

#[test]
fn store_blossom_mapping_lifecycle() {
    use crate::db::store::{Store, apply_put_batch};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    let cfg = config();
    let errors = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let store = Store::open(&cfg, Arc::new(AtomicBool::new(true)), 512).unwrap();
    let sha = "aa".repeat(32);
    let sha2 = "ee".repeat(32);
    let alice = "cc".repeat(32);
    let bob = "dd".repeat(32);
    // An empty batch commits nothing and returns no outcomes.
    assert!(apply_put_batch(&store, &errors, None, &[]).is_empty());
    // A fresh mapping + a mapping that already carries the owner: the
    // duplicate entry must be skipped, and a second owner merges in.
    store
        .add_blossom_mappings(&[(sha.clone(), "image/png".into(), 3, 100, alice.clone())])
        .unwrap();
    store
        .add_blossom_mappings(&[(sha.clone(), "image/png".into(), 3, 100, alice.clone())])
        .unwrap();
    store
        .add_blossom_mappings(&[(sha.clone(), "image/png".into(), 3, 100, bob.clone())])
        .unwrap();
    store
        .add_blossom_mappings(&[(sha2.clone(), "text/plain".into(), 1, 200, bob.clone())])
        .unwrap();
    let meta = store.load_blossom_mapping(&sha).unwrap().unwrap();
    assert_eq!(meta.owners.len(), 2, "both owners merge into the mapping");
    assert_eq!(
        store.list_blossom_shas(&alice, 10_000).unwrap(),
        vec![sha.clone()],
        "the reverse index lists the blob for the owner"
    );
    assert_eq!(store.list_blossom_shas(&bob, 10_000).unwrap().len(), 2);
    // Unknown blob / unknown owner return false.
    assert!(
        !store
            .remove_blossom_owner(&"bb".repeat(32), &alice)
            .unwrap()
    );
    assert!(!store.remove_blossom_owner(&sha, &"ff".repeat(32)).unwrap());
    // Removing one owner keeps the mapping; removing the last deletes it.
    assert!(store.remove_blossom_owner(&sha, &alice).unwrap());
    assert_eq!(
        store.load_blossom_mapping(&sha).unwrap().unwrap().owners,
        vec![bob.clone()]
    );
    assert!(!store.remove_blossom_owner(&sha, &alice).unwrap());
    assert!(store.remove_blossom_owner(&sha, &bob).unwrap());
    assert!(store.load_blossom_mapping(&sha).unwrap().is_none());
    assert!(
        store
            .list_blossom_shas(&bob, 10_000)
            .unwrap()
            .contains(&sha2)
    );
    // A corrupt metadata blob reports None (both loads and removals).
    {
        let mut wtxn = store.env.write_txn().unwrap();
        store
            .blossom
            .put(&mut wtxn, format!("sha:{sha2}").as_bytes(), b"not-json")
            .unwrap();
        wtxn.commit().unwrap();
    }
    assert!(store.load_blossom_mapping(&sha2).unwrap().is_none());
    assert!(!store.remove_blossom_owner(&sha2, &bob).unwrap());
}

#[test]
fn only_first_value_of_a_single_letter_tag_is_indexed() {
    // NIP-01: "Only the first value in any given tag is indexed." A filter
    // matching the second value of a same-name tag must not find the event,
    // matching the live path (`Filter::matches`). Only single-letter names
    // are indexed (the spec's indexing convention).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ev = event(
            1,
            "multi-value tag",
            now,
            vec![vec!["e".into(), "aa".repeat(32), "bb".repeat(32)]],
        );
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        let f: Filter =
            serde_json::from_value(serde_json::json!({ "kinds": [1], "#e": ["aa".repeat(32)] }))
                .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the first tag value must be indexed");
        assert_eq!(res[0].id, ev.id);
        let f: Filter =
            serde_json::from_value(serde_json::json!({ "kinds": [1], "#e": ["bb".repeat(32)] }))
                .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty(), "the second tag value must not be indexed");

        // Several same-name tags: every tag contributes its own first value.
        let multi = event(
            1,
            "two tags",
            now,
            vec![
                vec!["e".into(), "cc".repeat(32), "dd".repeat(32)],
                vec!["e".into(), "ee".repeat(32)],
            ],
        );
        assert_eq!(db.put(multi.clone(), now).await, PutOutcome::Stored);
        for value in ["cc".repeat(32), "ee".repeat(32)] {
            let f: Filter =
                serde_json::from_value(serde_json::json!({ "kinds": [1], "#e": [value] })).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(
                res.len(),
                1,
                "each same-name tag's first value must be indexed"
            );
        }
        let f: Filter =
            serde_json::from_value(serde_json::json!({ "kinds": [1], "#e": ["dd".repeat(32)] }))
                .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty(), "a trailing tag value must not be indexed");

        // Removing the event removes the index entries: a later query for
        // the first value returns nothing.
        db.apply_deletion(vec![ev.id.clone()], vec![], Some(ev.pubkey.clone()), now)
            .await;
        let f: Filter =
            serde_json::from_value(serde_json::json!({ "kinds": [1], "#e": ["aa".repeat(32)] }))
                .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(
            res.is_empty(),
            "deleted events must not be served via their tag index"
        );
    });
    db.shutdown();
}

#[test]
fn nip22_comments_are_stored_and_served() {
    // NIP-22 (kind 1111) comments are regular events: stored like any other
    // kind and served through the `#e` threading index (the lowercase parent
    // tags) as well as through the single-letter root-scope tags (`E`, `K`).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let root = event(1, "root", now, vec![vec!["t".into(), "discussion".into()]]);
        assert_eq!(db.put(root.clone(), now).await, PutOutcome::Stored);
        let comment = event(
            1111,
            "great note",
            now - 1,
            vec![
                vec!["E".into(), root.id.clone()],
                vec!["K".into(), "1".into()],
                vec!["P".into(), root.pubkey.clone()],
                vec!["e".into(), root.id.clone()],
                vec!["k".into(), "1".into()],
                vec!["p".into(), root.pubkey.clone()],
            ],
        );
        assert_eq!(db.put(comment.clone(), now).await, PutOutcome::Stored);
        let reply = event(
            1111,
            "and this is a reply",
            now - 2,
            vec![
                vec!["E".into(), root.id.clone()],
                vec!["K".into(), "1".into()],
                vec!["e".into(), comment.id.clone()],
                vec!["k".into(), "1111".into()],
                vec!["p".into(), comment.pubkey.clone()],
            ],
        );
        assert_eq!(db.put(reply.clone(), now).await, PutOutcome::Stored);

        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1111]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2, "comments are served by their kind");

        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [1111], "#e": [root.id]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(
            res.len(),
            1,
            "only the direct comment threads to the root via #e"
        );
        let f: Filter = serde_json::from_value(serde_json::json!({
            "kinds": [1111], "#e": [comment.id]
        }))
        .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the reply threads to the comment via #e");

        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [1111], "#E": [root.id]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2, "root-scope E tags are indexed");
        let f: Filter = serde_json::from_value(serde_json::json!({"#K": ["1"]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2, "root-scope K tags are indexed");

        let f: Filter = serde_json::from_value(serde_json::json!({
            "kinds": [1111], "authors": [root.pubkey]
        }))
        .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2, "comments are served by author");
    });
}

#[test]
fn nip_a3_payto_targets_are_replaceable() {
    // NIP-A3 (kind 10133) payment targets are replaceable events: the latest
    // per pubkey wins, and the multi-letter `payto` tag is queryable through
    // the full-scan fallback (single-letter tags are the only indexed ones).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let v1 = event(
            10133,
            "",
            now - 1,
            vec![
                vec!["payto".into(), "bitcoin".into(), "bc1q...".into()],
                vec![
                    "payto".into(),
                    "lightning".into(),
                    "user@example.com".into(),
                ],
            ],
        );
        assert_eq!(db.put(v1.clone(), now).await, PutOutcome::Stored);
        // A newer event by the same author replaces the previous one.
        let v2 = event(
            10133,
            "",
            now,
            vec![vec!["payto".into(), "nano".into(), "nano_...".into()]],
        );
        assert_eq!(db.put(v2.clone(), now).await, PutOutcome::Replaced);

        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [10133]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "only the latest payment target event is kept");
        assert_eq!(res[0].id, v2.id);

        let f: Filter = serde_json::from_value(serde_json::json!({"#payto": ["bitcoin"]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty(), "replaced payto values are gone");
        let f: Filter = serde_json::from_value(serde_json::json!({"#payto": ["nano"]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(
            res.len(),
            1,
            "multi-letter payto tags match via the full scan"
        );
    });
}

#[test]
fn overlong_index_components_do_not_poison_the_batch() {
    // LMDB rejects keys >= 512 bytes with MDB_BAD_VALSIZE. A tag value or
    // content word long enough to produce such a key used to abort the whole
    // merged write batch (rejecting every connection's events); the index
    // must now skip the over-long entry instead of erroring.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let long_tag = "x".repeat(500);
        let e_long_tag = event(
            1,
            "has a long tag",
            now,
            vec![vec!["t".into(), long_tag.clone()]],
        );
        let long_word = "w".repeat(500);
        let e_long_word = event(1, &long_word, now - 1, vec![]);
        let e_normal = event(1, "normal note", now - 2, vec![]);
        let results = db
            .put_batch(vec![
                (e_long_tag.clone(), now),
                (e_long_word.clone(), now),
                (e_normal.clone(), now),
            ])
            .await;
        assert_eq!(
            results,
            vec![PutOutcome::Stored, PutOutcome::Stored, PutOutcome::Stored],
            "over-long index components must not poison the batch"
        );
        // All three events are stored and reachable without the long filter.
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 3);
        // The long tag value is not indexed, but the scan falls back to the
        // time-range match, so the filter still finds the event.
        let f: Filter = serde_json::from_value(serde_json::json!({"#t": [long_tag]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(
            res.len(),
            1,
            "an over-long tag value must match via the scan fallback"
        );
        assert_eq!(res[0].id, e_long_tag.id);
    });
}

#[test]
fn non_alphanumeric_tag_names_fall_back_to_the_scan() {
    // Only single-letter ASCII-alphanumeric tag names are indexed; `#_` (and
    // other non-alphanumeric names) must still match through the time-range
    // scan so stored results agree with live delivery.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ev = event(1, "underscore tag", now, vec![vec!["_".into(), "v".into()]]);
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"#_": ["v"]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(
            res.len(),
            1,
            "a non-indexed tag name must be found by the scan"
        );
        assert_eq!(res[0].id, ev.id);
    });
    db.shutdown();
}

#[test]
fn until_bound_includes_the_maximal_id() {
    // An event with `created_at == until` and the maximal id (`ff..ff`) sits
    // exactly on the old exclusive upper bound and used to be dropped.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut ev = event(1, "max id at until", now, vec![]);
        ev.id = "ff".repeat(32);
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"until": now})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the maximal id at `until` must be included");
        assert_eq!(res[0].id, ev.id);
        // One second earlier excludes it.
        let f: Filter = serde_json::from_value(serde_json::json!({"until": now - 1})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty(), "the event is newer than the bound");
    });
    db.shutdown();
}

#[test]
fn group_purge_removes_only_that_groups_events() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let g1 = event(
            1,
            "g1 message",
            now,
            vec![vec!["h".into(), "group-1".into()]],
        );
        let g2 = event(
            1,
            "g2 message",
            now - 1,
            vec![vec!["h".into(), "group-2".into()]],
        );
        let plain = event(1, "no group", now - 2, vec![]);
        for e in [&g1, &g2, &plain] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        assert_eq!(db.group_purge("group-1".into()).await, 1);
        let f: Filter = serde_json::from_value(serde_json::json!({"#h": ["group-1"]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty(), "the purged group must have no events");
        let f: Filter = serde_json::from_value(serde_json::json!({"#h": ["group-2"]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "other groups are untouched");
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2, "the other group and the plain event survive");
    });
    db.shutdown();
}

#[test]
fn multi_filter_req_survives_an_early_limit() {
    // A first filter that hits its limit immediately (e.g. `limit: 0`) must
    // not abort the rest of the multi-filter REQ: `[{"limit":0},{"kinds":[1]}]`
    // still returns the kind-1 events from the second filter.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let e1 = event(1, "one", now, vec![]);
        let e2 = event(1, "two", now - 1, vec![]);
        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Stored);

        let f: Vec<Filter> = serde_json::from_value(serde_json::json!([
            {"limit": 0},
            {"kinds": [1]}
        ]))
        .unwrap();
        let (res, _) = db.query(f, 500, now).await;
        assert_eq!(res.len(), 2, "the second filter must still be evaluated");

        // A lone `limit: 0` filter returns nothing with `more == false`
        // (NIP-01: no stored events, subscription stays open — not a
        // truncated page that would send clients into a pagination loop).
        let f: Vec<Filter> = serde_json::from_value(serde_json::json!([
            {"limit": 0}
        ]))
        .unwrap();
        let (res, more) = db.query(f, 500, now).await;
        assert!(res.is_empty());
        assert!(!more, "limit: 0 must report finish, not more");
    });
}

#[test]
fn multi_filter_limits_are_per_filter() {
    // NIP-01: each filter of a REQ has its own `limit`, and the response is
    // the union of what each filter returns. An earlier filter filling its
    // quota must not consume (or abort) a later filter's quota; the union is
    // ordered by created_at, not by filter order.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let k1_old = event(1, "kind 1 old", now - 10, vec![]);
        let k1_new = event(1, "kind 1 new", now, vec![]);
        let k7 = event(7, "kind 7", now - 5, vec![]);
        for ev in [&k1_old, &k1_new, &k7] {
            assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        }

        let f: Vec<Filter> = serde_json::from_value(serde_json::json!([
            {"kinds": [1], "limit": 1},
            {"kinds": [7], "limit": 1}
        ]))
        .unwrap();
        let (res, _) = db.query(f, 500, now).await;
        assert_eq!(
            res.len(),
            2,
            "the second filter must contribute despite the first filter's limit"
        );
        let ids: Vec<String> = res.iter().map(|e| e.id.clone()).collect();
        assert!(ids.contains(&k1_new.id), "the newest kind-1 event wins");
        assert!(
            !ids.contains(&k1_old.id),
            "the older kind-1 event is over quota"
        );
        assert!(ids.contains(&k7.id), "the kind-7 filter keeps its quota");
        assert_eq!(res[0].id, k1_new.id, "the union is newest-first");
        assert_eq!(res[1].id, k7.id);
    });
    db.shutdown();
}

#[test]
fn ids_filter_supports_prefixes() {
    // NIP-01: `ids` entries may be event-id prefixes.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let e1 = event(1, "one", now, vec![]);
        let e2 = event(1, "two", now - 1, vec![]);
        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Stored);
        assert!(e1.id != e2.id);

        let prefix = &e1.id[..16];
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [prefix]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the prefix matches only its own event");
        assert_eq!(res[0].id, e1.id);
    });
}

#[test]
fn group_deletion_is_scoped_to_the_group() {
    // NIP-29 kind:9005 moderation deletion must only delete events of the
    // admin's own group: an admin of one group cannot remove another
    // group's events by referencing their ids.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let e1 = event(
            9000,
            "in group a",
            now,
            vec![vec!["h".into(), "group-a".into()]],
        );
        let e2 = event(
            9000,
            "in group b",
            now,
            vec![vec!["h".into(), "group-b".into()]],
        );
        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Stored);
        let removed = db
            .apply_group_deletion(vec![e1.id.clone(), e2.id.clone()], "group-a".into())
            .await;
        assert_eq!(removed, 1, "only the group-a event may be deleted");
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [e1.id]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert!(res.is_empty(), "group-a event deleted");
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [e2.id]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert_eq!(res.len(), 1, "group-b event must survive");
    });
}

#[test]
fn vanish_respects_the_request_created_at_bound() {
    // NIP-62: the request deletes the pubkey's history "until its
    // `.created_at`" — events timestamped after the request are not
    // covered by the deletion.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pubkey = "aa".repeat(32);
        let ev = |created| {
            let mut e = event(1, "v", created, vec![]);
            e.pubkey = pubkey.clone();
            e.id = nip01::compute_id(&e);
            e
        };
        let old = ev(1_000);
        let newer = ev(3_000);
        assert_eq!(db.put(old.clone(), 4_000).await, PutOutcome::Stored);
        assert_eq!(db.put(newer.clone(), 4_000).await, PutOutcome::Stored);
        // The vanish request was created at t=2000: only older events go.
        let removed = db
            .apply_vanish(hex::decode(&pubkey).unwrap().try_into().unwrap(), 2_000)
            .await;
        assert_eq!(removed, 1, "only events up to the request's created_at");
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (res, _) = db.query(vec![f], 10, 4_000).await;
        assert_eq!(res.len(), 1, "the newer event survives the vanish");
        assert_eq!(res[0].id, newer.id);
        // The pubkey is vanish-listed regardless: new events are rejected.
        let rejected = ev(4_000);
        assert!(
            matches!(
                db.put(rejected, 4_000).await,
                PutOutcome::Invalid(reason) if reason.contains("vanish")
            ),
            "a vanished pubkey cannot publish again"
        );
    });
    db.shutdown();
}

#[test]
fn vanish_keeps_delegatee_events_of_a_delegator() {
    // NIP-62: a request to vanish removes only events *authored* by the
    // pubkey. NIP-26 delegatee events are indexed under the delegator too,
    // so a delegator's vanish must not delete the delegatee's events.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let delegator = "aa".repeat(32);
        let delegatee = "bb".repeat(32);
        let mut e = event(
            1,
            "delegated",
            now,
            vec![vec![
                "delegation".into(),
                delegator.clone(),
                "kind=1".into(),
                "00".repeat(64),
            ]],
        );
        e.pubkey = delegatee.clone();
        e.id = nip01::compute_id(&e);
        assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);

        // A forged delegation tag must not let the delegator delete the
        // delegatee's event; deletion revalidates the NIP-26 token.
        assert_eq!(
            db.apply_deletion(vec![e.id.clone()], vec![], Some(delegator.clone()), now)
                .await,
            0,
            "invalid delegation must not authorize deletion"
        );

        // Vanish the delegator: the delegatee-authored event survives.
        let removed = db
            .apply_vanish(
                hex::decode(&delegator).unwrap().try_into().unwrap(),
                u64::MAX,
            )
            .await;
        assert_eq!(removed, 0, "delegator's vanish removes no delegatee events");
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [e.id]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert_eq!(res.len(), 1, "delegatee event must survive");

        // Vanish the delegatee: their own event is removed.
        let removed = db
            .apply_vanish(
                hex::decode(&delegatee).unwrap().try_into().unwrap(),
                u64::MAX,
            )
            .await;
        assert_eq!(removed, 1);
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [e.id]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert!(res.is_empty());
    });
}

#[test]
fn vanished_recipient_gift_wraps_are_rejected_on_republish() {
    // NIP-62: "Relays MUST ensure that the deleted events cannot be
    // re-broadcasted into the relay." Gift wraps addressed to the vanished
    // pubkey are signed by random keys, so the author check cannot catch
    // them; the recipient's p tag must.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let recipient = "aa".repeat(32);
        assert_eq!(
            db.apply_vanish(
                hex::decode(&recipient).unwrap().try_into().unwrap(),
                u64::MAX
            )
            .await,
            0
        );
        let wrap = |content: &str, wrapper: &str, p: &str| {
            let mut e = event(1059, content, now, vec![vec!["p".into(), p.to_string()]]);
            e.pubkey = wrapper.to_string();
            e.id = nip01::compute_id(&e);
            e
        };
        let blocked = wrap("wrap", &"bb".repeat(32), &recipient);
        assert!(
            matches!(
                db.put(blocked, now).await,
                PutOutcome::Invalid(reason) if reason.contains("vanish")
            ),
            "a wrap to a vanished recipient must not be re-accepted"
        );
        // An uppercase p tag value decodes to the same recipient.
        let upper = wrap(
            "wrap-upper",
            &"bb".repeat(32),
            &recipient.to_ascii_uppercase(),
        );
        assert!(matches!(db.put(upper, now).await, PutOutcome::Invalid(_)));
        // A wrap to someone else is still accepted.
        let other = wrap("wrap-other", &"bb".repeat(32), &"cc".repeat(32));
        assert_eq!(db.put(other, now).await, PutOutcome::Stored);
    });
    db.shutdown();
}

#[test]
fn access_control_persists_across_reopen() {
    // NIP-86 runtime bans/allowlists survive restarts: the access control is
    // stored in the database and restored when the database is reopened.
    let cfg = config();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        {
            let db = DbClient::open(
                &cfg,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let mut access = crate::config::AccessControl::default();
            access.allowed_kinds.push(5);
            access
                .blocked_ips
                .push(("203.0.113.9".into(), String::new()));
            db.save_access(access.clone()).await;
            // The pubkey lists live under their own key.
            db.save_relay_pubkeys(&[("aa".repeat(32), String::new())], &[])
                .await;
            let loaded = db.load_access().await.expect("persisted access loads");
            assert_eq!(loaded.allowed_kinds, access.allowed_kinds);
            assert_eq!(loaded.blocked_ips, access.blocked_ips);
        }
        // Reopen the same database: the state is restored.
        let db = DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let loaded = db.load_access().await.expect("persisted access loads");
        assert_eq!(loaded.allowed_kinds, vec![5]);
        assert_eq!(
            loaded.blocked_ips,
            vec![(String::from("203.0.113.9"), String::new())]
        );
        // The dedicated pubkey key survives the reopen.
        let (deny, allow) = db.load_relay_pubkeys().await.unwrap_or_default();
        assert_eq!(deny, vec![("aa".repeat(32), String::new())]);
        assert!(allow.is_empty());
    });
}

#[test]
fn schema_upgrade_creates_missing_tables_instantly() {
    // Simulates an ancient database that only has the `events` table (all
    // other tables were added by later versions). Opening it must create
    // every missing table instantly and non-destructively: events, the
    // access control and the Blossom mapping all keep working.
    let cfg = config();
    std::fs::create_dir_all(&cfg.path).unwrap();
    {
        let env = unsafe {
            heed::EnvOpenOptions::new()
                .max_dbs(32)
                .max_readers(cfg.max_readers.max(8))
                .map_size(cfg.max_map_size.max(cfg.map_size))
                .open(&cfg.path)
                .unwrap()
        };
        let mut wtxn = env.write_txn().unwrap();
        env.create_database::<heed::types::Bytes, heed::types::Bytes>(&mut wtxn, Some("events"))
            .unwrap();
        wtxn.commit().unwrap();
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let db = DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        // Events work (the events table was reused).
        let now = 1_700_000_000;
        let e = event(1, "upgrade", now, vec![]);
        assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [e.id]})).unwrap();
        let (found, _) = db.query(vec![f], 10, now).await;
        assert_eq!(found.len(), 1);
        // Access control works (access table + the relay pubkeys key).
        let mut access = crate::config::AccessControl::default();
        access
            .blocked_ips
            .push(("203.0.113.9".into(), String::new()));
        db.save_access(access).await;
        db.save_relay_pubkeys(&[("aa".repeat(32), String::new())], &[])
            .await;
        let loaded = db.load_access().await.unwrap();
        assert_eq!(loaded.blocked_ips[0].0, "203.0.113.9");
        let (deny, _) = db.load_relay_pubkeys().await.unwrap_or_default();
        assert_eq!(deny[0].0, "aa".repeat(32));
        // The Blossom mapping works (blossom table + migration marker).
        db.blossom_add_owner(
            &"bb".repeat(32),
            "image/png",
            3,
            now as i64,
            &"cc".repeat(32),
        )
        .await;
        let meta = db.blossom_load(&"bb".repeat(32)).await.unwrap();
        assert_eq!(meta.owners.len(), 1);
        assert!(!db.blossom_migration_done().await);
    });
}

#[test]
fn legacy_access_blob_pubkeys_migrate_to_dedicated_key() {
    // Databases written before the pubkey lists moved into their own key
    // carry them inside the `access` blob. Opening such a database must
    // migrate them once (the dedicated key then wins).
    let cfg = config();
    {
        // Write the legacy blob directly (the typed writer skips the
        // pubkey lists now).
        let dir = &cfg.path;
        std::fs::create_dir_all(dir).unwrap();
        // The env must be opened with the same map size as DbClient::open
        // (LMDB refuses a different map size at reopen).
        let map_size = cfg.max_map_size.max(cfg.map_size);
        let env = unsafe {
            heed::EnvOpenOptions::new()
                .max_dbs(cfg.max_dbs.max(16))
                .max_readers(cfg.max_readers.max(8))
                .map_size(map_size)
                .open(dir)
                .unwrap()
        };
        let mut wtxn = env.write_txn().unwrap();
        let access = env
            .create_database::<heed::types::Bytes, heed::types::Bytes>(&mut wtxn, Some("access"))
            .unwrap();
        let blob = serde_json::json!({
            "blocked_pubkeys": [["bb".repeat(32), "spam"]],
            "allowed_pubkeys": ["aa".repeat(32)],
            "blocked_kinds": [],
            "allowed_kinds": [],
            "blocked_ips": [],
        });
        access
            .put(
                &mut wtxn,
                b"access",
                serde_json::to_vec(&blob).unwrap().as_slice(),
            )
            .unwrap();
        wtxn.commit().unwrap();
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // DbClient::open runs the one-time migration.
        let db = DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let (deny, allow) = db.load_relay_pubkeys().await.unwrap_or_default();
        assert_eq!(deny, vec![("bb".repeat(32), "spam".to_string())]);
        assert_eq!(allow, vec![("aa".repeat(32), String::new())]);
        // The migration is idempotent: reopening does not double entries.
        drop(db);
        let db = DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let (deny, allow) = db.load_relay_pubkeys().await.unwrap_or_default();
        assert_eq!(deny.len(), 1);
        assert_eq!(allow.len(), 1);
    });
}

#[test]

// ----- trust period and expiry toggling -----
fn first_seen_trust_period() {
    // A pubkey's first event records its arrival; later events within
    // the trust window are rejected by the relay. Here we verify the
    // bookkeeping itself.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pubkey = [7u8; 32];
        // First touch: created, the arrival time is recorded.
        let (created, first) = db.touch_first_seen_batch(vec![(pubkey, now)]).await[0];
        assert!(created);
        assert_eq!(first, now);
        // Second touch: not created, the same time is returned.
        let (created, first) = db.touch_first_seen_batch(vec![(pubkey, now + 5)]).await[0];
        assert!(!created);
        assert_eq!(first, now);
        // The recorded first-seen time never changes, so the trust
        // period does not restart once the window has elapsed: the
        // entry is kept permanently (one 40-byte row per unique pubkey).
        let (created, first) = db.touch_first_seen_batch(vec![(pubkey, now + 9999)]).await[0];
        assert!(!created);
        assert_eq!(first, now, "first-seen stays at the original arrival");
        // A different pubkey is created independently.
        let (created, _) = db.touch_first_seen_batch(vec![([8u8; 32], now)]).await[0];
        assert!(created);
    });
}

#[test]
fn read_only_first_seen_does_not_record() {
    // The pre-store age check must not write first-seen: a rejected first
    // event (expired/duplicate/invalid) must not start the account-age clock.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pubkey = [9u8; 32];
        let (created, _) = db.first_seen_batch(vec![pubkey]).await[0];
        assert!(created, "never seen before");
        // Repeated read-only lookups still report "created": nothing written.
        let (created, _) = db.first_seen_batch(vec![pubkey]).await[0];
        assert!(created, "read-only lookup must not record first-seen");
        // Recording happens explicitly on a successful store.
        let (created, ts) = db.touch_first_seen_batch(vec![(pubkey, 1234)]).await[0];
        assert!(created);
        assert_eq!(ts, 1234);
        // Now the read-only lookup reports "not created" with the recorded time.
        let (created, ts) = db.first_seen_batch(vec![pubkey]).await[0];
        assert!(!created);
        assert_eq!(ts, 1234);
    });
}

#[test]
fn expiry_enabled_toggles_at_runtime() {
    // A config reload must be able to enable/disable NIP-40 handling.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ev = event(
            1,
            "expiring",
            now,
            vec![vec!["expiration".into(), (now - 5).to_string()]],
        );
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Expired);

        // Disabled: the expired event is accepted and served.
        db.set_expiry_enabled(false);
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        let (res, _) = db.query(vec![Filter::default()], 500, now).await;
        assert_eq!(res.len(), 1);

        // Re-enabled: a fresh expired event is rejected again.
        db.set_expiry_enabled(true);
        let ev2 = event(
            1,
            "expiring2",
            now,
            vec![vec!["expiration".into(), (now - 5).to_string()]],
        );
        assert_eq!(db.put(ev2, now).await, PutOutcome::Expired);
    });
}

#[test]
fn events_stored_while_nip40_was_disabled_are_purged_on_reenable() {
    // The expiry index is maintained even while NIP-40 is disabled, so an
    // event accepted during that window becomes purgeable when the feature
    // is re-enabled (it used to stay stored forever).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        db.set_expiry_enabled(false);
        let ev = event(
            1,
            "stored while disabled",
            now,
            vec![vec!["expiration".into(), (now - 5).to_string()]],
        );
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        // Re-enabling makes the stored event expired; the purge reclaims it.
        db.set_expiry_enabled(true);
        assert_eq!(
            db.purge_expired(now).await,
            1,
            "the event stored while disabled must be purged"
        );
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [ev.id]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert!(res.is_empty());
    });
    db.shutdown();
}

#[test]

// ----- filters, search and ordering -----
fn multiletter_tag_filters_match() {
    // NIP-01 only requires single-letter tags to be indexed; filters on
    // longer tag names must still match via the full scan.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let hit = event(1, "alt", now, vec![vec!["alt".into(), "reply".into()]]);
        let miss = event(1, "no alt", now, vec![]);
        assert_eq!(db.put(hit.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(miss, now).await, PutOutcome::Stored);

        let f: Filter = serde_json::from_value(serde_json::json!({"#alt": ["reply"]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, hit.id);

        // Combined with another dimension.
        let f: Filter = serde_json::from_value(serde_json::json!({
            "#alt": ["reply"], "kinds": [1]
        }))
        .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, hit.id);
    });
}

#[test]
fn delegated_events_match_delegator_queries() {
    // NIP-26: REQ with `authors: [<delegator>]` must also return events
    // published by a delegatee on the delegator's behalf.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let delegator = "a".repeat(64);
        let delegatee = "b".repeat(64);
        let mut delegated = event(1, "delegated", now, vec![]);
        delegated.pubkey = delegatee.clone();
        delegated.tags = vec![
            vec![
                "delegation".into(),
                delegator.clone(),
                "kind=1".into(),
                "00".repeat(64),
            ],
            // Only the first well-formed delegation tag is honored, so this
            // second one must not index the event under another delegator.
            vec![
                "delegation".into(),
                "c".repeat(64),
                "kind=1".into(),
                "00".repeat(64),
            ],
        ];
        delegated.id = nip01::compute_id(&delegated);
        let own = event(1, "own", now, vec![]);

        assert_eq!(db.put(delegated.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(own.clone(), now).await, PutOutcome::Stored);

        let f: Filter =
            serde_json::from_value(serde_json::json!({"authors": [delegator]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the delegated event is found");
        assert_eq!(res[0].id, delegated.id);
        // The delegatee's own key finds both its events.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"authors": [delegatee]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        // The forged second delegation tag is inert.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"authors": ["c".repeat(64)]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(
            res.is_empty(),
            "a second delegation tag must not be indexed"
        );
    });
}

#[test]
fn search_results_are_relevance_ordered() {
    // NIP-50: results are ordered by how well they match the query, and
    // the limit is applied after that ordering. Partial matches rank
    // below full matches.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Two terms matched, but older than the single-term note.
        let both = event(1, "nostr bitcoin and more", now - 100, vec![]);
        let one = event(1, "nostr only", now, vec![]);
        let none = event(1, "chess news", now, vec![]);
        assert_eq!(db.put(both.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(one.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(none.clone(), now).await, PutOutcome::Stored);

        let f: Filter =
            serde_json::from_value(serde_json::json!({"search": "nostr bitcoin"})).unwrap();
        let (res, more) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2);
        assert_eq!(
            res[0].id, both.id,
            "the note matching both terms ranks first"
        );
        assert_eq!(res[1].id, one.id, "partial matches rank below");
        assert!(!more, "both matches were delivered");
        assert!(!res.iter().any(|e| e.id == none.id));
    });
}

#[test]
fn multi_filter_search_limits_apply_per_filter() {
    // Pure-search REQs with differing per-filter limits: each filter keeps
    // its own quota in relevance order (a small limit must not starve a
    // larger one).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let a1 = event(1, "alpha one", now, vec![]);
        let a2 = event(1, "alpha two", now - 1, vec![]);
        let b1 = event(1, "beta one", now - 2, vec![]);
        for e in [&a1, &a2, &b1] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        let f: Vec<Filter> = serde_json::from_value(serde_json::json!([
            {"search": "alpha", "limit": 1},
            {"search": "beta", "limit": 2},
        ]))
        .unwrap();
        let (res, _) = db.query(f, 500, now).await;
        let contents: Vec<&str> = res.iter().map(|e| e.content.as_str()).collect();
        assert!(
            contents.contains(&"beta one"),
            "the larger second-filter quota must survive: {contents:?}"
        );
        assert_eq!(res.len(), 2, "quotas are 1 + 1 matched: {contents:?}");
    });
}

#[test]
fn search_ranks_rare_terms_higher() {
    // NIP-50 with IDF weighting: a note matching the rarer term ranks above
    // a newer note matching only the common term.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // "zebra" is rare (only the first note has it); "meetup" is common.
        let rare = event(1, "zebra meetup notes", now - 50, vec![]);
        let common = event(1, "meetup reminder", now, vec![]);
        assert_eq!(db.put(rare.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(common.clone(), now).await, PutOutcome::Stored);
        let f: Filter =
            serde_json::from_value(serde_json::json!({"search": "zebra meetup"})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2);
        assert_eq!(
            res[0].id, rare.id,
            "the rare-term match ranks first despite being older"
        );
        assert_eq!(res[1].id, common.id);
    });
}

#[test]
fn created_at_ties_are_not_split_across_pages() {
    // NIP-01 ordering / NIP-67: when the limit cuts inside a group of
    // events sharing the oldest created_at, every event at that
    // timestamp is included in the same response.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        for i in 0..5 {
            let e = event(1, &format!("tie-{i}"), now, vec![]);
            assert_eq!(db.put(e, now).await, PutOutcome::Stored);
        }
        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [1], "limit": 3})).unwrap();
        let (res, more) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 5, "all tied events are in one page");
        assert!(!more, "the tie completed the scan");
        assert!(res.windows(2).all(|w| w[0].created_at >= w[1].created_at));
    });
}

#[test]
fn tie_continuation_is_bounded() {
    // A flood of events sharing one created_at must not defeat the collector
    // cap: a `limit: 1` query stops at a small multiple of the cap and
    // reports `more` instead of materializing every tie.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        for i in 0..200 {
            let e = event(1, &format!("tie-{i}"), now, vec![]);
            assert_eq!(db.put(e, now).await, PutOutcome::Stored);
        }
        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [1], "limit": 1})).unwrap();
        let (res, more) = db.query(vec![f], 500, now).await;
        assert!(
            res.len() <= 2,
            "the tie group must be bounded by the collector cap: {}",
            res.len()
        );
        assert!(more, "a cut tie group must report `more`");
    });
    db.shutdown();
}

#[test]
fn multi_author_limit_applies_to_the_union() {
    // NIP-01: `{"authors": [A, B], "limit": n}` returns the n newest
    // events by either author; the limit must not be consumed by the
    // first author's range alone, and older events of the other author
    // must not displace newer ones.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pub_a = "a".repeat(64);
        let pub_b = "b".repeat(64);
        let mut ea1 = event(1, "a1", now, vec![]);
        ea1.pubkey = pub_a.clone();
        ea1.id = nip01::compute_id(&ea1);
        let mut ea2 = event(1, "a2", now - 1, vec![]);
        ea2.pubkey = pub_a.clone();
        ea2.id = nip01::compute_id(&ea2);
        // B's only event is OLDER than both of A's; with limit 2 it
        // must not be returned even though B sorts after A in the
        // pubkey index.
        let mut eb1 = event(1, "b1", now - 3, vec![]);
        eb1.pubkey = pub_b.clone();
        eb1.id = nip01::compute_id(&eb1);
        for e in [&ea1, &ea2, &eb1] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        let f: Filter = serde_json::from_value(serde_json::json!({
            "authors": [pub_a, pub_b], "limit": 2
        }))
        .unwrap();
        let (res, more) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2, "the two newest events are returned");
        assert_eq!(res[0].id, ea1.id);
        assert_eq!(res[1].id, ea2.id, "older B event must not displace A2");
        assert!(more, "B's older event was cut");
    });
}

#[test]
fn expiration_does_not_affect_ephemeral_events() {
    // NIP-40: "An expiration timestamp does not affect storage of
    // ephemeral events": an ephemeral event with a past expiration is
    // still handled as ephemeral (delivered live, never stored).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ev = event(
            21059,
            "ephemeral wrap",
            now,
            vec![vec!["expiration".into(), (now - 50).to_string()]],
        );
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Ephemeral);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [21059]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty(), "ephemeral events are never stored");
    });
}

#[test]

// ----- negentropy and counting (NIP-77/45) -----
fn neg_items_carry_visibility_flags() {
    // NIP-70/NIP-29: the negentropy items carry the protected flag and
    // the group id so the connection layer can mirror the REQ path's
    // visibility rules.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let protected = event(1, "protected", now, vec![vec!["-".into()]]);
        let grouped = event(1, "grouped", now - 1, vec![vec!["h".into(), "g1".into()]]);
        let plain = event(1, "plain", now - 2, vec![]);
        for e in [&protected, &grouped, &plain] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (items, _) = db.neg_items_reported(f, 100, now).await.unwrap_or_default();
        let by_id = |id: &str| items.iter().find(|i| hex::encode(i.id) == id).unwrap();
        assert!(by_id(&protected.id).protected, "protected flag set");
        assert!(
            !by_id(&plain.id).protected,
            "plain events are not protected"
        );
        assert_eq!(
            by_id(&grouped.id).gid.as_deref(),
            Some("g1"),
            "group id captured"
        );
        assert!(
            !by_id(&grouped.id).meta,
            "regular group events are not metadata"
        );
        assert!(
            by_id(&plain.id).wrap_recipients.is_none(),
            "non-gift-wraps carry no recipients"
        );
    });
}

#[test]
fn neg_items_carry_nip78_flag() {
    // NIP-78: the negentropy items carry the publisher pubkey and an
    // app-specific flag so a gated relay can withhold them from
    // unauthenticated peers during sync.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let app = event(30078, "app", now, vec![vec!["d".into(), "profile".into()]]);
        let plain = event(1, "plain", now - 1, vec![]);
        for e in [&app, &plain] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1, 30078]})).unwrap();
        let (items, _) = db.neg_items_reported(f, 100, now).await.unwrap_or_default();
        let by_id = |id: &str| items.iter().find(|i| hex::encode(i.id) == id).unwrap();
        assert!(by_id(&app.id).app_specific, "app-specific flag set");
        assert_eq!(
            by_id(&app.id).pubkey,
            app.pubkey,
            "publisher pubkey captured"
        );
        assert!(
            !by_id(&plain.id).app_specific,
            "plain events are not app-specific"
        );
    });
}

#[test]
fn count_stops_exactly_at_the_cap() {
    // NIP-45: the relay's count limit cuts exactly — the created_at
    // boundary continuation of the REQ path (NIP-67) must not inflate
    // the count beyond the cap or hide the `approximate` flag.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // All events share one created_at so the boundary continuation
        // would previously collect every one of them.
        for i in 0..7 {
            let e = event(
                7,
                &format!("r-{i}"),
                now,
                vec![vec!["e".into(), "t".repeat(64)]],
            );
            assert_eq!(db.put(e, now).await, PutOutcome::Stored);
        }
        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [7], "#e": ["t".repeat(64)]}))
                .unwrap();
        let (events, more) = db.count_reported(vec![f], 5, now).await.unwrap_or_default();
        assert_eq!(events.len(), 5, "the cap cuts exactly");
        assert!(more, "the capped scan is flagged as approximate");
    });
}

#[test]

// ----- replaceable d-tag semantics -----
fn replaceable_kinds_ignore_the_d_tag() {
    // NIP-01: kind 0/3/10000-19999 are replaced per (pubkey, kind) —
    // a `d` tag must not create a separate slot that keeps old versions
    // alive.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let d = vec![vec!["d".to_string(), "weird".to_string()]];
        let v1 = event(0, "{\"name\":\"old\"}", now, d.clone());
        let v2 = event(0, "{\"name\":\"new\"}", now + 5, vec![]);
        assert_eq!(db.put(v1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(
            db.put(v2.clone(), now).await,
            PutOutcome::Replaced,
            "the d-tagged kind 0 must be replaced by the plain one"
        );
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [0]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "only the latest kind 0 is stored");
        assert_eq!(res[0].id, v2.id);
    });
}

#[test]

// ----- overload protection -----
fn reader_requests_survive_a_writer_backlog() {
    // The dedicated reader threads exist so reads keep working while the
    // writer is stalled: a full writer queue must not fail-fast a query.
    let db = DbClient::open(&config(), true, Arc::new(Default::default()), 0, 128, 4, 8).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        db.put(event(1, "stored", now, vec![]), now).await;
        // Simulate a deep writer queue.
        db.pending_msgs
            .store(4, std::sync::atomic::Ordering::Relaxed);
        db.pending_events
            .store(8, std::sync::atomic::Ordering::Relaxed);
        let (res, _) = db
            .query(
                vec![serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap()],
                10,
                now,
            )
            .await;
        assert_eq!(res.len(), 1, "reads must not fail-fast on a write backlog");
        db.shutdown();
    });
}

#[test]
fn reported_reads_survive_a_writer_backlog() {
    // `request_read_result` (REQ/COUNT/NEG reporting paths) must use the
    // reader-queue accounting: a saturated writer queue must neither
    // fail-fast them nor leak the writer counter on completion.
    let db = DbClient::open(&config(), true, Arc::new(Default::default()), 0, 128, 4, 8).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        db.put(event(1, "stored", now, vec![]), now).await;
        // The put's reply can arrive before the writer drain releases its
        // accounting (reply-then-drop ordering): wait for the counters to
        // settle before fabricating the backlog, or the late release races
        // the fabricated values (flaky on slow/heavily loaded schedulers).
        // A bounded wait with a loud failure: never settling would itself
        // signal a real accounting leak.
        let start = std::time::Instant::now();
        loop {
            let settled = db.pending_msgs.load(std::sync::atomic::Ordering::Relaxed) == 0
                && db.pending_events.load(std::sync::atomic::Ordering::Relaxed) == 0;
            if settled {
                break;
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "writer accounting never settled after put"
            );
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        db.pending_msgs
            .store(4, std::sync::atomic::Ordering::Relaxed);
        db.pending_events
            .store(8, std::sync::atomic::Ordering::Relaxed);
        let res = db
            .query_req_reported(
                vec![serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap()],
                10,
                now,
            )
            .await;
        assert!(
            res.is_some(),
            "reporting reads must not fail-fast on a write backlog"
        );
        assert_eq!(res.unwrap().0.len(), 1);
        // The writer counter is untouched by the reporting read (no leak).
        assert_eq!(
            db.pending_msgs.load(std::sync::atomic::Ordering::Relaxed),
            4,
            "reporting reads must not touch the writer counter"
        );
        db.pending_msgs
            .store(0, std::sync::atomic::Ordering::Relaxed);
        db.pending_events
            .store(0, std::sync::atomic::Ordering::Relaxed);
        db.shutdown();
    });
}

#[test]
fn removal_of_overlong_tag_index_skips_without_poisoning() {
    // Put skips over-long index keys instead of aborting; removal must
    // mirror that, or deleting one pathological event would poison the
    // whole write batch (`Invalid(database error)` for everyone).
    let db = DbClient::open(&config(), true, Arc::new(Default::default()), 0, 128, 4, 8).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        let big = "v".repeat(600);
        let ev = event(1, "big", now, vec![vec!["t".into(), big]]);
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        assert_eq!(
            db.apply_deletion(vec![ev.id.clone()], vec![], None, now)
                .await,
            1,
            "deleting an event with an over-long tag value must succeed"
        );
        let ev2 = event(1, "after", now, vec![]);
        assert_eq!(
            db.put(ev2.clone(), now).await,
            PutOutcome::Stored,
            "the batch must not be poisoned by the removal"
        );
        db.shutdown();
    });
}

#[test]
fn read_flood_does_not_fail_fast_writes() {
    // Reads are counted separately (`pending_reads`): a REQ flood must not
    // trip the writer fail-fast gate.
    let db = DbClient::open(&config(), true, Arc::new(Default::default()), 0, 128, 4, 8).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        db.pending_reads
            .store(1000, std::sync::atomic::Ordering::Relaxed);
        let out = db.put(event(1, "w", now, vec![]), now).await;
        assert!(
            matches!(out, PutOutcome::Stored),
            "writes must survive a read backlog: {out:?}"
        );
        db.shutdown();
    });
}

#[test]
fn aggregate_sample_serves_through_the_api_reader() {
    let db = DbClient::open(&config(), true, Arc::new(Default::default()), 0, 128, 4, 8).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        db.put(event(1, "a", now, vec![]), now).await;
        db.put(event(7, "b", now, vec![]), now).await;
        let (items, _) = db.api_neg_sample(100, now).await.expect("sample");
        assert!(
            items.iter().any(|i| i.kind == 1) && items.iter().any(|i| i.kind == 7),
            "the sample must include the stored events"
        );
        assert!(
            items.iter().any(|i| i.pubkey.starts_with("0000")),
            "sample records carry the author pubkey"
        );
        db.shutdown();
        // After shutdown the API reader is gone: None, never a hang.
        assert!(db.api_neg_sample(10, now).await.is_none());
    });
}

#[test]
fn request_fails_fast_when_the_queue_is_full() {
    // Overload protection: with a full queue, new requests fail fast
    // instead of accumulating in memory, and the overload is surfaced
    // in the stats error counter.
    let errors = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let db = DbClient::open(&config(), true, Arc::clone(&errors), 0, 128, 4, 8).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        let ev = event(1, "x", now, vec![]);
        // Simulate a full queue: the message cap is exceeded.
        db.pending_msgs
            .store(4, std::sync::atomic::Ordering::Relaxed);
        let out = db.put(ev.clone(), now).await;
        assert!(
            matches!(out, PutOutcome::Invalid(_)),
            "must fail fast when the queue is full: {out:?}"
        );
        assert_eq!(errors.load(std::sync::atomic::Ordering::Relaxed), 1);
        // The event cap is also enforced.
        db.pending_msgs
            .store(0, std::sync::atomic::Ordering::Relaxed);
        db.pending_events
            .store(8, std::sync::atomic::Ordering::Relaxed);
        let out = db.put(ev, now).await;
        assert!(matches!(out, PutOutcome::Invalid(_)));
        // With the queue drained, requests are served again.
        db.pending_events
            .store(0, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            db.put(event(1, "y", now, vec![]), now).await,
            PutOutcome::Stored
        );
    });
}

#[test]
fn search_works_without_word_index() {
    // NIP-50 must work even when database.search_index is disabled: the
    // relay falls back to a full scan with content term checks.
    let cfg = DatabaseConfig {
        search_index: false,
        ..config()
    };
    let db = DbClient::open(
        &cfg,
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let hit = event(1, "rust is great", now, vec![]);
        let miss = event(1, "bitcoin only", now, vec![]);
        assert_eq!(db.put(hit.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(miss, now).await, PutOutcome::Stored);

        let f: Filter = serde_json::from_value(serde_json::json!({"search": "rust"})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, hit.id);

        // Combined with other filter dimensions.
        let f: Filter = serde_json::from_value(serde_json::json!({
            "search": "rust", "kinds": [1], "since": now
        }))
        .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
    });
}

#[test]
fn meta_index_disabled_skips_rebuild_and_keeps_scans_working() {
    // database.meta_index = false must (a) not write the metadata header,
    // (b) not trigger the startup rebuild, and (c) keep the scan working
    // through the full-parse fallback.
    let cfg = DatabaseConfig {
        meta_index: false,
        ..config()
    };
    let db = DbClient::open(
        &cfg,
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let stored = event(1, "meta disabled", now, vec![]);
        assert_eq!(db.put(stored.clone(), now).await, PutOutcome::Stored);

        // The scan must find the event via the full-parse fallback.
        let f: Filter = serde_json::from_value(serde_json::json!({
            "kinds": [1], "since": now, "until": now + 1
        }))
        .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, stored.id);
        db.shutdown();
    });
}

#[test]
fn query_directed_ascending() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let e1 = event(1, "first", now - 200, vec![]);
        let e2 = event(1, "second", now - 100, vec![]);
        let e3 = event(1, "third", now, vec![]);
        for e in [&e1, &e2, &e3] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }

        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (desc, _) = db.query_directed(vec![f.clone()], 500, now, false, 0).await;
        let ids: Vec<_> = desc.iter().map(|e| e.created_at).collect();
        assert_eq!(ids, vec![now, now - 100, now - 200]);

        let (asc, _) = db.query_directed(vec![f], 500, now, true, 0).await;
        let ids: Vec<_> = asc.iter().map(|e| e.created_at).collect();
        assert_eq!(ids, vec![now - 200, now - 100, now]);

        // Ascending limit keeps the oldest events.
        let (asc2, more) = db
            .query_directed(
                vec![serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap()],
                2,
                now,
                true,
                0,
            )
            .await;
        let ids: Vec<_> = asc2.iter().map(|e| e.created_at).collect();
        assert_eq!(ids, vec![now - 200, now - 100]);
        assert!(more);
    });
}

#[test]
fn deleted_replaceable_can_be_re_published() {
    // Regression: remove_event must clear the replaceable slot, otherwise an
    // NIP-09-deleted replaceable event could not be re-published with an
    // older created_at (the stale slot would win the tie-break).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pk = "0000000000000000000000000000000000000000000000000000000000000000";
        let d = vec![vec!["d".to_string(), "post-1".to_string()]];
        let v1 = event(30023, "v1", now - 10, d.clone());
        let v2 = event(30023, "v2", now, d.clone());
        assert_eq!(db.put(v1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(v2.clone(), now).await, PutOutcome::Replaced);
        // Deleting v2 removes it but must also clear the replaceable slot.
        assert_eq!(
            db.apply_deletion(vec![v2.id.clone()], vec![], Some(pk.into()), u64::MAX)
                .await,
            1
        );
        // Re-publishing the older version is now accepted again.
        assert_eq!(
            db.put(v1.clone(), now).await,
            PutOutcome::Stored,
            "the older version must be storable after the deletion"
        );
    });
}

#[test]
fn purged_replaceable_can_be_re_published() {
    // Regression: the NIP-40 purge of an expired addressable event must
    // clear its replaceable slot, otherwise the stale entry would keep
    // rejecting an older re-publication.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let d = vec![vec!["d".to_string(), "post-1".to_string()]];
        let v1 = event(30023, "v1", now - 10, d.clone());
        let mut v2 = event(30023, "v2", now, d.clone());
        // Expires shortly after storage, so it is storable first.
        v2.tags
            .push(vec!["expiration".into(), (now + 5).to_string()]);
        assert_eq!(db.put(v1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(v2.clone(), now).await, PutOutcome::Replaced);
        // Later, the purge removes v2 and must clear the slot.
        assert_eq!(db.purge_expired(now + 10).await, 1);
        assert_eq!(
            db.put(v1.clone(), now).await,
            PutOutcome::Stored,
            "the older version must be storable after the purge"
        );
    });
}

#[test]
fn neg_items_carry_gift_wrap_recipients() {
    // NIP-59: negentropy records of gift wraps must carry their recipients
    // so the connection layer can withhold them from anyone else.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let recipient = "b83130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
        let wrap = event(
            1059,
            "encrypted",
            now,
            vec![vec!["p".into(), recipient.into()]],
        );
        let plain = event(1, "plain", now, vec![]);
        assert_eq!(db.put(wrap.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(plain.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1, 1059]})).unwrap();
        let (items, _) = db.neg_items_reported(f, 100, now).await.unwrap_or_default();
        let wrap_item = items.iter().find(|i| hex::encode(i.id) == wrap.id).unwrap();
        assert_eq!(
            wrap_item.wrap_recipients.as_deref(),
            Some(&[recipient.to_string()][..])
        );
        let plain_item = items
            .iter()
            .find(|i| hex::encode(i.id) == plain.id)
            .unwrap();
        assert!(plain_item.wrap_recipients.is_none());
    });
}

#[test]
fn api_query_uses_dedicated_reader_and_stays_healthy() {
    // The REST API queries must be served by their own reader thread and
    // keep working across many calls: `api_pending` must not leak or wrap
    // (a double-decrement bug would break every subsequent call).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        for i in 0..64 {
            let ev = event(1, &format!("api-{i}"), now - i, vec![]);
            assert_eq!(db.put(ev, now).await, PutOutcome::Stored);
        }

        // Repeated queries must all succeed (regression: the counter was
        // decremented twice, breaking the API after the first request).
        for i in 0..16 {
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
            let (res, _) = db.api_query(vec![f], 500, now, false).await;
            assert_eq!(res.len(), 64, "api query {i} must return all events");
        }

        // The WebSocket query path is unaffected by API traffic.
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 64);
    });
}

#[test]
fn api_count_serves_aggregations_and_stays_healthy() {
    // `api_count` (REST API aggregations: monthly/daily/hourly and the
    // count endpoints) must be served by the dedicated API reader thread
    // with the same fail-fast cap as `api_query`, and the pending counter
    // must not leak.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        for i in 0..32 {
            let ev = event(1, &format!("agg-{i}"), now - i, vec![]);
            assert_eq!(db.put(ev, now).await, PutOutcome::Stored);
        }
        let kinds1: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let kinds2: Filter = serde_json::from_value(serde_json::json!({"kinds": [2]})).unwrap();

        // Success path: matching events are returned with the `more` flag.
        let (events, more) = db.api_count(vec![kinds1.clone()], 2000, now).await;
        assert_eq!(events.len(), 32, "api_count must return the matches");
        assert!(!more);
        // Empty path: no matching events.
        let (events, more) = db.api_count(vec![kinds2.clone()], 2000, now).await;
        assert!(events.is_empty());
        assert!(!more);
        // The shared-reader WebSocket path is unaffected by API traffic.
        let (events, _) = db.query(vec![kinds1.clone()], 500, now).await;
        assert_eq!(events.len(), 32);
    });
    // The request-timeout path (timeout_secs > 0) still serves the result.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        30,
        128,
        4096,
        262144,
    )
    .unwrap();
    rt.block_on(async {
        let kinds1: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (events, _) = db.api_count(vec![kinds1], 2000, unix_now()).await;
        assert!(events.is_empty());
    });
    db.shutdown();
}

#[test]
fn api_count_fails_fast_under_queue_pressure_and_after_shutdown() {
    // `max_api_pending` follows `max_pending_msgs` (min 1): when the
    // pending counter is at the cap, aggregations must fail fast instead
    // of queueing behind each other, and the counter must recover for
    // later calls.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        2, // max_pending_msgs = 2 -> max_api_pending = 2 (writes still work)
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        for i in 0..8 {
            let ev = event(1, &format!("agg-{i}"), now - i, vec![]);
            assert_eq!(db.put(ev, now).await, PutOutcome::Stored);
        }
        let kinds1: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        // Deterministic fail-fast: the pending counter is at the cap, so
        // the next aggregation must be refused without reaching the queue.
        db.api_pending
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        let (events, more) = db.api_count(vec![kinds1.clone()], 2000, now).await;
        assert!(
            events.is_empty() && !more,
            "an aggregation at the pending cap must fail fast"
        );
        db.api_pending
            .fetch_sub(2, std::sync::atomic::Ordering::Relaxed);

        // Concurrent aggregations against a cap of one in-flight request:
        // some may be served and the rest fail fast — whichever happens,
        // the counter must not leak (the later call below is served
        // normally).
        let mut futures = Vec::new();
        for _ in 0..16 {
            let kinds1 = kinds1.clone();
            let db = db.clone();
            futures.push(tokio::spawn(async move {
                db.api_count(vec![kinds1], 2000, now).await
            }));
        }
        for f in futures {
            let (events, _) = f.await.unwrap();
            assert_eq!(
                events.len() % 8,
                0,
                "a served aggregation returns all matches; a failed one returns none"
            );
        }
        // The counter recovers: a later call is served normally.
        let (events, _) = db.api_count(vec![kinds1.clone()], 2000, now).await;
        assert_eq!(events.len(), 8, "api_count must recover after fail-fast");
        // The WebSocket path is unaffected.
        let (events, _) = db.query(vec![kinds1.clone()], 500, now).await;
        assert_eq!(events.len(), 8);

        // After shutdown the channel is closed: api_count must return an
        // empty result instead of panicking.
        db.shutdown();
        let (events, more) = db.api_count(vec![kinds1.clone()], 2000, now).await;
        assert!(events.is_empty());
        assert!(!more);
    });
}

#[test]
fn mixed_search_and_plain_filters_return_the_union() {
    // Regression: a REQ mixing a search filter and a plain filter must
    // return the union of both (each with its own limit), not a response
    // truncated to the search filters' limits — the old code applied the
    // global relevance truncation to the whole output, silently dropping
    // every plain-filter result.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let hit = event(1, "needle in a haystack", now, vec![]);
        let plain1 = event(1, "plain one", now - 1, vec![]);
        let plain2 = event(1, "plain two", now - 2, vec![]);
        for ev in [&hit, &plain1, &plain2] {
            assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        }

        let f: Vec<Filter> = serde_json::from_value(serde_json::json!([
            {"search": "needle", "limit": 1},
            {"kinds": [1], "limit": 2}
        ]))
        .unwrap();
        let (res, _) = db.query(f, 500, now).await;
        // The old code truncated the whole response to the search filters'
        // limits, dropping every plain-filter result (only the hit would
        // come back). Each filter now has its own quota: the search filter
        // contributes the hit and the plain filter its two events.
        assert_eq!(res.len(), 3, "search hit plus the plain events");
        let ids: Vec<String> = res.iter().map(|e| e.id.clone()).collect();
        assert!(ids.contains(&hit.id));
        assert!(ids.contains(&plain1.id));
        assert!(ids.contains(&plain2.id));
    });
}

#[test]
fn long_dtags_do_not_collide_in_the_replaceable_index() {
    // Regression: two addressable events whose long `d` tags share the
    // same prefix used to collide in the replaceable index (both truncated
    // to the same key), making one replace the other. The index key now
    // carries a fingerprint of the full value.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let d1 = format!("{}x", "a".repeat(600));
        let d2 = format!("{}y", "a".repeat(600));
        let e1 = event(30023, "one", now, vec![vec!["d".into(), d1.clone()]]);
        let e2 = event(30023, "two", now, vec![vec!["d".into(), d2.clone()]]);
        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(
            db.put(e2.clone(), now).await,
            PutOutcome::Stored,
            "a distinct long d tag must not be replaced by its prefix twin"
        );

        // Both events are individually addressable: querying each address
        // returns its own version.
        for (d, content) in [(&d1, "one"), (&d2, "two")] {
            let f: Filter = serde_json::from_value(serde_json::json!({
                "kinds": [30023],
                "authors": ["0000000000000000000000000000000000000000000000000000000000000000"],
                "#d": [d]
            }))
            .unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1, "address {d:?} must resolve uniquely");
            assert_eq!(res[0].content, content);
        }
    });
}

#[test]
fn unknown_filter_keys_are_ignored_by_the_scan() {
    // Regression: a filter carrying an unknown non-`#` key (e.g. a typo'd
    // `"kind"`) must not silently return zero events — the key is ignored
    // and the remaining constraints apply.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let e1 = event(1, "one", now, vec![vec!["t".into(), "rust".into()]]);
        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);

        let f: Filter =
            serde_json::from_value(serde_json::json!({"kind": [1], "kinds": [1]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the unknown `kind` key must be ignored");

        let f: Filter = serde_json::from_value(serde_json::json!({"foo": "bar"})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "a filter with only unknown keys matches all");

        // A `#`-prefixed constraint still applies.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"foo": 1, "#t": ["go"]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 0);
    });
}

#[test]
fn search_finds_big_events() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let content = format!("needle-{}", "z".repeat(300_000));
        let e = event(1, &content, now, vec![]);
        assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"search": "needle"})).unwrap();
        let (res, _) = db.query(vec![f.clone()], 500, now).await;
        assert_eq!(res.len(), 1, "search must find the 300KB event");
        let (res2, _) = db.query_req(vec![f], 500, now).await;
        assert_eq!(res2.len(), 1);
    });
}

#[test]
fn search_finds_words_past_the_index_cap() {
    // NIP-50 searches the whole content, but the word index only stores the
    // first `max_indexed_words` tokens; an event whose matching word comes
    // later must still be found (long events carry an overflow marker that
    // the scan walks with a full-content check).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        2, // max_indexed_words: only "early" and "fills" are indexed
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ev = event(1, "early fills the cap late", now, vec![]);
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        // A word past the index cap is found via the overflow walk.
        let f: Filter = serde_json::from_value(serde_json::json!({"search": "late"})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(
            res.len(),
            1,
            "a word past the index cap must still be found"
        );
        assert_eq!(res[0].id, ev.id);
        // The indexed prefix still works.
        let f: Filter = serde_json::from_value(serde_json::json!({"search": "early"})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
        // Removal drops the overflow marker too.
        db.apply_deletion(vec![ev.id.clone()], vec![], Some(ev.pubkey.clone()), now)
            .await;
        let f: Filter = serde_json::from_value(serde_json::json!({"search": "late"})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(
            res.is_empty(),
            "the overflow index entry must be removed with the event"
        );
    });
    db.shutdown();
}

#[test]
fn startup_loads_bypass_fail_fast_and_timeout() {
    // The startup loads must not silently degrade to empty when the
    // queue is (momentarily) full or the reader is slow: an empty deny
    // list would lift every persisted ban (fail-open). The blocking
    // loads bypass the fail-fast threshold entirely (the passed cap is
    // clamped to a minimum of 1 server-side) and still load the lists.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        0, // max_pending_msgs = 0 → every limited request fails fast
        262144,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        db.save_relay_pubkeys(&[("aa".repeat(32), "test".into())], &[])
            .await;
        let (deny, _) = db.load_relay_pubkeys().await.unwrap_or_default();
        assert_eq!(
            deny.len(),
            1,
            "the blocking startup load must not fail fast"
        );
        let allow = db.load_blossom_allow().await;
        assert!(
            allow.unwrap_or_default().is_empty(),
            "no blossom allowlist persisted"
        );
        db.shutdown();
    });
}

#[test]
fn reload_loads_report_failure() {
    // The SIGHUP reloads report None instead of degrading: the caller
    // keeps the previous lists. After the reader thread is gone, the
    // requests cannot be served and must be reported as failed.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        db.shutdown();
        assert!(
            db.try_load_relay_pubkeys().await.is_none(),
            "a failed reload must be reported as None"
        );
        assert!(
            db.try_load_blossom_allow().await.is_none(),
            "a failed reload must be reported as None"
        );
    });
}

#[test]
fn reload_loads_report_success() {
    // A healthy client returns the persisted lists.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        db.save_relay_pubkeys(&[("bb".repeat(32), "test".into())], &[])
            .await;
        db.save_access(crate::config::AccessControl {
            restrict_relay: true,
            ..Default::default()
        })
        .await;
        let (deny, _) = db.try_load_relay_pubkeys().await.expect("loads");
        assert_eq!(deny.len(), 1);
        let allow = db.try_load_blossom_allow().await.expect("loads");
        assert!(allow.is_empty());
        db.shutdown();
    });
}

#[test]
fn event_meta_roundtrips_and_prefilters() {
    use crate::db::store::{META_LEN, decode_meta, encode_meta};
    // Header roundtrip.
    let pubkey = [0x42u8; 32];
    let header = encode_meta(30001, 1_600_000_000, &pubkey, 0);
    assert_eq!(header.len(), META_LEN);
    let (kind, created, pk, exp) = decode_meta(&header).unwrap();
    assert_eq!((kind, created, exp), (30001, 1_600_000_000, 0));
    assert_eq!(pk, pubkey);
    assert!(decode_meta(&header[..META_LEN - 1]).is_none());
    // The scan stores the meta alongside the event and a query whose
    // kinds do not match is answered without the event.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let e = event(30001, "meta test", now, vec![]);
        assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [30001]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert_eq!(res.len(), 1);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert!(res.is_empty(), "kind mismatch must reject via the header");
        db.shutdown();
    });
}

#[test]
fn event_meta_rebuilds_from_stored_events() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let store = crate::db::store::Store::open(&config(), expiry, 128).unwrap();
        let _db = store.clone_for_reader();
        let now = unix_now();
        let mut ev = event(1, "rebuild", now, vec![]);
        let id = ev.id_bytes().unwrap();
        // Seed the store directly (the writer thread is not running).
        let mut wtxn = store.env.write_txn().unwrap();
        let raw = serde_json::to_vec(&ev).unwrap();
        store.events.put(&mut wtxn, &id, &raw).unwrap();
        store
            .by_created
            .put(&mut wtxn, &crate::db::store::created_key(now, &id), b"")
            .unwrap();
        wtxn.commit().unwrap();
        ev.id = hex::encode(id);
        // The meta index is empty: a rebuild must fill it.
        assert!(store.meta_needs_rebuild().unwrap());
        let count = store.rebuild_event_meta().unwrap();
        assert_eq!(count, 1);
        assert!(!store.meta_needs_rebuild().unwrap());
        let meta = store.event_meta.unwrap();
        let rtxn = store.env.read_txn().unwrap();
        let raw = meta.get(&rtxn, &id).unwrap().unwrap();
        let (kind, created, _, _) = crate::db::store::decode_meta(raw).unwrap();
        assert_eq!(kind, 1);
        assert_eq!(created, now);
    });
}

#[test]
fn removing_corrupt_event_cleans_primary_indexes() {
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = crate::db::store::Store::open(&config(), expiry, 128).unwrap();
    let id = [7u8; 32];
    let created = 1_700_000_000;
    let mut wtxn = store.env.write_txn().unwrap();
    store.events.put(&mut wtxn, &id, b"{not-json").unwrap();
    store
        .by_created
        .put(&mut wtxn, &crate::db::store::created_key(created, &id), b"")
        .unwrap();
    wtxn.commit().unwrap();

    let mut wtxn = store.env.write_txn().unwrap();
    store.remove_event(&mut wtxn, &id).unwrap();
    wtxn.commit().unwrap();

    let rtxn = store.env.read_txn().unwrap();
    assert!(store.events.get(&rtxn, &id).unwrap().is_none());
    assert!(
        store
            .by_created
            .get(&rtxn, &crate::db::store::created_key(created, &id))
            .unwrap()
            .is_none()
    );
}

#[test]
fn group_and_role_snapshots_survive_restart() {
    // NIP-29/43 state must survive restarts without replaying history:
    // persist a snapshot, then load + restore it into fresh stores.
    let db = DbClient::open(&config(), true, Arc::new(Default::default()), 0, 128, 4, 8).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // No snapshot on a fresh database: the caller must migrate.
        assert!(db.load_groups().await.is_none());
        assert!(db.load_roles().await.is_none());

        let mut groups = crate::nips::nip29::GroupStore::with_cap(100);
        let now = unix_now();
        let create = crate::nips::nip29::tests::event(
            crate::nips::nip29::CREATE_GROUP,
            crate::nips::nip29::tests::ADMIN,
            Some("g1"),
            vec![],
        );
        groups.apply(&create, "relay", now, false, false);
        db.save_groups(groups.snapshot()).await;
        let mut restored = crate::nips::nip29::GroupStore::with_cap(7);
        restored.restore(db.load_groups().await.expect("snapshot"));
        assert!(restored.group("g1").is_some(), "groups must restore");
        // The capacity cap comes from the config, not the snapshot.
        assert!(
            restored
                .group("g1")
                .unwrap()
                .is_admin(crate::nips::nip29::tests::ADMIN)
        );

        let mut roles = crate::nips::nip43::RoleStore::default();
        roles.create("mod", "Mod", "", "", None);
        roles.assign(crate::nips::nip29::tests::USER, "mod");
        db.save_roles(roles.snapshot()).await;
        let mut restored_roles = crate::nips::nip43::RoleStore::default();
        restored_roles.restore(db.load_roles().await.expect("snapshot"));
        assert!(
            restored_roles.is_member_of(crate::nips::nip29::tests::USER),
            "roles must restore"
        );
        db.shutdown();
    });
}

#[test]
fn sixteen_max_dbs_still_opens_with_the_word_index() {
    // 17 named tables are created (16 plus the word index); an operator
    // value of 16 must not fail at startup (the clamp raises it to 17).
    let mut cfg = config();
    cfg.max_dbs = 16;
    assert!(cfg.search_index);
    let db = DbClient::open(
        &cfg,
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .expect("17 tables must fit via the clamp");
    db.shutdown();
}
