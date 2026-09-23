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
        max_map_size: 64 * 1024 * 1024,
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
fn tag_filter_with_until_bounds_the_range() {
    // Regression: the indexed `#tag` walk built its exclusive upper bound
    // with `end[..prefix_len + CREATED_LEN].copy_from_slice(..)`, whose
    // destination is the whole (prefix-sized) buffer: any tag filter with
    // an explicit `until` panicked the reader thread instead of scanning.
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
        for (content, created_at) in [("old", now - 100), ("mid", now - 50), ("new", now)] {
            let e = event(
                1,
                content,
                created_at,
                vec![vec!["t".into(), "rust".into()]],
            );
            assert_eq!(db.put(e, now).await, PutOutcome::Stored);
        }
        let f: Filter =
            serde_json::from_value(serde_json::json!({"#t": ["rust"], "until": now - 60})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "only the pre-`until` event matches");
        assert_eq!(res[0].content, "old");

        let f: Filter = serde_json::from_value(
            serde_json::json!({"#t": ["rust"], "since": now - 60, "until": now - 1}),
        )
        .unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the bounded window selects the middle event");
        assert_eq!(res[0].content, "mid");

        let f: Filter =
            serde_json::from_value(serde_json::json!({"#t": ["rust"], "since": now - 50})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2, "the open upper bound keeps both newer events");
    });
    db.shutdown();
}

#[test]
fn tag_range_never_panics_on_boundary_inputs() {
    // The `tag_range` byte-slicing once panicked on an explicit `until`
    // (wrong slice target); fuzz the boundary matrix directly so the
    // slicing stays total: empty/huge values, maximal timestamps and
    // inverted windows must all produce well-formed bounds.
    use crate::db::store::tag_range;
    let values: Vec<Vec<u8>> = vec![vec![], vec![b'x'], vec![0xff; 8], vec![0u8; 65535]];
    let bounds = [0u64, 1, 100, u64::MAX - 1, u64::MAX];
    for name in [b'e', 0u8, 0xff] {
        for value in &values {
            for &since in &bounds {
                for &until in &bounds {
                    let (start, end) = tag_range(name, value, since, until);
                    let prefix_len = 1 + 1 + 4 + value.len();
                    assert_eq!(
                        &start[..prefix_len],
                        &end[..prefix_len],
                        "both bounds share the tag prefix"
                    );
                    assert_eq!(start.len(), prefix_len + 8 + 32);
                    assert!(
                        end.len() == prefix_len + 8 + 32 || end.len() == prefix_len + 8 + 32 + 1,
                        "the maximal `until` appends one byte past the maximal id"
                    );
                    if since <= until {
                        assert!(start <= end, "a non-empty window must stay ordered");
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn database_dir_lock_is_exclusive() {
    // A second relay on the same `database.path` (a different pid file or
    // port defeats the pid/port gate) must fail fast instead of running a
    // split-brain second writer thread.
    let cfg = config();
    let _first = crate::db::lock_database_dir(&cfg.path).expect("the first holder takes the lock");
    assert!(
        crate::db::lock_database_dir(&cfg.path).is_err(),
        "a second lock on the same database directory must fail"
    );
}

#[test]
fn count_at_the_exact_cap_is_not_approximate() {
    // A walk that exhausts exactly at the request cap is complete: only a
    // walk cut short by the cap reports `approximate`.
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
        for i in 0..3u64 {
            let e = event(1, &format!("count me {i}"), now - 10 + i, Vec::new());
            assert_eq!(db.put(e, now).await, PutOutcome::Stored);
        }
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (counted, more) = db
            .count_reported(vec![f.clone()], 3, now)
            .await
            .expect("count must not fail");
        assert_eq!(counted.len(), 3);
        assert!(!more, "an exact-cap count is complete, not approximate");
        let (counted, more) = db
            .count_reported(vec![f.clone()], 2, now)
            .await
            .expect("count must not fail");
        assert_eq!(counted.len(), 2);
        assert!(more, "a truncated count is approximate");
        let (counted, more) = db
            .count_reported(vec![f], 4, now)
            .await
            .expect("count must not fail");
        assert_eq!(counted.len(), 3);
        assert!(!more, "a below-cap count is complete");
    });
    db.shutdown();
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
        assert_eq!(
            db.apply_deletion(targets, vec![], Some(e2.pubkey.clone()), u64::MAX)
                .await,
            1
        );
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
        assert_eq!(db.purge_expired(now, 0).await, (1, false));

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
        assert_eq!(db.purge_expired(now, 0).await, (1, false));
    });
}

#[test]
fn purge_expired_reports_group_state_removals() {
    // NIP-40: removing an expired NIP-29/NIP-43 state event must tell the
    // caller to rebuild the derived state; an ordinary expired post must
    // not.
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
        let mut moderation = event(9000, "mod", now - 100, vec![]);
        moderation.tags = vec![
            vec!["h".into(), "group-exp".into()],
            vec!["expiration".into(), (now - 50).to_string()],
        ];
        let mut role = event(
            crate::nips::nip43::MEMBERSHIP_LIST,
            "members",
            now - 100,
            vec![],
        );
        role.tags = vec![vec!["expiration".into(), (now - 50).to_string()]];
        let mut post = event(1, "post", now - 100, vec![]);
        post.tags = vec![vec!["expiration".into(), (now - 50).to_string()]];
        for e in [&moderation, &role, &post] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        db.set_expiry_enabled(true);
        assert_eq!(
            db.purge_expired(now, 0).await,
            (3, true),
            "a removed NIP-29/NIP-43 state event must request a rebuild"
        );
    });
    db.shutdown();
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
fn long_d_address_deletion_keeps_the_rest_of_the_batch() {
    // A `d` tag long enough to fill LMDB's key-size limit must not make the
    // address tombstone too long: `deleted_address_key` adds an `a` prefix
    // on top of the replaceable slot key, and one byte of overflow used to
    // abort the whole deletion transaction (the sibling `e`-tag targets
    // were rolled back with it).
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
        let long_d = "d".repeat(500);
        let d_tag = vec![vec!["d".to_string(), long_d.clone()]];
        let long = event(30023, "long-d", now - 10, d_tag.clone());
        assert_eq!(db.put(long.clone(), now).await, PutOutcome::Stored);
        let sibling = event(1, "sibling", now, vec![]);
        assert_eq!(db.put(sibling.clone(), now).await, PutOutcome::Stored);

        let address = crate::nips::nip09::Address {
            kind: 30023,
            pubkey: pk.into(),
            d: long_d,
        };
        assert_eq!(
            db.apply_deletion(
                vec![sibling.id.clone()],
                vec![address],
                Some(pk.into()),
                u64::MAX,
            )
            .await,
            2,
            "both the e-tag target and the long-d address must be deleted"
        );
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1, 30023]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty(), "no target may survive the deletion");

        // The address tombstone (built with the same one-byte-shorter
        // normalization) still blocks older re-publications.
        let older = event(30023, "older", now - 20, d_tag);
        assert_eq!(db.put(older, now).await, PutOutcome::PreviouslyDeleted);
    });
    db.shutdown();
}

#[test]
fn deleted_address_key_fits_the_lmdb_limit() {
    use crate::db::store::{MAX_INDEX_KEY, deleted_address_key};
    let key = deleted_address_key(30023, &[7u8; 32], &"x".repeat(5_000));
    assert!(
        key.len() <= MAX_INDEX_KEY,
        "tombstone key is {} bytes, over the {MAX_INDEX_KEY}-byte limit",
        key.len()
    );
    assert_eq!(key[0], b'a');
    // Distinct over-long `d` tags sharing the truncation prefix stay
    // distinct through the fingerprint.
    let a = deleted_address_key(30023, &[7u8; 32], &"x".repeat(5_000));
    let b = deleted_address_key(30023, &[7u8; 32], &("x".repeat(4_999) + "y"));
    assert_ne!(a, b);
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
fn deletion_by_e_tag_ignores_the_request_timestamp() {
    // NIP-09's created_at cut applies to `a` (addressable) targets only. The
    // relay accepts events up to 3600 s in the future, so applying the cut
    // to `e` targets made a clock-skewed post undeletable while its deletion
    // was acknowledged.
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
        let skewed = event(1, "clock skewed", now + 500, vec![]);
        assert_eq!(db.put(skewed.clone(), now).await, PutOutcome::Stored);
        assert_eq!(
            db.apply_deletion(vec![skewed.id.clone()], vec![], Some(pk.into()), now)
                .await,
            1,
            "an e target is deleted regardless of its created_at"
        );
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [skewed.id]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert!(res.is_empty(), "the skewed target must be gone");
    });
    db.shutdown();
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
fn gift_wraps_with_mixed_case_p_are_deleted() {
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
        let recipient = "aB3130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
        let wrap = event(
            1059,
            "encrypted",
            now,
            vec![vec!["p".into(), recipient.into()]],
        );
        let vanish_wrap = event(
            1059,
            "encrypted for vanish",
            now + 1,
            vec![vec!["p".into(), recipient.into()]],
        );
        assert_eq!(db.put(wrap, now).await, PutOutcome::Stored);
        assert_eq!(db.put(vanish_wrap, now + 1).await, PutOutcome::Stored);
        let recipient_bytes = hex::decode(recipient).unwrap();
        let removed = db
            .delete_gift_wraps_to(recipient_bytes.clone().try_into().unwrap())
            .await;
        assert_eq!(removed, 2, "mixed-case p-tagged wraps must be found");

        let vanish_wrap = event(
            1059,
            "encrypted for vanish",
            now + 2,
            vec![vec!["p".into(), recipient.into()]],
        );
        assert_eq!(db.put(vanish_wrap, now + 2).await, PutOutcome::Stored);
        let removed = db
            .apply_vanish(recipient_bytes.try_into().unwrap(), now + 2)
            .await;
        assert_eq!(removed, 1, "vanish must find mixed-case p-tagged wraps");
    });
}

#[test]
fn vanish_wrap_purge_respects_the_request_bound() {
    // A gift wrap created after the vanish request is not part of the
    // vanished history and must survive, like the authored events the
    // by_pubkey walk already bounds.
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
        let recipient = "d83130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
        let old_wrap = event(1059, "old", now, vec![vec!["p".into(), recipient.into()]]);
        let new_wrap = event(
            1059,
            "new",
            now + 100,
            vec![vec!["p".into(), recipient.into()]],
        );
        assert_eq!(db.put(old_wrap.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(new_wrap.clone(), now).await, PutOutcome::Stored);
        let recipient_bytes = hex::decode(recipient).unwrap();
        let removed = db
            .apply_vanish(recipient_bytes.try_into().unwrap(), now)
            .await;
        assert_eq!(
            removed, 1,
            "only the wrap within the request bound is removed"
        );
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({ "ids": [new_wrap.id] })).unwrap();
        let (events, _) = db.query(vec![filter], 10, now).await;
        assert_eq!(events.len(), 1, "the later wrap must survive the vanish");
    });
    db.shutdown();
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
        let pages_before = db.last_page_now().await;
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
        // The map is a fixed upfront reservation, so assert real page
        // growth instead of comparing the constant `map_size` ceiling
        // against the initial size (which could never fail).
        assert!(
            db.last_page_now().await > pages_before,
            "the bulk writes must allocate new pages"
        );
    });
}

#[test]
fn failed_commit_revokes_every_put_in_the_batch() {
    // A commit failure (MapFull) must roll the whole batch back: every put
    // is answered Invalid, nothing becomes queryable, and the failure is
    // counted. The map floor is 16 MiB, so the test-only fault hook makes
    // the next commit fail instead of filling a real environment.
    let store = crate::db::store::Store::open(
        &config(),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        128,
    )
    .unwrap();
    let errors = Arc::new(Default::default());
    let now = 1_700_000_000u64;
    let puts: Vec<(Arc<Event>, u64)> = (0..3)
        .map(|i| (Arc::new(event(1, &format!("batch-{i}"), now, vec![])), now))
        .collect();
    let ids: Vec<[u8; 32]> = puts
        .iter()
        .map(|(e, _)| e.id_bytes().expect("valid id"))
        .collect();
    store
        .fail_next_commit
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let first_seen = vec![None; puts.len()];
    let outcomes = crate::db::store::apply_put_batch(&store, &errors, None, &puts, &first_seen);
    assert_eq!(outcomes.len(), puts.len());
    assert!(
        outcomes.iter().all(|o| matches!(o, PutOutcome::Invalid(_))),
        "every put in the failed batch must be revoked: {outcomes:?}"
    );
    let rtxn = store.env.read_txn().unwrap();
    for id in &ids {
        assert!(
            store.events.get(&rtxn, id).unwrap().is_none(),
            "a failed batch must not leave events behind"
        );
    }
    assert_eq!(
        errors.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the commit failure must be counted"
    );
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
    assert!(apply_put_batch(&store, &errors, None, &[], &[]).is_empty());
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
fn gift_wrap_deletion_refuses_an_unbuilt_index() {
    use crate::db::store::Store;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    let cfg = config();
    // A raw store: no writer recovery ever ran, so the recipient index
    // was never backfilled.
    let store = Store::open(&cfg, Arc::new(AtomicBool::new(true)), 512).unwrap();
    let recipient = [7u8; 32];
    // The range walk would silently miss every pre-index wrap, so the
    // deletion must fail loudly instead (the vanish path then skips its
    // marker and the NIP-09 path reports the failure).
    let err = store
        .delete_gift_wraps_to(&recipient, u64::MAX)
        .expect_err("an unbuilt index must fail the deletion");
    assert!(err.to_string().contains("not built"), "{err}");
    // After the backfill the same deletion succeeds (nothing stored).
    assert_eq!(store.rebuild_gift_wrap_index().unwrap(), 0);
    assert_eq!(store.delete_gift_wraps_to(&recipient, u64::MAX).unwrap(), 0);
}

#[test]
fn reader_floor_covers_nested_read_transactions() {
    // The `max_readers` floor must cover the nested read transactions some
    // paths take (`list_blossom_page` resolves each sha inside its walk
    // transaction). A configured `max_readers = 1` used to become
    // `reader_threads + 2` slots, which the nesting plus the concurrent
    // reader/API/writer paths can exhaust with MDB_READERS_FULL (surfacing
    // as silent empty scans). The floor is `2 * reader_threads + 3`.
    let mut cfg = config();
    cfg.max_readers = 1;
    cfg.reader_threads = 2;
    let store = crate::db::store::Store::open(
        &cfg,
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        512,
    )
    .unwrap();
    // Holding the full floor open at once must succeed: without the raised
    // floor the 5th (`reader_threads + 2` + 1) transaction would fail.
    let mut txns = Vec::new();
    for i in 0..(2 * cfg.reader_threads + 3) {
        txns.push(
            store
                .env
                .read_txn()
                .unwrap_or_else(|e| panic!("reader slot {i} unavailable: {e}")),
        );
    }
    assert_eq!(txns.len(), 7);
}

#[test]
fn blossom_order_index_backfills_legacy_mappings() {
    // Databases written before the uploaded-order index existed have the
    // `sha:` mappings but no order keys and no marker: the chunked rebuild
    // must recreate the index and write the marker last.
    let store = crate::db::store::Store::open(
        &config(),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        512,
    )
    .unwrap();
    let alice = "aa".repeat(32);
    let bob = "bb".repeat(32);
    let sha_a = "11".repeat(32);
    let sha_b = "22".repeat(32);
    store
        .add_blossom_mappings(&[
            (sha_a.clone(), "image/png".into(), 3, 100, alice.clone()),
            (sha_b.clone(), "image/png".into(), 5, 200, bob.clone()),
            (sha_b.clone(), "image/png".into(), 5, 200, alice.clone()),
        ])
        .unwrap();
    // Drop the order keys and the marker to simulate the pre-index layout.
    let mut wtxn = store.env.write_txn().unwrap();
    let order_keys: Vec<Vec<u8>> = store
        .blossom
        .iter(&wtxn)
        .unwrap()
        .filter_map(|item| item.ok().map(|(key, _)| key.to_vec()))
        .filter(|key| key.starts_with(b"bls:"))
        .collect();
    assert_eq!(order_keys.len(), 3);
    for key in &order_keys {
        store.blossom.delete(&mut wtxn, key).unwrap();
    }
    store
        .index_meta
        .delete(&mut wtxn, b"blossom_order")
        .unwrap();
    wtxn.commit().unwrap();

    assert!(store.blossom_order_needs_rebuild().unwrap());
    assert_eq!(store.rebuild_blossom_order().unwrap(), 3);
    assert!(!store.blossom_order_needs_rebuild().unwrap());
    // The rebuilt index serves BUD-12 paging again (newest upload first).
    let page = store.list_blossom_page(&alice, None, None, 10).unwrap();
    let shas: Vec<&str> = page.iter().map(|(sha, _)| sha.as_str()).collect();
    assert_eq!(shas, vec![sha_b.as_str(), sha_a.as_str()]);
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
        assert_eq!(db.group_purge("group-1".into(), now).await, Some(1));
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
fn purged_group_history_cannot_be_republished() {
    // NIP-29: the per-group purge marker (one record, not one tombstone per
    // purged event) blocks a re-broadcast of the purged history after the
    // id is re-created, while genuinely newer events pass.
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
        let old = event(
            1,
            "purged history",
            now - 100,
            vec![vec!["h".into(), "group-9".into()]],
        );
        let other = event(
            1,
            "other group",
            now - 100,
            vec![vec!["h".into(), "group-8".into()]],
        );
        let plain = event(1, "no group", now - 100, vec![]);
        for e in [&old, &other, &plain] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        assert_eq!(db.group_purge("group-9".into(), now).await, Some(1));
        // The purged event is gone and a re-broadcast is refused without a
        // per-event tombstone.
        assert_eq!(
            db.put(old.clone(), now).await,
            PutOutcome::PreviouslyDeleted
        );
        // Events created after the cut pass (the re-create and new posts).
        // The bound is inclusive of the purge second, so a same-second post
        // is blocked; only strictly newer events pass.
        let fresh = event(
            1,
            "after the purge",
            now + 1,
            vec![vec!["h".into(), "group-9".into()]],
        );
        assert_eq!(db.put(fresh, now + 1).await, PutOutcome::Stored);
        // Unrelated groups and untagged events are unaffected: fresh events
        // (same age range as the purged one) are still accepted.
        let other_new = event(
            1,
            "other group new",
            now - 50,
            vec![vec!["h".into(), "group-8".into()]],
        );
        let plain_new = event(1, "no group new", now - 50, vec![]);
        assert_eq!(db.put(other_new, now).await, PutOutcome::Stored);
        assert_eq!(db.put(plain_new, now).await, PutOutcome::Stored);
        // A second purge moves the cut: the previously accepted event is
        // removed and its replay is blocked too.
        assert_eq!(db.group_purge("group-9".into(), now + 1).await, Some(1));
        let fresh = event(
            1,
            "after the purge",
            now + 1,
            vec![vec!["h".into(), "group-9".into()]],
        );
        assert_eq!(db.put(fresh, now + 1).await, PutOutcome::PreviouslyDeleted);
    });
    db.shutdown();
}

#[test]
fn purge_marker_blocks_same_second_and_future_dated_replays() {
    // #121 regression: the marker used a strict `<` against the purge time,
    // so an event purged in the purge second (or a future-dated event the
    // relay accepted) could be replayed after a re-create. The cut now
    // covers every removed event's timestamp inclusively, while the
    // kind:9007 re-create compares against the purge time only.
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
        let tagged = |content: &str, created: u64, kind: u64| {
            event(
                kind,
                content,
                created,
                vec![vec!["h".into(), "group-marker".into()]],
            )
        };
        let old = tagged("old", now - 100, 1);
        let same = tagged("same second", now, 1);
        let future = tagged("future dated", now + 1_000, 1);
        for e in [&old, &same, &future] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        assert_eq!(db.group_purge("group-marker".into(), now).await, Some(3));

        // Every removed generation is rejected on replay: older, same
        // second and future dated alike.
        for e in [&old, &same, &future] {
            assert_eq!(
                db.put(e.clone(), now).await,
                PutOutcome::PreviouslyDeleted,
                "a purged event must not be replayable"
            );
        }
        // A re-create at the purge second passes even though the
        // future-dated removed event pushed the cut past it.
        let recreate = tagged("re-create", now, 9007);
        assert_eq!(db.put(recreate, now).await, PutOutcome::Stored);
        // A post between the purge and the removed future event is blocked
        // by the raised cut; one past it passes.
        let inside = tagged("inside the cut", now + 500, 1);
        assert_eq!(
            db.put(inside, now + 500).await,
            PutOutcome::PreviouslyDeleted
        );
        let after = tagged("after the cut", now + 2_000, 1);
        assert_eq!(db.put(after, now + 2_000).await, PutOutcome::Stored);
    });
    db.shutdown();
}

#[test]
fn group_purge_marker_merges_and_keeps_one_record() {
    // The marker value is `(purge time, cut)`: one fixed record per group,
    // merged on re-purge by keeping the furthest purge time and cut, and
    // readable after a reopen (legacy 8-byte markers mean `(cut, cut)`).
    use crate::db::store::{
        Store, decode_purged_group_marker, encode_purged_group_marker, purged_group_key,
    };
    let store = Store::open(
        &config(),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        128,
    )
    .unwrap();
    let now = 1_700_000_000u64;
    let gid = "marker-merge";
    let tagged = |content: &str, created: u64| {
        event(1, content, created, vec![vec!["h".into(), gid.into()]])
    };
    for (i, created) in [now - 100, now - 10, now].into_iter().enumerate() {
        let e = tagged(&format!("m{i}"), created);
        let mut wtxn = store.env.write_txn().unwrap();
        assert_eq!(
            store.put_event_in(&mut wtxn, &e, now).unwrap(),
            PutOutcome::Stored
        );
        wtxn.commit().unwrap();
    }
    assert_eq!(store.purge_group(gid, now).unwrap(), 3);
    let key = purged_group_key(gid);
    {
        let rtxn = store.env.read_txn().unwrap();
        assert_eq!(store.purged_groups.len(&rtxn).unwrap(), 1);
        let raw = store.purged_groups.get(&rtxn, &key).unwrap().unwrap();
        assert_eq!(
            raw.len(),
            48,
            "the marker carries (purge time, cut, create id)"
        );
        assert_eq!(decode_purged_group_marker(raw), (now, now, None));
    }
    // A future-dated event is removed by a later purge and raises the cut.
    let future = tagged("future", now + 300);
    let mut wtxn = store.env.write_txn().unwrap();
    assert_eq!(
        store.put_event_in(&mut wtxn, &future, now).unwrap(),
        PutOutcome::Stored
    );
    wtxn.commit().unwrap();
    assert_eq!(store.purge_group(gid, now).unwrap(), 1);
    // A later purge with a smaller `now` keeps the larger purge time/cut.
    assert_eq!(store.purge_group(gid, now - 50).unwrap(), 0);
    let rtxn = store.env.read_txn().unwrap();
    assert_eq!(store.purged_groups.len(&rtxn).unwrap(), 1);
    let raw = store.purged_groups.get(&rtxn, &key).unwrap().unwrap();
    assert_eq!(
        decode_purged_group_marker(raw),
        (now, now + 300, None),
        "the purge time and cut must not regress"
    );
    // Round trip and the legacy 8-byte marker read as `(cut, cut)`.
    assert_eq!(
        decode_purged_group_marker(&encode_purged_group_marker(7, 9, None)),
        (7, 9, None)
    );
    let create = [7u8; 32];
    assert_eq!(
        decode_purged_group_marker(&encode_purged_group_marker(7, 9, Some(&create))),
        (7, 9, Some(create))
    );
    assert_eq!(
        decode_purged_group_marker(&7u64.to_be_bytes()),
        (7, 7, None)
    );
}

#[test]
fn a_resumed_purge_keeps_the_raised_cut() {
    // A crash after a chunk removed a future-dated event must not lose the
    // raised cut: the pending record carries it, so the resume's marker
    // still blocks a re-broadcast of that event.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        let gid = "resume-cut";
        let tagged = |content: &str, created: u64| {
            event(1, content, created, vec![vec!["h".into(), gid.into()]])
        };
        let old = tagged("old", now - 10);
        let future = tagged("future", now + 300);
        for e in [&old, &future] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        // Fail after the first removal chunk committed: the marker and the
        // pending (with the raised cut) are durable, the walk is not done.
        faults
            .chunk_after
            .store(2, std::sync::atomic::Ordering::SeqCst);
        let _ = db.group_purge_until(gid.to_string(), now, u64::MAX).await;
        faults
            .chunk_after
            .store(0, std::sync::atomic::Ordering::SeqCst);
        // The resume finishes the (now empty) walk and must keep the cut
        // raised by the already-removed future-dated event.
        let _ = db.group_purge_until(gid.to_string(), now, u64::MAX).await;
        assert_eq!(
            db.put(future, now).await,
            PutOutcome::PreviouslyDeleted,
            "the resumed purge must keep the cut raised by the removed event"
        );
    });
    db.shutdown();
}

#[test]
fn a_bounded_purge_keeps_a_wider_pending_bound() {
    // A crashed live purge is unbounded: a later migration's bounded purge
    // must not narrow it, or the history the live purge still owed would
    // be served.
    use crate::db::store::{
        Store, encode_pending_purge, encode_purged_group_marker, purged_group_key,
    };
    let store = Store::open(
        &config(),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        128,
    )
    .unwrap();
    let now = 1_700_000_000u64;
    let gid = "wide-pending";
    let tagged = |content: &str, created: u64| {
        event(1, content, created, vec![vec!["h".into(), gid.into()]])
    };
    for (content, created) in [("old", now - 10), ("newer", now + 100)] {
        let e = tagged(content, created);
        let mut wtxn = store.env.write_txn().unwrap();
        assert_eq!(
            store.put_event_in(&mut wtxn, &e, now).unwrap(),
            PutOutcome::Stored
        );
        wtxn.commit().unwrap();
    }
    {
        // What a crashed live purge leaves: the marker and an unbounded
        // pending record.
        let mut wtxn = store.env.write_txn().unwrap();
        let key = purged_group_key(gid);
        store
            .purged_groups
            .put(&mut wtxn, &key, &encode_purged_group_marker(now, now, None))
            .unwrap();
        store
            .purge_pending
            .put(
                &mut wtxn,
                &key,
                &encode_pending_purge(gid, now, now, u64::MAX, None),
            )
            .unwrap();
        wtxn.commit().unwrap();
    }
    // The migration's bounded purge must honour the wider pending bound.
    assert_eq!(store.purge_group_until(gid, now - 5, now - 5).unwrap(), 2);
    let rtxn = store.env.read_txn().unwrap();
    assert_eq!(store.purge_pending.len(&rtxn).unwrap(), 0);
    assert!(
        store.events.is_empty(&rtxn).unwrap(),
        "the merged unbounded walk must remove the newer event too"
    );
}

#[test]
fn purge_marker_survives_reopen() {
    // Durability: the marker is persisted with the database, so a restart
    // cannot let the purged history back in.
    let cfg = config();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        let tagged = |content: &str, created: u64| {
            event(
                1,
                content,
                created,
                vec![vec!["h".into(), "reopen-group".into()]],
            )
        };
        let old = tagged("old", now - 10);
        let same = tagged("same", now);
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
            for e in [&old, &same] {
                assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
            }
            assert_eq!(db.group_purge("reopen-group".into(), now).await, Some(2));
            db.shutdown();
        }
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
        for e in [&old, &same] {
            assert_eq!(
                db.put(e.clone(), now).await,
                PutOutcome::PreviouslyDeleted,
                "the persisted marker must block the replay after a restart"
            );
        }
        db.shutdown();
    });
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
fn vanish_removes_events_at_maximal_timestamp() {
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
        let pubkey = "bb".repeat(32);
        let mut event = event(1, "maximal vanish timestamp", u64::MAX, vec![]);
        event.pubkey = pubkey.clone();
        event.id = nip01::compute_id(&event);
        assert_eq!(db.put(event.clone(), u64::MAX).await, PutOutcome::Stored);

        let removed = db
            .apply_vanish(hex::decode(pubkey).unwrap().try_into().unwrap(), u64::MAX)
            .await;
        assert_eq!(removed, 1);

        let filter: Filter =
            serde_json::from_value(serde_json::json!({"authors": [event.pubkey]})).unwrap();
        let (events, _) = db.query(vec![filter], 10, u64::MAX).await;
        assert!(events.is_empty(), "maximal-timestamp event survived vanish");
    });
    db.shutdown();
}

#[test]
fn vanish_replay_is_a_no_op() {
    // NIP-62 requests are signed and can be re-broadcast: replaying one must
    // not re-walk the author's history. The stored marker keeps the furthest
    // honored `until_created`, so covered requests remove nothing.
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
        let pubkey = "cc".repeat(32);
        let ev = |created| {
            let mut e = event(1, "v", created, vec![]);
            e.pubkey = pubkey.clone();
            e.id = nip01::compute_id(&e);
            e
        };
        assert_eq!(db.put(ev(1_000), 4_000).await, PutOutcome::Stored);
        assert_eq!(db.put(ev(3_000), 4_000).await, PutOutcome::Stored);
        let pk: [u8; 32] = hex::decode(&pubkey).unwrap().try_into().unwrap();
        assert_eq!(
            db.apply_vanish(pk, 3_000).await,
            2,
            "the first request deletes both events"
        );
        // The same request, and an older one, are covered: no work.
        assert_eq!(db.apply_vanish(pk, 3_000).await, 0);
        assert_eq!(db.apply_vanish(pk, 2_000).await, 0);
        // A newer request is still honored (and finds nothing left).
        assert_eq!(db.apply_vanish(pk, 5_000).await, 0);
        assert_eq!(db.apply_vanish(pk, 3_000).await, 0);
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
            access.blocked_ips.push("203.0.113.9".into(), String::new());
            db.save_access(access.clone()).await;
            // The pubkey lists live under their own key.
            db.save_relay_pubkeys(&[("aa".repeat(32), String::new())], &[])
                .await;
            let crate::db::LoadAccessOutcome::Loaded(loaded) = db.load_access().await else {
                panic!("persisted access must load");
            };
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
        let crate::db::LoadAccessOutcome::Loaded(loaded) = db.load_access().await else {
            panic!("persisted access must load");
        };
        assert_eq!(loaded.allowed_kinds, vec![5]);
        assert_eq!(
            loaded.blocked_ips.entries(),
            [(String::from("203.0.113.9"), String::new())]
        );
        // The dedicated pubkey key survives the reopen.
        let (deny, allow) = db.load_relay_pubkeys().await.unwrap_or_default();
        assert_eq!(deny, vec![("aa".repeat(32), String::new())]);
        assert!(allow.is_empty());
    });
}

#[test]
fn access_load_distinguishes_missing_loaded_and_failed() {
    // The startup load must not conflate "nothing was ever persisted" (seed
    // the config) with "the database could not answer" (refuse to start):
    // treating a failed read as missing would silently replace the
    // persisted NIP-86 bans with the config seed.
    let cfg = config();
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
        // A fresh database has nothing persisted.
        assert!(matches!(
            db.load_access().await,
            crate::db::LoadAccessOutcome::Missing
        ));
        // Persisted state loads back.
        let mut access = crate::config::AccessControl::default();
        access.blocked_ips.push("203.0.113.9".into(), String::new());
        db.save_access(access.clone()).await;
        let crate::db::LoadAccessOutcome::Loaded(loaded) = db.load_access().await else {
            panic!("persisted access must load");
        };
        assert_eq!(loaded.blocked_ips, access.blocked_ips);
        // A reader that cannot answer reports `Failed`, never `Missing`.
        db.shutdown();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(matches!(
            db.load_access().await,
            crate::db::LoadAccessOutcome::Failed
        ));
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
        access.blocked_ips.push("203.0.113.9".into(), String::new());
        db.save_access(access).await;
        db.save_relay_pubkeys(&[("aa".repeat(32), String::new())], &[])
            .await;
        let crate::db::LoadAccessOutcome::Loaded(loaded) = db.load_access().await else {
            panic!("persisted access must load");
        };
        assert_eq!(loaded.blocked_ips.entries()[0].0, "203.0.113.9");
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
        let meta = db
            .blossom_load_checked(&"bb".repeat(32))
            .await
            .unwrap()
            .unwrap();
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
            db.purge_expired(now, 0).await,
            (1, false),
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
fn search_index_walk_respects_time_bounds() {
    // The word-index walk must honour `since`/`until` like the pubkey/kind
    // walks: without the range bounds the walk starts at the newest entry
    // of the term and burns the scan budget on out-of-window events before
    // reaching the window, so a narrow window can come back empty while
    // reporting `more`.
    let store = crate::db::store::Store::open(
        &config(),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        512,
    )
    .unwrap();
    let now = 1_700_000_000;
    let mut wtxn = store.env.write_txn().unwrap();
    for i in 0..10u64 {
        let ev = event(1, "windowed term", now + 100 + i, vec![]);
        assert!(matches!(
            store.put_event_in(&mut wtxn, &ev, now).unwrap(),
            PutOutcome::Stored
        ));
    }
    let target = event(1, "windowed term", now, vec![]);
    assert!(matches!(
        store.put_event_in(&mut wtxn, &target, now).unwrap(),
        PutOutcome::Stored
    ));
    wtxn.commit().unwrap();

    let filter: Filter = serde_json::from_value(serde_json::json!({
        "search": "windowed",
        "since": now - 10,
        "until": now + 10,
    }))
    .unwrap();
    // Budget 1: the walk may examine a single candidate. With the bounds
    // applied to the term range, the in-window event is the only candidate.
    let (events, more) = store.scan(&[filter], now, 10, false, false, 1, 0).unwrap();
    assert_eq!(events.len(), 1, "the in-window event must be found");
    assert_eq!(events[0].id, target.id);
    assert!(!more);
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
            db.apply_deletion(vec![ev.id.clone()], vec![], Some(ev.pubkey.clone()), now)
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
    // instead of accumulating in memory, and the overload is surfaced in
    // the dedicated overload counter (not the fault counter).
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
        assert_eq!(
            db.take_overloads(),
            1,
            "the cap fail-fast must bump the overload counter"
        );
        assert_eq!(
            errors.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "an overload is not a database fault"
        );
        // The event cap is also enforced.
        db.pending_msgs
            .store(0, std::sync::atomic::Ordering::Relaxed);
        db.pending_events
            .store(8, std::sync::atomic::Ordering::Relaxed);
        let out = db.put(ev, now).await;
        assert!(matches!(out, PutOutcome::Invalid(_)));
        assert_eq!(
            db.take_overloads(),
            1,
            "the event-cap fail-fast must bump the overload counter"
        );
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
fn inline_writes_release_queue_accounting_before_their_reply() {
    // Regression: the writer drain used to release the queued-work
    // accounting of every drained message only at the end (right before
    // the put flush). Inline-completed messages (`SaveAccess` and friends)
    // send their reply inside the drain, so a caller woken by such a reply
    // could immediately issue another write and be spuriously fail-fast
    // ("database overloaded") while the rest of the batch was still
    // counted.
    //
    // This test observes the release itself instead of reply timing: the
    // writer counts every released message in the test-only
    // `Store::writer_releases` hook, in the same step as the release. Once
    // at least two releases are observed, the shared message counter must
    // already have dropped, even though the burst is still being
    // processed. Without per-message release the counter only reaches zero
    // at the drain end, so the check below cannot pass.
    let mut cfg = config();
    cfg.max_db_queue_bytes = 1_024;
    let errors = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let cap = 16;
    // Open the store here so the test shares the writer's progress
    // counter (`writer_releases`) with the writer thread.
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = crate::db::store::Store::open(&cfg, Arc::clone(&expiry), 128).unwrap();
    let released = Arc::clone(&store.writer_releases);
    let db =
        DbClient::open_with_store(&cfg, store, expiry, Arc::clone(&errors), 0, cap, cap).unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        for round in 0..16u64 {
            // Quiescence: the previous round is fully drained and released,
            // so this round starts from a clean counter.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while db.pending_msgs.load(std::sync::atomic::Ordering::Relaxed) != 0 {
                if std::time::Instant::now() >= deadline {
                    panic!("round {round}: the queue did not drain between rounds");
                }
                tokio::task::yield_now().await;
            }
            let base = released.load(std::sync::atomic::Ordering::Relaxed);
            let mut saves = Vec::with_capacity(cap);
            for _ in 0..cap {
                let db = db.clone();
                saves.push(tokio::spawn(async move {
                    db.save_access(crate::config::AccessControl::default())
                        .await
                }));
            }
            // Wait until the writer has released at least two messages of
            // this burst. Releases are monotonic and only ever follow a
            // completed message arm, so from here on the shared counter
            // must already reflect them.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let done = released
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .saturating_sub(base);
                if done >= 2 {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    panic!("round {round}: the writer did not release any burst message");
                }
                tokio::task::yield_now().await;
            }
            let msgs = db.pending_msgs.load(std::sync::atomic::Ordering::Relaxed);
            assert!(
                msgs <= cap - 2,
                "round {round}: two released messages must free two queue slots, got {msgs}"
            );
            // And a new write is admitted immediately: at most `cap - 2`
            // slots can be occupied, so the probe cannot fail fast.
            let probe = event(1, &format!("probe-{round}"), now, vec![]);
            let out = db.put(probe, now).await;
            assert!(
                matches!(out, PutOutcome::Stored),
                "round {round}: a write must be admitted while the burst drains: {out:?}"
            );
            for save in saves {
                assert!(save.await.unwrap(), "the burst save must commit");
            }
        }
        assert_eq!(
            db.take_overloads(),
            0,
            "no write may fail fast while the burst drains its inline replies"
        );
        assert_eq!(
            errors.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the burst must not report database faults"
        );
        db.shutdown();
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
fn query_directed_ascending_ids() {
    // The `ids` branch must honor the scan direction like every other
    // branch: with `ascending` a multi-id `limit` keeps the oldest events,
    // otherwise the newest. Reachability is currently narrow (WS uses
    // newest-first; REST single-id makes the cutoff moot), so this pins the
    // contract for future `query_directed` callers.
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
        let ids = vec![e3.id.clone(), e1.id.clone()];
        let f: Filter =
            serde_json::from_value(serde_json::json!({"ids": ids})).unwrap();
        let (desc, _) = db.query_directed(vec![f.clone()], 1, now, false, 0).await;
        assert_eq!(desc.len(), 1);
        assert_eq!(desc[0].id, e3.id, "newest-first keeps the newest id");
        let (asc, _) = db.query_directed(vec![f], 1, now, true, 0).await;
        assert_eq!(asc.len(), 1);
        assert_eq!(asc[0].id, e1.id, "ascending keeps the oldest id");
    });
    db.shutdown();
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
        assert_eq!(db.purge_expired(now + 10, 0).await, (1, false));
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
            let (res, _) = db
                .api_query(vec![f], 500, now, false)
                .await
                .expect("api query");
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
        let (events, more) = db
            .api_count(vec![kinds1.clone()], 2000, now)
            .await
            .expect("api count");
        assert_eq!(events.len(), 32, "api_count must return the matches");
        assert!(!more);
        // Empty path: no matching events.
        let (events, more) = db
            .api_count(vec![kinds2.clone()], 2000, now)
            .await
            .expect("api count");
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
        let (events, _) = db
            .api_count(vec![kinds1], 2000, unix_now())
            .await
            .expect("api count");
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
        assert!(
            db.api_count(vec![kinds1.clone()], 2000, now)
                .await
                .is_none(),
            "an aggregation at the pending cap must fail fast (None, not an empty 200)"
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
            // Fail-fast under pressure is reported as `None`; a served
            // aggregation returns all matches.
            let Some((events, _)) = f.await.unwrap() else {
                continue;
            };
            assert_eq!(events.len(), 8, "a served aggregation returns all matches");
        }
        // The counter recovers: a later call is served normally.
        let (events, _) = db
            .api_count(vec![kinds1.clone()], 2000, now)
            .await
            .expect("api count");
        assert_eq!(events.len(), 8, "api_count must recover after fail-fast");
        // The WebSocket path is unaffected.
        let (events, _) = db.query(vec![kinds1.clone()], 500, now).await;
        assert_eq!(events.len(), 8);

        // After shutdown the channel is closed: api_count must report the
        // failure as `None` (a 503, not an empty 200) instead of panicking.
        db.shutdown();
        assert!(
            db.api_count(vec![kinds1.clone()], 2000, now)
                .await
                .is_none(),
            "a closed channel must fail the aggregation"
        );
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
fn save_blossom_allow_reports_the_commit_result() {
    // The reply carries the commit outcome: the caller must not report a
    // persisted allowlist change that only lives in memory.
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
        let entries = vec!["aa".repeat(32)];
        assert!(db.save_blossom_allow(&entries).await, "commit reported");
        assert_eq!(db.try_load_blossom_allow().await.expect("loads"), entries);
        db.shutdown();
        assert!(
            !db.save_blossom_allow(&["bb".repeat(32)]).await,
            "a dead writer must not report a committed allowlist"
        );
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
fn gift_wrap_index_backfills_legacy_wraps() {
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = crate::db::store::Store::open(&config(), expiry, 128).unwrap();
    let now = 1_700_000_000;
    let recipient = "aB3130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
    let wrap = event(
        1059,
        "legacy wrap",
        now,
        vec![vec!["p".into(), recipient.into()]],
    );
    let id = wrap.id_bytes().unwrap();
    let mut wtxn = store.env.write_txn().unwrap();
    assert!(matches!(
        store.put_event_in(&mut wtxn, &wrap, now).unwrap(),
        PutOutcome::Stored
    ));
    wtxn.commit().unwrap();
    let key = crate::db::store::tag_key(
        crate::db::store::GIFT_WRAP_INDEX,
        &hex::decode(recipient).unwrap(),
        now,
        &id,
    );
    // Simulate a database written before the recipient index existed: the
    // event is stored but its hidden entry is missing.
    let mut wtxn = store.env.write_txn().unwrap();
    store.by_tag.delete(&mut wtxn, &key).unwrap();
    wtxn.commit().unwrap();
    assert!(store.gift_wrap_index_needs_rebuild().unwrap());
    assert_eq!(store.rebuild_gift_wrap_index().unwrap(), 1);
    assert!(!store.gift_wrap_index_needs_rebuild().unwrap());
    // The backfilled entry makes the mixed-case recipient lookup find it.
    let removed = store
        .delete_gift_wraps_to(&hex::decode(recipient).unwrap(), u64::MAX)
        .unwrap();
    assert_eq!(removed, 1);
}

#[test]
fn gift_wrap_index_entries_are_removed_with_the_event() {
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = crate::db::store::Store::open(&config(), expiry, 128).unwrap();
    let now = 1_700_000_000;
    let recipient = "b83130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
    let wrap = event(1059, "wrap", now, vec![vec!["p".into(), recipient.into()]]);
    let id = wrap.id_bytes().unwrap();
    let mut wtxn = store.env.write_txn().unwrap();
    assert!(matches!(
        store.put_event_in(&mut wtxn, &wrap, now).unwrap(),
        PutOutcome::Stored
    ));
    wtxn.commit().unwrap();
    let key = crate::db::store::tag_key(
        crate::db::store::GIFT_WRAP_INDEX,
        &hex::decode(recipient).unwrap(),
        now,
        &id,
    );
    let rtxn = store.env.read_txn().unwrap();
    assert!(store.by_tag.get(&rtxn, &key).unwrap().is_some());
    drop(rtxn);
    // Removing the event (any path) must drop the recipient entry with it,
    // or a later deletion by recipient would find a dangling key.
    let mut wtxn = store.env.write_txn().unwrap();
    store.remove_event(&mut wtxn, &id).unwrap();
    wtxn.commit().unwrap();
    let rtxn = store.env.read_txn().unwrap();
    assert!(store.by_tag.get(&rtxn, &key).unwrap().is_none());
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
fn corrupt_event_cleanup_is_bounded_by_the_scan_cap() {
    // A corrupt event's index cleanup must not walk an arbitrarily large
    // table while the caller's write transaction is open: past the cap the
    // dangling index entries are left behind (harmless, the scans verify
    // existence) instead of blocking every queued write.
    use crate::db::store::{CORRUPT_CLEANUP_SCAN_CAP, created_key};
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = crate::db::store::Store::open(&config(), expiry, 128).unwrap();
    let id = [9u8; 32];
    let created = 1_700_000_000u64;
    let mut wtxn = store.env.write_txn().unwrap();
    store.events.put(&mut wtxn, &id, b"{not-json").unwrap();
    // Fill `by_created` with unrelated keys that sort before the corrupt
    // event's key, so the walk hits the cap before finding it.
    for i in 0..CORRUPT_CLEANUP_SCAN_CAP {
        store
            .by_created
            .put(&mut wtxn, &created_key(i as u64, &[1u8; 32]), b"")
            .unwrap();
    }
    store
        .by_created
        .put(&mut wtxn, &created_key(created, &id), b"")
        .unwrap();
    wtxn.commit().unwrap();

    let mut wtxn = store.env.write_txn().unwrap();
    store.remove_event(&mut wtxn, &id).unwrap();
    wtxn.commit().unwrap();

    let rtxn = store.env.read_txn().unwrap();
    assert!(
        store.events.get(&rtxn, &id).unwrap().is_none(),
        "the corrupt event itself is removed"
    );
    assert!(
        store
            .by_created
            .get(&rtxn, &created_key(created, &id))
            .unwrap()
            .is_some(),
        "the capped walk leaves the dangling index entry behind"
    );
}

#[test]
fn corrupt_short_keys_do_not_panic_the_removal_walks() {
    // Bitrot can leave index keys shorter than an id. The walks used to
    // slice `key[key.len() - ID_LEN..]`, panicking the writer and silently
    // dropping the removal; they must skip the corrupt key and still remove
    // the valid entries. The checked DbClient API is exercised over the
    // corrupted tables (a failed walk would report None / zero).
    use crate::db::store::{ID_LEN, Store, tag_key};
    let cfg = config();
    let now = 1_700_000_000u64;
    // NIP-40 disabled while seeding: an already-expired event is still
    // stored (and indexed) so the purge walk can run over it.
    let store = Store::open(
        &cfg,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        128,
    )
    .unwrap();
    let authored = |kind: u64, content: &str, pk: &str, created: u64, tags: Vec<Vec<String>>| {
        let mut e = event(kind, content, created, tags);
        e.pubkey = pk.to_string();
        e.id = nip01::compute_id(&e);
        e
    };
    let gid = "corrupt-group";
    let h_event = authored(
        1,
        "h",
        &"11".repeat(32),
        now,
        vec![vec!["h".into(), gid.into()]],
    );
    let author_event = authored(1, "author", &"00".repeat(32), now, vec![]);
    let exp_event = authored(
        1,
        "expiring",
        &"22".repeat(32),
        now - 100,
        vec![vec!["expiration".into(), (now - 50).to_string()]],
    );
    let mut wtxn = store.env.write_txn().unwrap();
    for e in [&h_event, &author_event, &exp_event] {
        assert_eq!(
            store.put_event_in(&mut wtxn, e, now).unwrap(),
            PutOutcome::Stored
        );
    }
    // by_tag (purge walk): a short key inside the group's range. It keeps
    // the tag prefix and diverges inside the created field, so it sorts
    // after the range start and before the valid key.
    let mut short_tag = tag_key(b'h', gid.as_bytes(), 0, &[0u8; ID_LEN]);
    let prefix = 1 + 1 + 4 + gid.len();
    short_tag.truncate(prefix + 8);
    *short_tag.last_mut().unwrap() = 0xff;
    assert!(short_tag.len() < ID_LEN);
    store.by_tag.put(&mut wtxn, &short_tag, b"").unwrap();
    // by_pubkey (vanish walk): the 32-byte pubkey prefix means a key
    // shorter than ID_LEN sorts outside the range, so insert a corrupt
    // 40-byte key that extracts a bogus id (the walk must skip it).
    let mut short_pubkey = vec![0u8; 40];
    short_pubkey[ID_LEN + 7] = 1;
    store.by_pubkey.put(&mut wtxn, &short_pubkey, b"").unwrap();
    // expiry (purge walk): a 9-byte key with a timestamp below `now` and a
    // byte above the range start.
    let mut short_expiry = vec![0u8; 8];
    short_expiry.push(0xff);
    assert!(short_expiry.len() < ID_LEN);
    store.expiry.put(&mut wtxn, &short_expiry, b"").unwrap();
    wtxn.commit().unwrap();
    drop(store);

    let db = DbClient::open(
        &cfg,
        false,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        assert_eq!(
            db.group_purge(gid.into(), now).await,
            Some(1),
            "the valid event is still purged"
        );
        assert_eq!(
            db.apply_vanish_checked([0u8; 32], now).await,
            Some((1, false)),
            "the valid event is still vanished"
        );
        db.set_expiry_enabled(true);
        assert_eq!(
            db.purge_expired(now, 0).await,
            (1, false),
            "the valid expired event is still purged"
        );
    });
    db.shutdown();
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
        restored.restore(db.load_groups().await.expect_loaded("snapshot"));
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
        restored_roles.restore(db.load_roles().await.expect_loaded("snapshot"));
        assert!(
            restored_roles.is_member_of(crate::nips::nip29::tests::USER),
            "roles must restore"
        );
        db.shutdown();
    });
}

#[test]
fn sixteen_max_dbs_still_opens_with_the_word_index() {
    // 22 named tables are created (21 plus the word index); an operator
    // value of 16 must not fail at startup (the clamp raises it to 22).
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
    .expect("22 tables must fit via the clamp");
    db.shutdown();
}

#[test]
fn db_queue_byte_cap_fails_fast() {
    // The count caps alone let a queue of maximum-size events reach
    // gigabytes; the byte cap refuses the message up front. The failed
    // reservation must be rolled back, or the first oversized payload
    // would permanently fail-fast every later write.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut cfg = config();
        cfg.max_db_queue_bytes = 1_000;
        let errors = Arc::new(Default::default());
        let db = DbClient::open(&cfg, true, Arc::clone(&errors), 0, 128, 4096, 262144).unwrap();
        let now = unix_now();
        let big = event(1, &"x".repeat(4_000), now, vec![]);
        assert!(
            db.put_batch_deferred(vec![(Arc::new(big), now)]).is_none(),
            "an over-budget write must fail fast"
        );
        assert_eq!(
            db.take_overloads(),
            1,
            "the byte-cap fail-fast must bump the overload counter"
        );
        assert_eq!(
            errors.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "an overload is not a database fault"
        );
        // The reservation was rolled back: a normal event still stores.
        let small = event(1, "ok", now, vec![]);
        assert_eq!(db.put(small, now).await, PutOutcome::Stored);
        db.shutdown();
    });
}

#[test]
fn reader_queue_byte_cap_fails_fast() {
    // The reader/API queues get the same byte cap over their filter
    // payloads: a huge filter is refused instead of queueing behind the
    // scan threads.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut cfg = config();
        cfg.max_db_queue_bytes = 1_000;
        let errors = Arc::new(Default::default());
        let db = DbClient::open(&cfg, true, Arc::clone(&errors), 0, 128, 4096, 262144).unwrap();
        let now = unix_now();
        let e = event(1, "hello", now, vec![]);
        assert_eq!(db.put(e, now).await, PutOutcome::Stored);
        let huge: Filter = serde_json::from_value(serde_json::json!({
            "#e": vec!["a".repeat(2_000)]
        }))
        .unwrap();
        let (out, _) = db.query(vec![huge], 10, now).await;
        assert!(out.is_empty(), "the over-budget query is refused");
        assert_eq!(
            db.take_overloads(),
            1,
            "the byte-cap read fail-fast must bump the overload counter"
        );
        assert_eq!(
            errors.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "an overload is not a database fault"
        );
        // The reservation was rolled back: a normal query still works.
        let small: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (out, _) = db.query(vec![small], 10, now).await;
        assert_eq!(out.len(), 1);
        db.shutdown();
    });
}

#[test]
fn startup_rebuild_queries_keep_the_reader_byte_accounting_balanced() {
    // Regression (#96 over #94): the NIP-29/43 rebuild queries go through
    // `request_read_startup`, which reserved only the count. The reader
    // thread releases both counters on completion, so the payload bytes
    // were subtracted without ever being added: `pending_read_bytes`
    // underflowed to `usize::MAX` and every later byte-checked read (the
    // REQ scan path, `size_on_disk`, the account-age `first_seen_batch`)
    // failed fast for the rest of the process.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let cfg = config();
        let errors = Arc::new(Default::default());
        let db = DbClient::open(&cfg, true, Arc::clone(&errors), 30, 128, 4096, 262144).unwrap();
        let now = unix_now();
        let e = event(1, "account-age probe", now, vec![]);
        assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);

        // The startup rebuild query (a filter with payload bytes).
        let kinds: Vec<u64> = (9000..=9022).collect();
        let f: Filter = serde_json::from_value(serde_json::json!({ "kinds": kinds })).unwrap();
        let page = db.query_full_startup(vec![f], 100, now, true).await;
        assert!(page.is_some(), "the startup query must answer");

        // The byte-checked read path must still work afterwards.
        let small: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (out, _) = db.query(vec![small], 10, now).await;
        assert_eq!(
            out.len(),
            1,
            "reads must not fail after a startup rebuild query"
        );
        // A fail-fast read returns an empty vec here; a working one answers
        // exactly one status per requested pubkey.
        let status = db.first_seen_batch(vec![e.pubkey_bytes().unwrap()]).await;
        assert_eq!(status.len(), 1, "first-seen reads must still answer");
        db.shutdown();
    });
}

#[test]
fn vanish_pubkeys_each_reports_database_failure() {
    // The NIP-29/43 rebuilds resume from the vanished-pubkey set; a failed
    // read used to be reported as an empty set (`Some(())`), resurrecting
    // vanished members/roles. A dead reader must be a hard failure.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let cfg = config();
        let db = DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            30,
            128,
            4096,
            262144,
        )
        .unwrap();
        let pk = [7u8; 32];
        assert!(
            db.apply_vanish_checked(pk, 1_700_000_000).await.is_some(),
            "the vanish marker must be written"
        );
        let mut seen: Vec<Vec<u8>> = Vec::new();
        assert!(
            db.vanish_pubkeys_each(|key| seen.push(key.to_vec()))
                .await
                .is_some(),
            "a healthy read reports success"
        );
        assert_eq!(seen, vec![pk.to_vec()]);
        db.shutdown();
        assert!(
            db.vanish_pubkeys_each(|_| {}).await.is_none(),
            "a failed read must report failure instead of an empty list"
        );
    });
}

#[test]
fn vanish_reports_whether_group_state_was_removed() {
    // NIP-62: only a removed NIP-29 state event (moderation/join/leave)
    // requires the derived group state to be rebuilt; deleting ordinary
    // posts must not trigger the full-history scan.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
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
        let now = unix_now();
        // Two distinct authors: a vanished key cannot publish again.
        let authored = |kind: u64, pk: &str, created: u64| {
            let mut e = event(kind, "x", created, vec![]);
            e.pubkey = pk.to_string();
            e.id = nip01::compute_id(&e);
            e
        };
        let pk_note = "aa".repeat(32);
        let pk_mod = "bb".repeat(32);
        assert_eq!(
            db.put(authored(1, &pk_note, now), now).await,
            PutOutcome::Stored
        );
        assert_eq!(
            db.apply_vanish_checked([0xaa; 32], now).await,
            Some((1, false)),
            "an ordinary post must not require a group state rebuild"
        );
        assert_eq!(
            db.put(authored(9000, &pk_mod, now + 1), now + 1).await,
            PutOutcome::Stored
        );
        assert_eq!(
            db.apply_vanish_checked([0xbb; 32], now + 1).await,
            Some((1, true)),
            "a removed moderation event must require a rebuild"
        );
        db.shutdown();
    });
}

#[test]
fn search_finds_a_word_too_long_to_index() {
    // A word longer than the index key limit can never have its own index
    // range, so the event must carry the overflow marker (the full-content
    // walk). Without the marker, a query mixing an indexed term with the
    // long term walked only the indexed term's range and missed the event.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        32,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let long = "a".repeat(600);
        let ev = event(1, &format!("short {long}"), now, vec![]);
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        // Mixed query: the indexable term routes to the word walk, the long
        // term can only be found through the overflow marker.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"search": format!("zzz {long}")})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(
            res.len(),
            1,
            "an event containing a too-long word must be found via the overflow walk"
        );
        assert_eq!(res[0].id, ev.id);
        // A long-only query falls through to the time-range scan.
        let f: Filter = serde_json::from_value(serde_json::json!({"search": long})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the long-word-only query must match");
        // Removal drops the marker (mirroring the put rule).
        db.apply_deletion(vec![ev.id.clone()], vec![], Some(ev.pubkey.clone()), now)
            .await;
        let f: Filter =
            serde_json::from_value(serde_json::json!({"search": format!("zzz {long}")})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty(), "the marker must be removed with the event");
    });
    db.shutdown();
}

#[test]
fn search_limit_applies_to_the_union_of_indexed_and_overflow_matches() {
    // A limit reached while walking the indexed term ranges must not skip
    // the overflow-only matches: both ranges belong to the same merged
    // walk, so the newest union member wins the single slot.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        2, // max_indexed_words: the third token is overflow-only
        4096,
        262144,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        let indexed = event(1, "late old", now - 10, vec![]);
        let overflow = event(1, "x y late", now, vec![]);
        assert_eq!(db.put(indexed.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(overflow.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"search": "late"})).unwrap();
        let (res, _) = db.query(vec![f], 1, now).await;
        assert_eq!(res.len(), 1, "the limit must return one union member");
        assert_eq!(
            res[0].id, overflow.id,
            "the newer overflow match must win the union slot"
        );
    });
    db.shutdown();
}

// ----- crash recovery, durability and thread failure injection -----

#[test]
fn writer_thread_recovers_from_a_handler_panic() {
    // A panic inside a writer handler must not kill the database thread:
    // the queued batch is revoked (an OK after a rollback would be a lie),
    // the queued-work counters return to zero and the next request is
    // served. The one-shot test hook panics after the put joined the batch,
    // so both the reply revocation and the `PendingGuard` release are
    // exercised.
    let cfg = config();
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = crate::db::store::Store::open(&cfg, Arc::clone(&expiry), 128).unwrap();
    store
        .panic_next_write
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let db = DbClient::open_with_store(
        &cfg,
        store,
        expiry,
        Arc::new(Default::default()),
        0,
        128,
        4096,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        let e = event(1, "panic candidate", now, vec![]);
        let out = db.put(e.clone(), now).await;
        assert!(
            matches!(out, PutOutcome::Invalid(_)),
            "the panicking handler's put must be revoked, got {out:?}"
        );
        assert_eq!(
            db.pending_msgs.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the panic must release the queued-message counter"
        );
        assert_eq!(
            db.pending_events.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the panic must release the queued-event counter"
        );
        assert_eq!(
            db.pending_bytes.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the panic must release the queued-byte counter"
        );
        // The rolled-back put was not stored, and the thread recovered.
        assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [e.id]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert_eq!(res.len(), 1, "the database thread must keep serving");
    });
    db.shutdown();
}

#[test]
fn reader_thread_recovers_from_a_handler_panic() {
    // A panic inside a reader handler drops that request's reply (a
    // reporting caller sees a failure instead of a default), releases the
    // reader-queue counters and leaves the thread serving the next query.
    let cfg = config();
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = crate::db::store::Store::open(&cfg, Arc::clone(&expiry), 128).unwrap();
    store
        .panic_next_read
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let db = DbClient::open_with_store(
        &cfg,
        store,
        expiry,
        Arc::new(Default::default()),
        0,
        128,
        4096,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        let e = event(1, "reader panic", now, vec![]);
        assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [e.id]})).unwrap();
        assert!(
            db.query_req_reported(vec![f.clone()], 10, now)
                .await
                .is_none(),
            "the panicked reader's reply must be a reported failure"
        );
        // The reply is dropped during unwinding, so the caller observes the
        // failure before the reader thread has finished its panic recovery:
        // wait briefly for the counters instead of racing the unwind.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline
            && db.pending_reads.load(std::sync::atomic::Ordering::Relaxed) != 0
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(
            db.pending_reads.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the panic must release the reader-queue counter"
        );
        assert_eq!(
            db.pending_read_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the panic must release the reader byte counter"
        );
        let (res, _) = db.query(vec![f], 10, now).await;
        assert_eq!(res.len(), 1, "the reader must keep serving after a panic");
    });
    db.shutdown();
}

#[test]
fn pending_group_purge_is_reported_and_resumable() {
    // Crash recovery for `kind:9008`: the initial commit writes the marker
    // and the in-progress record, then the walk fails (armed fault) before
    // removing a chunk. `pending_purges` reports the record and the
    // re-issued purge completes the walk idempotently, keeping the furthest
    // cut, before clearing the record.
    use crate::db::store::Store;
    let cfg = config();
    let now = 1_700_000_000u64;
    let gid = "pending-purge";
    let tagged = |content: &str, created: u64| {
        event(1, content, created, vec![vec!["h".into(), gid.into()]])
    };
    let e1 = tagged("one", now - 10);
    let e2 = tagged("two", now);
    // Future-dated history pushes the completed cut past the purge time.
    let e3 = tagged("future", now + 100);
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = Store::open(&cfg, Arc::clone(&expiry), 128).unwrap();
    {
        let mut wtxn = store.env.write_txn().unwrap();
        for e in [&e1, &e2, &e3] {
            assert_eq!(
                store.put_event_in(&mut wtxn, e, now).unwrap(),
                PutOutcome::Stored
            );
        }
        wtxn.commit().unwrap();
    }
    // Arm the one-shot fault: the purge records its marker and in-progress
    // record, then fails before the first removal chunk.
    store
        .fail_next_purge_chunk
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let db = DbClient::open_with_store(
        &cfg,
        store,
        expiry,
        Arc::new(Default::default()),
        0,
        128,
        4096,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // The failed walk reports failure, but the marker is already
        // committed: the group's history stays stored while a replay is
        // fail-closed.
        let history: Filter = serde_json::from_value(serde_json::json!({"#h": [gid]})).unwrap();
        assert_eq!(db.group_purge(gid.into(), now).await, None);
        assert_eq!(
            db.query(vec![history.clone()], 10, now).await.0.len(),
            3,
            "a failed purge must leave the group's history stored"
        );
        assert_eq!(db.put(e1.clone(), now).await, PutOutcome::PreviouslyDeleted);
        assert_eq!(
            db.pending_purges()
                .await
                .expect("a healthy pending read must answer"),
            vec![(gid.to_string(), now, u64::MAX)],
            "the interrupted purge must be recorded"
        );
        // The re-issued purge finishes the walk and clears the record.
        assert_eq!(db.group_purge(gid.into(), now).await, Some(3));
        assert!(
            db.pending_purges()
                .await
                .expect("a healthy pending read must answer")
                .is_empty(),
            "the completed purge must clear its in-progress record"
        );
        assert!(db.query(vec![history], 10, now).await.0.is_empty());
        // An idempotent re-run keeps the furthest cut: the future-dated
        // event's timestamp was folded in, so a replay between the purge
        // time and that event is still rejected.
        assert_eq!(db.group_purge(gid.into(), now).await, Some(0));
        assert_eq!(
            db.put(tagged("between", now + 50), now).await,
            PutOutcome::PreviouslyDeleted
        );
        // Beyond the furthest removed timestamp a new event is accepted.
        assert_eq!(
            db.put(tagged("fresh", now + 200), now).await,
            PutOutcome::Stored
        );
    });
    db.shutdown();
}

#[test]
fn interrupted_vanish_is_resumed_at_startup() {
    // Arm the one-shot vanish fault so a real `Msg::Vanish` fails after the
    // in-progress record committed: the record exists, no marker is written
    // and the history stays stored. A restart (`Store::open` + the real
    // writer/reader threads) runs the startup resume, which removes the
    // remaining history, writes the completed marker and bars the pubkey.
    use crate::db::store::Store;
    let cfg = config();
    let now = 1_700_000_000u64;
    let pk = "ef".repeat(32);
    let pk_bytes: [u8; 32] = hex::decode(&pk).unwrap().try_into().unwrap();
    let authored = |content: &str, created: u64| {
        let mut e = event(1, content, created, vec![]);
        e.pubkey = pk.to_string();
        e.id = nip01::compute_id(&e);
        e
    };
    let old = authored("old", now - 20);
    let newer = authored("newer", now - 10);
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = Store::open(&cfg, Arc::clone(&expiry), 128).unwrap();
    {
        let mut wtxn = store.env.write_txn().unwrap();
        for e in [&old, &newer] {
            assert_eq!(
                store.put_event_in(&mut wtxn, e, now).unwrap(),
                PutOutcome::Stored
            );
        }
        wtxn.commit().unwrap();
    }
    // Arm the one-shot fault: the vanish records its in-progress record,
    // then fails before the first removal chunk.
    store
        .fail_next_vanish_chunk
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let db = DbClient::open_with_store(
        &cfg,
        store,
        expiry,
        Arc::new(Default::default()),
        0,
        128,
        4096,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let author_filter =
        || -> Filter { serde_json::from_value(serde_json::json!({"authors": [pk]})).unwrap() };
    rt.block_on(async {
        assert_eq!(
            db.apply_vanish_checked(pk_bytes, now).await,
            None,
            "the interrupted walk must report failure"
        );
        assert_eq!(
            db.query(vec![author_filter()], 10, now).await.0.len(),
            2,
            "a failed vanish must leave its history stored"
        );
    });
    db.shutdown();
    // No completed marker, but the in-progress record is durable.
    {
        let store = Store::open(
            &cfg,
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            128,
        )
        .unwrap();
        let rtxn = store.env.read_txn().unwrap();
        assert!(
            store.vanish.get(&rtxn, &pk_bytes).unwrap().is_none(),
            "an interrupted vanish must not write the completed marker"
        );
        let pending = store
            .vanish_pending
            .get(&rtxn, &pk_bytes)
            .unwrap()
            .expect("the interrupted vanish must be recorded");
        assert_eq!(u64::from_be_bytes(pending.try_into().unwrap()), now);
    }
    // A restart: the writer completes the pending vanish before serving.
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
    rt.block_on(async {
        // The write round trip is ordered after the startup resume (the
        // resume runs on the writer thread before it drains any message),
        // so it is the barrier that makes the reads below deterministic.
        assert_eq!(
            db.put(event(1, "barrier", now, vec![]), now).await,
            PutOutcome::Stored
        );
        assert!(
            db.query(vec![author_filter()], 10, now).await.0.is_empty(),
            "the resumed vanish must remove the remaining history"
        );
        // The pubkey is barred...
        assert!(
            matches!(
                db.put(authored("after", now + 100), now).await,
                PutOutcome::Invalid(reason) if reason.contains("vanish")
            ),
            "a resumed vanish must bar the pubkey"
        );
        // ...and a re-delivered request is a no-op covered by the marker.
        assert_eq!(
            db.apply_vanish_checked(pk_bytes, now).await,
            Some((0, false))
        );
    });
    db.shutdown();
    // The completed marker replaced the pending record.
    let store = Store::open(
        &cfg,
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        128,
    )
    .unwrap();
    let rtxn = store.env.read_txn().unwrap();
    assert_eq!(store.vanish_pending.len(&rtxn).unwrap(), 0);
    let marker = store
        .vanish
        .get(&rtxn, &pk_bytes)
        .unwrap()
        .expect("the resumed vanish must write the completed marker");
    assert_eq!(u64::from_be_bytes(marker.try_into().unwrap()), now);
}

#[test]
fn pending_vanish_is_resumed_at_startup() {
    // Crash recovery for NIP-62: an interrupted walk leaves an
    // in-progress record (and possibly no marker). The writer resumes it
    // before serving, so the remaining history is gone and the completed
    // marker makes a re-delivered request a no-op. A crash between the
    // marker and the pending clear must also be cleaned up.
    use crate::db::store::Store;
    let cfg = config();
    let now = 1_700_000_000u64;
    let pk_a = "ab".repeat(32);
    let pk_b = "cd".repeat(32);
    let authored = |pk: &str, content: &str, created: u64| {
        let mut e = event(1, content, created, vec![]);
        e.pubkey = pk.to_string();
        e.id = nip01::compute_id(&e);
        e
    };
    let a_old = authored(&pk_a, "a-old", now - 10);
    let a_new = authored(&pk_a, "a-new", now - 5);
    let b_old = authored(&pk_b, "b-old", now - 10);
    let a_bytes: [u8; 32] = hex::decode(&pk_a).unwrap().try_into().unwrap();
    let b_bytes: [u8; 32] = hex::decode(&pk_b).unwrap().try_into().unwrap();
    {
        let store = Store::open(
            &cfg,
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            128,
        )
        .unwrap();
        let mut wtxn = store.env.write_txn().unwrap();
        for e in [&a_old, &a_new, &b_old] {
            assert_eq!(
                store.put_event_in(&mut wtxn, e, now).unwrap(),
                PutOutcome::Stored
            );
        }
        wtxn.commit().unwrap();
        let mut wtxn = store.env.write_txn().unwrap();
        // A: the walk removed one event and persisted the in-progress
        // record, but the process died before the marker.
        store
            .remove_event(&mut wtxn, &a_old.id_bytes().unwrap())
            .unwrap();
        store
            .vanish_pending
            .put(&mut wtxn, &a_bytes, &u64::MAX.to_be_bytes())
            .unwrap();
        // B: the marker was committed but the process died before the
        // pending record was cleared.
        store
            .remove_event(&mut wtxn, &b_old.id_bytes().unwrap())
            .unwrap();
        store
            .vanish
            .put(&mut wtxn, &b_bytes, &u64::MAX.to_be_bytes())
            .unwrap();
        store
            .vanish_pending
            .put(&mut wtxn, &b_bytes, &u64::MAX.to_be_bytes())
            .unwrap();
        wtxn.commit().unwrap();
    }
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // A write round trip is ordered after the startup resume (the
        // resume runs on the writer thread before it drains any message),
        // so it is the barrier that makes the reads below deterministic.
        // Querying first could race the resume on the reader threads.
        assert_eq!(
            db.put(event(1, "barrier", now, vec![]), now).await,
            PutOutcome::Stored
        );
        // No event of either pubkey survives (the interrupted walks were
        // completed before the writer served the barrier).
        for pk in [&pk_a, &pk_b] {
            let f: Filter = serde_json::from_value(serde_json::json!({"authors": [pk]})).unwrap();
            let (res, _) = db.query(vec![f], 10, now).await;
            assert!(
                res.is_empty(),
                "the interrupted vanish for {pk} must be completed at startup"
            );
        }
        // The replay short-circuit works after the resume.
        assert_eq!(
            db.apply_vanish_checked(a_bytes, u64::MAX).await,
            Some((0, false))
        );
        assert_eq!(
            db.apply_vanish_checked(b_bytes, u64::MAX).await,
            Some((0, false))
        );
    });
    db.shutdown();
    // Every pending record was cleared.
    let store = Store::open(
        &cfg,
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        128,
    )
    .unwrap();
    let rtxn = store.env.read_txn().unwrap();
    assert_eq!(
        store.vanish_pending.len(&rtxn).unwrap(),
        0,
        "the resume must clear every pending vanish record"
    );
}

#[test]
fn state_stamp_advances_with_group_state_removals() {
    // The persistent derived-group-state generation (consumed by the group
    // snapshot currency check): bumped by a removal of a NIP-29/NIP-43
    // state event via vanish, expiry or group purge, and *not* bumped by an
    // ordinary removal.
    let cfg = config();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = unix_now();
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
        assert_eq!(
            db.state_stamp().await,
            Some(0),
            "a fresh database starts at generation 0"
        );
        let authored = |kind: u64, pk: &str, created: u64| {
            let mut e = event(kind, "x", created, vec![]);
            e.pubkey = pk.to_string();
            e.id = nip01::compute_id(&e);
            e
        };

        // An ordinary post's vanish is not a derived-state change.
        assert_eq!(
            db.put(authored(1, &"aa".repeat(32), now), now).await,
            PutOutcome::Stored
        );
        assert_eq!(
            db.apply_vanish_checked([0xaa; 32], now).await,
            Some((1, false))
        );
        assert_eq!(
            db.state_stamp().await,
            Some(0),
            "an ordinary removal must not bump the stamp"
        );

        // A moderation event's vanish is.
        assert_eq!(
            db.put(authored(9000, &"bb".repeat(32), now), now).await,
            PutOutcome::Stored
        );
        assert_eq!(
            db.apply_vanish_checked([0xbb; 32], now).await,
            Some((1, true))
        );
        assert_eq!(db.state_stamp().await, Some(1));

        // An expired state event removed by NIP-40 is.
        db.set_expiry_enabled(false);
        let mut expiring = authored(9001, &"cc".repeat(32), now - 100);
        expiring.tags = vec![vec!["expiration".into(), (now - 50).to_string()]];
        assert_eq!(db.put(expiring, now).await, PutOutcome::Stored);
        db.set_expiry_enabled(true);
        assert_eq!(db.purge_expired(now, 0).await, (1, true));
        assert_eq!(db.state_stamp().await, Some(2));

        // A group purge bumps the stamp at completion.
        let gid = "stamp-group";
        let tagged = event(1, "group post", now, vec![vec!["h".into(), gid.into()]]);
        assert_eq!(db.put(tagged, now).await, PutOutcome::Stored);
        assert_eq!(db.group_purge(gid.into(), now).await, Some(1));
        assert_eq!(db.state_stamp().await, Some(3));
        db.shutdown();
    });
    // The stamp is persistent: a restart reports the same generation.
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
    rt.block_on(async {
        assert_eq!(db.state_stamp().await, Some(3));
    });
    db.shutdown();
}

#[test]
fn state_seq_advances_with_group_and_role_puts_but_not_ordinary_events() {
    // The derived-state sequence (consumed by the snapshot currency check)
    // advances in the same commit as every NIP-29/NIP-43 state-relevant
    // put, so a debounced snapshot write that was skipped is detectable at
    // startup; an ordinary post leaves it untouched.
    let cfg = config();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = unix_now();
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
        assert_eq!(
            db.state_seq().await,
            Some(0),
            "a fresh database starts at sequence 0"
        );
        let authored = |kind: u64, pk: &str, created: u64| {
            let mut e = event(kind, "x", created, vec![]);
            e.pubkey = pk.to_string();
            e.id = nip01::compute_id(&e);
            e
        };

        // An ordinary post does not advance the state sequence.
        assert_eq!(
            db.put(authored(1, &"aa".repeat(32), now), now).await,
            PutOutcome::Stored
        );
        assert_eq!(db.state_seq().await, Some(0));

        // NIP-29 moderation and join/leave events do.
        assert_eq!(
            db.put(authored(9000, &"bb".repeat(32), now), now).await,
            PutOutcome::Stored
        );
        assert_eq!(db.state_seq().await, Some(1));
        assert_eq!(
            db.put(
                authored(crate::nips::nip29::JOIN, &"cc".repeat(32), now),
                now
            )
            .await,
            PutOutcome::Stored
        );
        assert_eq!(db.state_seq().await, Some(2));

        // NIP-43 role-state events do too.
        assert_eq!(
            db.put(
                authored(crate::nips::nip43::ROLE_DEFINITION, &"dd".repeat(32), now),
                now
            )
            .await,
            PutOutcome::Stored
        );
        assert_eq!(db.state_seq().await, Some(3));

        // A duplicate put does not: the sequence tracks stored events.
        let duplicate = authored(9000, &"bb".repeat(32), now);
        assert!(matches!(
            db.put(duplicate, now).await,
            PutOutcome::Duplicate(_)
        ));
        assert_eq!(db.state_seq().await, Some(3));
        db.shutdown();
    });
    // The sequence is persistent: a restart reports the same value.
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
    rt.block_on(async {
        assert_eq!(db.state_seq().await, Some(3));
    });
    db.shutdown();
}

#[test]
fn nip09_deleting_a_group_state_event_advances_the_stamp() {
    // A NIP-09 deletion removes NIP-29/NIP-43 state events without going
    // through vanish/expiry/purge: the derived-state stamp must advance in
    // the same removal transaction, or a crash after the deletion could
    // restore a snapshot that still authorizes the deleted grant.
    let cfg = config();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = unix_now();
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
        assert_eq!(db.state_stamp().await, Some(0));
        let pk = "aa".repeat(32);
        let authored = |kind: u64, tags: Vec<Vec<String>>, created: u64| {
            let mut e = event(kind, "x", created, tags);
            e.pubkey = pk.clone();
            e.id = nip01::compute_id(&e);
            e
        };

        // An ordinary post's deletion is not a derived-state change.
        let post = authored(1, vec![], now);
        assert_eq!(db.put(post.clone(), now).await, PutOutcome::Stored);
        assert_eq!(
            db.apply_deletion(vec![post.id.clone()], vec![], Some(pk.clone()), now)
                .await,
            1
        );
        assert_eq!(
            db.state_stamp().await,
            Some(0),
            "an ordinary deletion must not bump the stamp"
        );

        // A role definition removed by an `e`-tag target advances the
        // generation (NIP-43 role state is derived from it).
        let role = authored(
            33534,
            vec![vec!["-".into()], vec!["d".into(), "king".into()]],
            now,
        );
        assert_eq!(db.put(role.clone(), now).await, PutOutcome::Stored);
        assert_eq!(
            db.apply_deletion(vec![role.id.clone()], vec![], Some(pk.clone()), now)
                .await,
            1
        );
        assert_eq!(db.state_stamp().await, Some(1));

        // The `a`-tag address walk bumps it too (the address is
        // addressable, so the deletion goes through the replaceable slot
        // walk rather than the `e`-tag path).
        let role = authored(
            33534,
            vec![vec!["-".into()], vec!["d".into(), "queen".into()]],
            now,
        );
        assert_eq!(db.put(role.clone(), now).await, PutOutcome::Stored);
        let address = crate::nips::nip09::Address {
            kind: 33534,
            pubkey: pk.clone(),
            d: "queen".into(),
        };
        assert_eq!(
            db.apply_deletion(vec![], vec![address], Some(pk.clone()), u64::MAX)
                .await,
            1
        );
        assert_eq!(db.state_stamp().await, Some(2));
        // The stamp is persistent across a restart.
        db.shutdown();
    });
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
    rt.block_on(async {
        assert_eq!(db.state_stamp().await, Some(2));
    });
    db.shutdown();
}

#[test]
fn startup_removal_reads_report_failure_when_the_reader_is_gone() {
    // The contracts are startup-checked: `None` means "the database could
    // not answer", so a caller fails closed instead of treating an
    // unreadable pending list/stamp as empty.
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
        assert!(db.pending_purges().await.is_some());
        assert!(db.state_stamp().await.is_some());
        assert!(db.state_seq_group().await.is_some());
        assert!(db.state_seq_role().await.is_some());
        db.shutdown();
        assert!(
            db.pending_purges().await.is_none(),
            "a lost reader must report failure"
        );
        assert!(
            db.state_stamp().await.is_none(),
            "a lost reader must report failure"
        );
        assert!(
            db.state_seq_group().await.is_none(),
            "a lost reader must report the group sequence as unavailable"
        );
        assert!(
            db.state_seq_role().await.is_none(),
            "a lost reader must report the role sequence as unavailable"
        );
    });
}

#[test]
fn disabled_fsync_writer_serves_requests() {
    // With fsync disabled the writer switches to a timed receive so it can
    // sync periodically; requests must keep their normal behavior and the
    // shutdown sync must still run.
    let mut cfg = config();
    cfg.disabled_fsync = true;
    let errors = Arc::new(Default::default());
    let db = DbClient::open(&cfg, true, Arc::clone(&errors), 0, 128, 4096, 262144).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        let e = event(1, "no fsync", now, vec![]);
        assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [e.id]})).unwrap();
        let (res, _) = db.query(vec![f], 10, now).await;
        assert_eq!(res.len(), 1);
        assert_eq!(
            errors.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a healthy no-fsync writer must not report database errors"
        );
    });
    db.shutdown();
}

#[test]
fn timed_receive_wakes_on_a_message_and_times_out() {
    // The writer's periodic-sync receive must wake immediately for a queued
    // message (normal write latency), return TimedOut when idle and Closed
    // once every sender is gone.
    use crate::db::threads::{RecvOutcome, recv_timeout};
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    tx.send(Msg::Shutdown).unwrap();
    let start = std::time::Instant::now();
    assert!(matches!(
        recv_timeout(&mut rx, std::time::Duration::from_secs(5)),
        RecvOutcome::Message(Msg::Shutdown)
    ));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "a queued message must not wait for the timeout"
    );
    assert!(matches!(
        recv_timeout(&mut rx, std::time::Duration::from_millis(20)),
        RecvOutcome::TimedOut
    ));
    // A message sent while the receive is parked wakes it immediately.
    let (tx2, mut rx2) = mpsc::unbounded_channel::<Msg>();
    let sender = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        let _ = tx2.send(Msg::Shutdown);
    });
    let start = std::time::Instant::now();
    assert!(matches!(
        recv_timeout(&mut rx2, std::time::Duration::from_secs(5)),
        RecvOutcome::Message(Msg::Shutdown)
    ));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "a message must unpark the blocked receiver"
    );
    sender.join().unwrap();
    drop(tx);
    assert!(matches!(
        recv_timeout(&mut rx, std::time::Duration::from_millis(20)),
        RecvOutcome::Closed
    ));
}

// ----- reported scans, NIP-09 deletion recovery and shutdown cancellation -----

#[test]
fn reported_scans_return_none_on_a_scan_error() {
    // A store/scan error must never be presented as an empty successful
    // result: the reporting variants answer `None` (the reader drops the
    // reply, like `BlossomLoad`), while the unchecked paths keep their
    // default-empty semantics.
    use crate::db::store::Store;
    let cfg = config();
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = Store::open(&cfg, Arc::clone(&expiry), 128).unwrap();
    let fail_scan = Arc::clone(&store.fail_next_scan);
    let db = DbClient::open_with_store(
        &cfg,
        store,
        expiry,
        Arc::new(Default::default()),
        0,
        128,
        4096,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        db.put(event(1, "stored", now, vec![]), now).await;
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        fail_scan.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            db.query_req_result(vec![f.clone()], 10, now)
                .await
                .is_none(),
            "a failed REQ scan must not look like an empty timeline"
        );
        fail_scan.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            db.count_result(vec![f.clone()], 10, now).await.is_none(),
            "a failed COUNT scan must not look like zero"
        );
        fail_scan.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            db.neg_query_result(f.clone(), 10, now).await.is_none(),
            "a failed NEG scan must not look like an empty item set"
        );
        fail_scan.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            db.aggregate_sample_result(10, now).await.is_none(),
            "a failed aggregate sample must not look like an empty database"
        );
        // The reader keeps serving after the injected errors.
        let (events, _) = db.query(vec![f], 10, now).await;
        assert_eq!(events.len(), 1);
    });
    db.shutdown();
}

#[test]
fn pending_deletion_is_reported_and_resumed_at_startup() {
    // Crash recovery for NIP-09: the interrupted walk leaves its request
    // record (the fault fails after the first chunk committed), and the
    // writer completes it before serving any message on the next start.
    use crate::db::store::Store;
    let cfg = config();
    let now = 1_700_000_000u64;
    let pk = "ab".repeat(32);
    let authored = |kind: u64, content: &str, created: u64, tags: Vec<Vec<String>>| {
        let mut e = event(kind, content, created, tags);
        e.pubkey = pk.clone();
        e.id = nip01::compute_id(&e);
        e
    };
    let post = authored(1, "post", now - 20, vec![]);
    let moderation = authored(
        9000,
        "mod",
        now - 10,
        vec![vec!["h".into(), "pending-del".into()]],
    );
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = Store::open(&cfg, Arc::clone(&expiry), 128).unwrap();
    {
        let mut wtxn = store.env.write_txn().unwrap();
        for e in [&post, &moderation] {
            assert_eq!(
                store.put_event_in(&mut wtxn, e, now).unwrap(),
                PutOutcome::Stored
            );
        }
        wtxn.commit().unwrap();
    }
    // Fail after the first removal chunk committed: the walk is partial
    // (both targets are in one chunk and are gone), the record remains.
    store
        .fail_next_delete_chunk
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let db = DbClient::open_with_store(
        &cfg,
        store,
        expiry,
        Arc::new(Default::default()),
        0,
        128,
        4096,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let targets = vec![post.id.clone(), moderation.id.clone()];
    rt.block_on(async {
        let (removed, state_removed) = db
            .apply_deletion_checked(targets.clone(), vec![], Some(pk.clone()), now)
            .await;
        assert!(
            removed.is_none(),
            "an interrupted deletion must not report a clean count"
        );
        assert!(
            state_removed,
            "the removed moderation event must be reported even though a later chunk failed"
        );
        // The pending record carries the whole request.
        let pending = db
            .pending_deletions()
            .await
            .expect("a healthy pending read must answer");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].targets, targets);
        assert_eq!(pending[0].request_pubkey.as_deref(), Some(pk.as_str()));
        assert_eq!(pending[0].request_created, now);
        assert!(pending[0].addresses.is_empty());
        assert!(pending[0].group.is_none());
        assert_eq!(
            db.table_counts().await.expect("counts").delete_pending,
            1,
            "the in-progress record is visible to the gauges"
        );
        assert_eq!(db.state_stamp().await, Some(1));
    });
    db.shutdown();
    // A restart resumes the pending deletion before serving any message.
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
    rt.block_on(async {
        // The write round trip is ordered after the startup resume (the
        // resume runs on the writer thread before it drains any message),
        // so it is the barrier that makes the reads below deterministic.
        assert_eq!(
            db.put(event(1, "barrier", now, vec![]), now).await,
            PutOutcome::Stored
        );
        assert!(
            db.pending_deletions()
                .await
                .expect("a healthy pending read must answer")
                .is_empty(),
            "the resumed deletion must clear its record"
        );
        assert_eq!(db.table_counts().await.expect("counts").delete_pending, 0);
        let f: Filter = serde_json::from_value(serde_json::json!({"authors": [pk]})).unwrap();
        assert!(db.query(vec![f], 10, now).await.0.is_empty());
    });
    db.shutdown();
}

#[test]
fn interrupted_deletion_resume_removes_remaining_state() {
    // A genuinely partial walk: one target was removed and the record
    // persisted, but the process died before the rest. The startup resume
    // finishes the walk and reports that it removed group state.
    use crate::db::store::{Store, encode_pending_deletion, pending_deletion_key};
    let cfg = config();
    let now = 1_700_000_000u64;
    let pk = "cd".repeat(32);
    let authored = |kind: u64, content: &str, created: u64, tags: Vec<Vec<String>>| {
        let mut e = event(kind, content, created, tags);
        e.pubkey = pk.clone();
        e.id = nip01::compute_id(&e);
        e
    };
    let post = authored(1, "post", now - 20, vec![]);
    let moderation = authored(9000, "mod", now - 10, vec![]);
    let targets = vec![post.id.clone(), moderation.id.clone()];
    {
        let store = Store::open(
            &cfg,
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            128,
        )
        .unwrap();
        let mut wtxn = store.env.write_txn().unwrap();
        for e in [&post, &moderation] {
            assert_eq!(
                store.put_event_in(&mut wtxn, e, now).unwrap(),
                PutOutcome::Stored
            );
        }
        // Simulate the interrupted walk: the post is already removed and
        // the request is recorded, while the moderation event remains.
        store
            .remove_event(&mut wtxn, &post.id_bytes().unwrap())
            .unwrap();
        let encoded = encode_pending_deletion(&targets, &[], Some(&pk), now, None);
        let key = pending_deletion_key(&encoded);
        store.delete_pending.put(&mut wtxn, &key, &encoded).unwrap();
        wtxn.commit().unwrap();
    }
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Barrier: any write is ordered after the startup resume.
        assert_eq!(
            db.put(event(1, "barrier", now, vec![]), now).await,
            PutOutcome::Stored
        );
        assert!(
            db.resumed_deletion_state_removed(),
            "the resume removed the moderation event and must surface it"
        );
        assert!(
            db.pending_deletions()
                .await
                .expect("a healthy pending read must answer")
                .is_empty()
        );
        assert_eq!(db.state_stamp().await, Some(1));
        let f: Filter = serde_json::from_value(serde_json::json!({"authors": [pk]})).unwrap();
        assert!(db.query(vec![f], 10, now).await.0.is_empty());
    });
    db.shutdown();
}

#[test]
fn shutdown_cancellation_aborts_removals_and_leaves_pending() {
    // A long removal must stop at the next chunk boundary when the process
    // is shutting down; the pending record stays so the next startup
    // resumes it (fail-closed). The flag is set on `shutdown`, but tests
    // set it directly to observe the walk without racing the join.
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
        let now = unix_now();
        let post = event(1, "post", now, vec![]);
        let pk = post.pubkey.clone();
        assert_eq!(db.put(post.clone(), now).await, PutOutcome::Stored);
        let gid = "cancel-group";
        let tagged = event(1, "group", now, vec![vec!["h".into(), gid.into()]]);
        assert_eq!(db.put(tagged, now).await, PutOutcome::Stored);
        // An already-expired event (stored while NIP-40 was off) gives the
        // expiry walk a backlog to cancel.
        db.set_expiry_enabled(false);
        let expiring = expired_event("expires", now - 1, now);
        assert_eq!(db.put(expiring, now).await, PutOutcome::Stored);
        db.set_expiry_enabled(true);

        db.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        let (removed, state) = db
            .apply_deletion_checked(vec![post.id.clone()], vec![], Some(pk.clone()), now)
            .await;
        assert!(removed.is_none(), "a cancelled deletion is a failure");
        assert!(!state);
        assert_eq!(
            db.pending_deletions()
                .await
                .expect("a healthy pending read must answer")
                .len(),
            1,
            "the cancelled deletion must leave its resume record"
        );
        let vanish_pk = hex::decode("ef".repeat(32)).unwrap();
        assert_eq!(
            db.apply_vanish_checked(vanish_pk.try_into().unwrap(), now)
                .await,
            None,
            "a cancelled vanish is a failure"
        );
        assert_eq!(
            db.vanish_counts().await.expect("counts").1,
            1,
            "the cancelled vanish must leave its pending record"
        );
        assert_eq!(
            db.group_purge(gid.into(), now).await,
            None,
            "a cancelled purge reports failure, not zero removed"
        );
        assert!(
            !db.pending_purges()
                .await
                .expect("a healthy pending read must answer")
                .is_empty(),
            "the cancelled purge must stay resumable"
        );
        assert_eq!(
            db.purge_expired(now, 0).await,
            (0, false),
            "a cancelled expiry walk stops at the chunk boundary without removing"
        );

        // Clearing the flag lets the retries complete and clear the records.
        db.cancel.store(false, std::sync::atomic::Ordering::SeqCst);
        let (removed, _) = db
            .apply_deletion_checked(vec![post.id.clone()], vec![], Some(pk.clone()), now)
            .await;
        assert_eq!(removed, Some(1));
        assert!(
            db.pending_deletions()
                .await
                .expect("a healthy pending read must answer")
                .is_empty()
        );
        assert_eq!(db.group_purge(gid.into(), now).await, Some(1));
        assert!(
            db.pending_purges()
                .await
                .expect("a healthy pending read must answer")
                .is_empty()
        );
        assert_eq!(
            db.purge_expired(now, 0).await,
            (1, false),
            "the retry after the cancellation clears the expiry backlog"
        );
    });
    db.shutdown();
}

#[test]
fn save_access_and_pubkeys_is_atomic() {
    // The access blob and the relay pubkey lists must move together: a
    // failed commit leaves *both* keys at their previous values.
    use crate::config::AccessControl;
    use crate::db::store::Store;
    let cfg = config();
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = Store::open(&cfg, Arc::clone(&expiry), 128).unwrap();
    let deny = vec![("aa".repeat(32), "first".to_string())];
    let allow = vec![("bb".repeat(32), "first".to_string())];
    let initial = AccessControl {
        allowed_kinds: vec![1],
        ..Default::default()
    };
    store.save_access(&initial).unwrap();
    store.save_relay_pubkeys(&deny, &allow).unwrap();

    let deny2 = vec![("cc".repeat(32), "second".to_string())];
    let allow2 = vec![("dd".repeat(32), "second".to_string())];
    let updated = AccessControl {
        allowed_kinds: vec![1, 2],
        ..Default::default()
    };
    store
        .fail_next_commit
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        store
            .save_access_and_pubkeys(&updated, &deny2, &allow2)
            .is_err(),
        "the injected commit failure must be reported"
    );
    assert_eq!(
        store.load_access().unwrap().unwrap().allowed_kinds,
        vec![1],
        "a failed combined save must not touch the access blob"
    );
    assert_eq!(
        store.load_relay_pubkeys().unwrap(),
        (deny.clone(), allow.clone()),
        "a failed combined save must not touch the pubkey lists"
    );

    assert!(
        store
            .save_access_and_pubkeys(&updated, &deny2, &allow2)
            .is_ok()
    );
    assert_eq!(
        store.load_access().unwrap().unwrap().allowed_kinds,
        vec![1, 2]
    );
    assert_eq!(store.load_relay_pubkeys().unwrap(), (deny2, allow2));
    drop(store);

    // The DbClient wrapper commits both keys in one round trip too.
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let final_access = AccessControl {
            allowed_kinds: vec![3],
            ..Default::default()
        };
        let final_deny = vec![("ee".repeat(32), "final".to_string())];
        assert!(
            db.save_access_and_pubkeys(&final_access, &final_deny, &[])
                .await
        );
        assert!(matches!(
            db.load_access().await,
            LoadAccessOutcome::Loaded(access) if access.allowed_kinds == vec![3]
        ));
        assert_eq!(db.load_relay_pubkeys().await.expect("lists").0, final_deny);
    });
    db.shutdown();
}

#[test]
fn purge_expired_reaps_old_first_seen_entries() {
    // `first_seen` used to grow forever: entries older than the configured
    // new-pubkey gate can never reject a pubkey again and are reaped.
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
        let now = unix_now();
        let old = [1u8; 32];
        let fresh = [2u8; 32];
        db.touch_first_seen_batch(vec![(old, now - 1000), (fresh, now)])
            .await;
        assert_eq!(db.table_counts().await.expect("counts").first_seen, 2);

        assert_eq!(db.purge_expired(now, 500).await, (0, false));
        assert_eq!(
            db.table_counts().await.expect("counts").first_seen,
            1,
            "the stale entry is reaped"
        );
        assert_eq!(
            db.first_seen_batch(vec![old]).await[0],
            (true, 0),
            "the reaped pubkey reads as unknown (and may be recorded again)"
        );
        assert_eq!(
            db.first_seen_batch(vec![fresh]).await[0],
            (false, now),
            "the fresh entry survives"
        );

        // A zero margin disables the reap (the caller passed no gate).
        db.touch_first_seen_batch(vec![(old, now + 1)]).await;
        assert_eq!(db.purge_expired(now + 1, 0).await, (0, false));
        assert_eq!(db.table_counts().await.expect("counts").first_seen, 2);
    });
    db.shutdown();
}

#[test]
fn vanish_pubkeys_raw_page_round_trips() {
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
        let now = unix_now();
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
        for key in keys {
            assert_eq!(db.apply_vanish_checked(key, now).await, Some((0, false)));
        }
        let first = db
            .vanish_pubkeys_raw_page(None, 2)
            .await
            .expect("a healthy page must answer");
        assert_eq!(first, vec![keys[0], keys[1]]);
        let second = db
            .vanish_pubkeys_raw_page(Some(&first[1]), 2)
            .await
            .expect("a healthy page must answer");
        assert_eq!(second, vec![keys[2]]);
        let end = db
            .vanish_pubkeys_raw_page(Some(&second[0]), 2)
            .await
            .expect("a healthy page must answer");
        assert!(end.is_empty());
        assert_eq!(db.table_counts().await.expect("counts").vanish, 3);
    });
    db.shutdown();
}

#[test]
fn health_accessors_report_empty_queue_and_probeable_disk() {
    // The stats writer consumes these inherent accessors (the temporary
    // fallback trait is gone): a fresh client reports an empty queue, no
    // overloads and a probeable filesystem whose fullness matches the same
    // margin the put path uses.
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
    assert_eq!(db.pending_msgs(), 0);
    assert_eq!(db.pending_events(), 0);
    assert_eq!(db.pending_bytes(), 0);
    assert_eq!(db.pending_reads(), 0);
    assert_eq!(db.pending_read_bytes(), 0);
    assert_eq!(db.api_pending(), 0);
    assert_eq!(db.api_pending_bytes(), 0);
    assert_eq!(db.take_overloads(), 0);
    assert!(!db.cancelled(), "a running client is not cancelled");
    let free = db
        .free_disk_bytes()
        .expect("statvfs must answer for the test database path");
    assert_eq!(
        db.disk_full(),
        store::disk_below_margin(free),
        "the accessor must apply the same margin as the put path"
    );
    db.shutdown();
}

#[test]
fn disk_write_margin_boundary_is_exclusive() {
    // The put path refuses to commit below `DISK_FREE_MARGIN`: the pure
    // helper is unit-tested instead of trying to fill a real filesystem to
    // the boundary.
    assert!(store::disk_below_margin(0));
    assert!(store::disk_below_margin(store::DISK_FREE_MARGIN - 1));
    assert!(
        !store::disk_below_margin(store::DISK_FREE_MARGIN),
        "exactly at the margin is not below it"
    );
    assert!(!store::disk_below_margin(store::DISK_FREE_MARGIN + 1));
}

#[test]
fn cap_fail_fast_counts_overloads_not_errors() {
    // A cap rejection is the relay shedding load, not a storage fault: the
    // write, read and API fail-fast paths bump only the overload counter,
    // while a channel send failure (after shutdown) counts neither.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        1,
        262144,
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = unix_now();
    rt.block_on(async {
        // Park one writer message at the cap (1): the next write fails fast.
        db.pending_msgs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ev = event(1, "overload", now, vec![]);
        assert_eq!(
            db.put(ev.clone(), now).await,
            PutOutcome::Invalid("database unavailable".into())
        );
        db.pending_msgs
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        // Reader cap: the shared reader queue is at its cap.
        db.pending_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let filter: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (out, _) = db.query(vec![filter.clone()], 10, now).await;
        assert!(out.is_empty(), "a failed-fast query returns empty");
        db.pending_reads
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        // API cap: the dedicated API reader queue is at its cap.
        db.api_pending
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(
            db.api_count(vec![filter], 10, now).await.is_none(),
            "an API request at the cap must report failure"
        );
        db.api_pending
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(
            db.take_overloads(),
            3,
            "each cap fail-fast must bump the overload counter once"
        );
        assert_eq!(
            db.take_errors(),
            0,
            "a cap fail-fast must not be counted as a database error"
        );

        // After shutdown the send fails: that is neither an overload nor a
        // database fault (no request was queued).
        db.shutdown();
        let _ = db.put(ev, now).await;
        assert_eq!(db.take_overloads(), 0);
        assert_eq!(db.take_errors(), 0);
    });
}

#[test]
fn group_state_events_advance_only_the_group_sequence() {
    // The group snapshot restore check compares against the group-family
    // sequence only: a NIP-43 role event must not cross-invalidate it (and
    // vice versa, see the role test). The legacy combined sequence stays
    // readable as the max.
    let cfg = config();
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = unix_now();
    let authored = |kind: u64, pk: &str, created: u64| {
        let mut e = event(kind, "x", created, vec![]);
        e.pubkey = pk.to_string();
        e.id = nip01::compute_id(&e);
        e
    };
    rt.block_on(async {
        assert_eq!(db.state_seq_group().await, Some(0));
        assert_eq!(db.state_seq_role().await, Some(0));

        // An ordinary post and a NIP-43 role event leave the group
        // sequence untouched.
        assert_eq!(
            db.put(authored(1, &"aa".repeat(32), now), now).await,
            PutOutcome::Stored
        );
        assert_eq!(
            db.put(
                authored(crate::nips::nip43::ROLE_DEFINITION, &"bb".repeat(32), now),
                now
            )
            .await,
            PutOutcome::Stored
        );
        assert_eq!(db.state_seq_group().await, Some(0));
        assert_eq!(db.state_seq_role().await, Some(1));
        assert_eq!(
            db.state_seq().await,
            Some(1),
            "the legacy counter is the combined max"
        );

        // NIP-29 moderation, join and leave events advance the group
        // sequence only.
        assert_eq!(
            db.put(authored(9000, &"cc".repeat(32), now), now).await,
            PutOutcome::Stored
        );
        assert_eq!(db.state_seq_group().await, Some(1));
        assert_eq!(db.state_seq_role().await, Some(1));
        assert_eq!(db.state_seq().await, Some(2));
        assert_eq!(
            db.put(
                authored(crate::nips::nip29::JOIN, &"dd".repeat(32), now),
                now
            )
            .await,
            PutOutcome::Stored
        );
        assert_eq!(
            db.put(
                authored(crate::nips::nip29::LEAVE, &"ee".repeat(32), now),
                now
            )
            .await,
            PutOutcome::Stored
        );
        assert_eq!(db.state_seq_group().await, Some(3));
        assert_eq!(
            db.state_seq_role().await,
            Some(1),
            "NIP-29 events must not advance the role sequence"
        );
        assert_eq!(db.state_seq().await, Some(4));
        db.shutdown();
    });
    // Both counters are persistent across a restart.
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
    rt.block_on(async {
        assert_eq!(db.state_seq_group().await, Some(3));
        assert_eq!(db.state_seq_role().await, Some(1));
        assert_eq!(db.state_seq().await, Some(4));
    });
    db.shutdown();
}

#[test]
fn role_state_events_advance_only_the_role_sequence() {
    // Mirror of the group test: a NIP-29 event must not invalidate a role
    // snapshot.
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
    let now = unix_now();
    let authored = |kind: u64, pk: &str, created: u64| {
        let mut e = event(kind, "x", created, vec![]);
        e.pubkey = pk.to_string();
        e.id = nip01::compute_id(&e);
        e
    };
    rt.block_on(async {
        assert_eq!(
            db.put(authored(9002, &"aa".repeat(32), now), now).await,
            PutOutcome::Stored
        );
        assert_eq!(db.state_seq_group().await, Some(1));
        assert_eq!(db.state_seq_role().await, Some(0));

        for kind in [
            crate::nips::nip43::ROLE_DEFINITION,
            crate::nips::nip43::ADD_USER,
            crate::nips::nip43::REMOVE_USER,
        ] {
            assert_eq!(
                db.put(authored(kind, &"bb".repeat(32), now), now).await,
                PutOutcome::Stored
            );
        }
        assert_eq!(
            db.state_seq_role().await,
            Some(3),
            "each stored role-state event advances the role sequence"
        );
        // NIP-43 JOIN/LEAVE are ephemeral (kind 298xx): they never store,
        // so they must not advance any sequence.
        for kind in [crate::nips::nip43::JOIN, crate::nips::nip43::LEAVE] {
            assert_eq!(
                db.put(authored(kind, &"cc".repeat(32), now), now).await,
                PutOutcome::Ephemeral
            );
        }
        assert_eq!(db.state_seq_role().await, Some(3));
        assert_eq!(
            db.state_seq_group().await,
            Some(1),
            "role events must not advance the group sequence"
        );
        assert_eq!(
            db.state_seq().await,
            Some(4),
            "the legacy counter stays the combined max"
        );
        db.shutdown();
    });
}

#[cfg(unix)]
#[test]
fn access_state_lock_is_exclusive_across_handles() {
    // The daemon and the CLI take this advisory lock around their persisted
    // access read-modify-write: a second acquisition must block until the
    // first guard drops.
    let cfg = config();
    let first = lock_access_state(&cfg.path).expect("the lock file opens");
    let path = cfg.path.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _second = lock_access_state(&path).expect("the second handle opens");
        tx.send(()).unwrap();
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(150))
            .is_err(),
        "a second acquisition must block while the first is held"
    );
    drop(first);
    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok(),
        "the lock must be acquirable once the first guard drops"
    );
    worker.join().unwrap();
}

#[cfg(unix)]
#[test]
fn save_blossom_allow_waits_for_the_access_lock() {
    // The daemon's Blossom-allowlist persist path (the only one, called
    // from the command handler) must take the CLI's cross-process lock: a
    // commit cannot land while the CLI holds the lock.
    let cfg = config();
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let held = lock_access_state(&cfg.path).expect("the lock file opens");
        let saving = {
            let db = db.clone();
            tokio::spawn(async move { db.save_blossom_allow(&["aa".repeat(32)]).await })
        };
        // Give the save task time to reach the blocking lock acquisition.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !saving.is_finished(),
            "the Blossom persist must wait for the access lock"
        );
        drop(held);
        let persisted = tokio::time::timeout(std::time::Duration::from_secs(5), saving)
            .await
            .expect("the persist must proceed once the lock is released")
            .expect("the persist task must not panic");
        assert!(persisted, "the commit must succeed after the wait");
        db.shutdown();
    });
}

#[cfg(unix)]
#[test]
fn save_blossom_allow_locked_skips_the_access_lock() {
    // The `/blossom allow|deny` handler holds the cross-process lock across
    // its read-modify-write and must use the unlocked save: a second `flock`
    // on another descriptor from the same process would block on the
    // caller's own lock. While another handle holds the lock, the unlocked
    // save still commits.
    let cfg = config();
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let held = lock_access_state(&cfg.path).expect("the lock file opens");
        let entries = vec!["bb".repeat(32)];
        let saved = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            db.save_blossom_allow_locked(&entries),
        )
        .await
        .expect("the unlocked save must not wait for the access lock");
        assert!(saved, "the unlocked save must commit");
        assert_eq!(db.try_load_blossom_allow().await.expect("loads"), entries);
        drop(held);
        db.shutdown();
    });
}

// ----- systematic failure injection over the write paths -----

/// Cloneable handles to the test-only fault hooks, kept by tests that arm
/// a hook after the writer thread already owns its `Store`.
struct Faults {
    commit: Arc<std::sync::atomic::AtomicBool>,
    disk_full: Arc<std::sync::atomic::AtomicBool>,
    /// Shared removal-chunk countdown (`1` fails before the first chunk,
    /// `2` after the first committed one).
    chunk_after: Arc<std::sync::atomic::AtomicUsize>,
}

/// Opens a store and a client over it, returning the fault handles: the
/// hooks are shared `Arc`s, so a test can arm and disarm them after
/// startup (arming before the writer starts would let the startup
/// recovery, not the targeted operation, consume them).
fn open_with_faults(cfg: &DatabaseConfig) -> (DbClient, Faults) {
    let expiry = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = crate::db::store::Store::open(cfg, Arc::clone(&expiry), 128).unwrap();
    let faults = Faults {
        commit: Arc::clone(&store.fail_next_commit),
        disk_full: Arc::clone(&store.disk_full_override),
        chunk_after: Arc::clone(&store.fail_chunk_after),
    };
    let db = DbClient::open_with_store(
        cfg,
        store,
        expiry,
        Arc::new(Default::default()),
        0,
        128,
        262_144,
    )
    .unwrap();
    (db, faults)
}

/// Builds an event with an explicit author and a recomputed id.
fn authored_event(
    kind: u64,
    pubkey: &str,
    content: &str,
    created: u64,
    tags: Vec<Vec<String>>,
) -> Event {
    let mut e = event(kind, content, created, tags);
    e.pubkey = pubkey.to_string();
    e.id = nip01::compute_id(&e);
    e
}

/// A NIP-40 event that expires at `expires`.
fn expired_event(content: &str, created: u64, expires: u64) -> Event {
    let mut e = event(
        1,
        content,
        created,
        vec![vec!["expiration".into(), expires.to_string()]],
    );
    e.id = nip01::compute_id(&e);
    e
}

/// A one-group NIP-29 snapshot with the given id.
fn groups_snapshot(gid: &str, now: u64) -> crate::nips::nip29::GroupsSnapshot {
    let mut groups = crate::nips::nip29::GroupStore::with_cap(100);
    groups.apply(
        &crate::nips::nip29::tests::event(
            crate::nips::nip29::CREATE_GROUP,
            crate::nips::nip29::tests::ADMIN,
            Some(gid),
            vec![],
        ),
        "relay",
        now,
        false,
        false,
    );
    groups.snapshot()
}

/// A one-role NIP-43 snapshot with the given role id.
fn roles_snapshot(role: &str) -> crate::nips::nip43::RolesSnapshot {
    let mut roles = crate::nips::nip43::RoleStore::default();
    roles.create(role, role, "", "", None);
    assert!(roles.assign(crate::nips::nip29::tests::USER, role));
    roles.snapshot()
}

/// Loads the persisted group snapshot into a fresh store.
async fn load_groups_restored(db: &DbClient) -> crate::nips::nip29::GroupStore {
    let mut restored = crate::nips::nip29::GroupStore::with_cap(100);
    restored.restore(
        db.load_groups()
            .await
            .expect_loaded("a persisted group snapshot"),
    );
    restored
}

/// Sends one put and waits for its reply. The single-shot operations reply
/// from inside the writer's drain (before its queued-work accounting is
/// released), so only a *flushed* put makes the `pending_*` counters
/// deterministic to assert right after.
async fn writer_barrier(db: &DbClient, now: u64) {
    assert_eq!(
        db.put(event(1, "barrier", now, vec![]), now).await,
        PutOutcome::Stored
    );
}

/// Waits for the reader-side queue counters to drain. The reader sends its
/// reply before releasing the accounting, so a completed read can still be
/// observed with a briefly nonzero counter; the wait is a bounded poll
/// (no fixed sleep) so the assertions that follow are deterministic.
async fn await_reader_counters(db: &DbClient) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if db.pending_reads() == 0
            && db.pending_read_bytes() == 0
            && db.api_pending() == 0
            && db.api_pending_bytes() == 0
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the reader-side queue counters did not drain"
        );
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
}

#[test]
fn commit_failure_write_paths_report_failure_without_partial_state() {
    // Every single-shot write path that honors the one-shot
    // `fail_next_commit` hook must report the failure to its caller
    // (`false` / `Invalid`), leave the pre-operation state untouched, count
    // the failure as a database error (never an overload) and complete on
    // a clean retry.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    rt.block_on(async {
        // Visible pre-state per path.
        let kept = event(1, "kept", now, vec![]);
        assert_eq!(db.put(kept.clone(), now).await, PutOutcome::Stored);
        assert!(db.save_groups(groups_snapshot("g-a", now)).await);
        assert!(db.save_roles(roles_snapshot("alpha")).await);
        let access_a = crate::config::AccessControl {
            allowed_kinds: vec![1],
            ..Default::default()
        };
        let deny_a = vec![("aa".repeat(32), "a".to_string())];
        assert!(db.save_access(access_a.clone()).await);
        assert!(db.save_access_and_pubkeys(&access_a, &deny_a, &[]).await);
        assert!(
            db.blossom_add_owner("sha-keep", "text/plain", 4, 1, &"bb".repeat(32))
                .await
        );

        let by_id = |id: &str| -> Filter {
            serde_json::from_value(serde_json::json!({"ids": [id]})).unwrap()
        };

        // Put batch: the whole aborted batch is revoked.
        faults
            .commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let rejected = event(1, "rejected", now, vec![]);
        let outcomes = db.put_batch(vec![(rejected.clone(), now)]).await;
        assert!(
            outcomes.iter().all(|o| matches!(o, PutOutcome::Invalid(_))),
            "a failed commit must revoke every put in the batch: {outcomes:?}"
        );
        assert!(
            db.query(vec![by_id(&rejected.id)], 10, now)
                .await
                .0
                .is_empty(),
            "the rolled-back put must not be visible"
        );
        assert_eq!(db.query(vec![by_id(&kept.id)], 10, now).await.0.len(), 1);
        assert_eq!(db.take_errors(), 1, "the failed commit is a database error");

        // Group snapshot: a failed commit must not move the snapshot.
        faults
            .commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(!db.save_groups(groups_snapshot("g-b", now)).await);
        let restored = load_groups_restored(&db).await;
        assert!(restored.group("g-a").is_some(), "the old snapshot survives");
        assert!(
            restored.group("g-b").is_none(),
            "the failed save must not land"
        );
        assert_eq!(db.take_errors(), 1);
        assert!(db.save_groups(groups_snapshot("g-b", now)).await);
        let restored = load_groups_restored(&db).await;
        assert!(restored.group("g-b").is_some(), "the retry must commit");

        // Role snapshot.
        faults
            .commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(!db.save_roles(roles_snapshot("beta")).await);
        let mut restored_roles = crate::nips::nip43::RoleStore::default();
        restored_roles.restore(
            db.load_roles()
                .await
                .expect_loaded("a persisted role snapshot"),
        );
        assert!(restored_roles.roles.contains_key("alpha"));
        assert!(!restored_roles.roles.contains_key("beta"));
        assert_eq!(db.take_errors(), 1);
        assert!(db.save_roles(roles_snapshot("beta")).await);
        let mut restored_roles = crate::nips::nip43::RoleStore::default();
        restored_roles.restore(
            db.load_roles()
                .await
                .expect_loaded("a persisted role snapshot"),
        );
        assert!(restored_roles.roles.contains_key("beta"));

        // Clear snapshot.
        faults
            .commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(!db.clear_groups_snapshot().await);
        assert!(
            db.load_groups().await.is_some(),
            "the failed clear must not land"
        );
        assert_eq!(db.take_errors(), 1);
        assert!(db.clear_groups_snapshot().await);
        assert!(db.load_groups().await.is_none(), "the retry must clear");

        // Access save.
        let access_b = crate::config::AccessControl {
            allowed_kinds: vec![1, 2],
            ..Default::default()
        };
        faults
            .commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(!db.save_access(access_b.clone()).await);
        assert!(matches!(
            db.load_access().await,
            LoadAccessOutcome::Loaded(access) if access.allowed_kinds == vec![1]
        ));
        assert_eq!(db.take_errors(), 1);
        assert!(db.save_access(access_b).await);
        assert!(matches!(
            db.load_access().await,
            LoadAccessOutcome::Loaded(access) if access.allowed_kinds == vec![1, 2]
        ));

        // Access + relay pubkeys: both keys move together or not at all.
        let access_c = crate::config::AccessControl {
            allowed_kinds: vec![3],
            ..Default::default()
        };
        let deny_c = vec![("cc".repeat(32), "c".to_string())];
        faults
            .commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(!db.save_access_and_pubkeys(&access_c, &deny_c, &[]).await);
        assert_eq!(
            db.load_relay_pubkeys().await.expect("lists"),
            (deny_a, Vec::new())
        );
        assert!(matches!(
            db.load_access().await,
            LoadAccessOutcome::Loaded(access) if access.allowed_kinds == vec![1, 2]
        ));
        assert_eq!(db.take_errors(), 1);
        assert!(db.save_access_and_pubkeys(&access_c, &deny_c, &[]).await);
        assert_eq!(
            db.load_relay_pubkeys().await.expect("lists").0,
            deny_c,
            "the retry must persist both keys"
        );

        // Blossom owner add.
        let owner = "dd".repeat(32);
        faults
            .commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            !db.blossom_add_owner("sha-new", "text/plain", 7, 2, &owner)
                .await
        );
        assert!(
            db.blossom_list(&owner, 10).await.is_empty(),
            "the failed mapping must not appear in the reverse index"
        );
        assert_eq!(db.take_errors(), 1);
        assert!(
            db.blossom_add_owner("sha-new", "text/plain", 7, 2, &owner)
                .await
        );
        assert_eq!(db.blossom_list(&owner, 10).await, vec!["sha-new"]);

        // Blossom mapping batch (the one-time auto-migration path).
        let owner_b = "ee".repeat(32);
        let batch = || {
            vec![(
                "sha-batch".to_string(),
                "text/plain".to_string(),
                1,
                3,
                owner_b.clone(),
            )]
        };
        faults
            .commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(!db.blossom_add_mappings(batch()).await);
        assert!(db.blossom_list(&owner_b, 10).await.is_empty());
        assert_eq!(db.take_errors(), 1);
        assert!(db.blossom_add_mappings(batch()).await);
        assert_eq!(db.blossom_list(&owner_b, 10).await, vec!["sha-batch"]);

        // Every queued-work reservation returned to zero; the failures were
        // database errors, never cap (overload) rejections.
        writer_barrier(&db, now).await;
        await_reader_counters(&db).await;
        assert_eq!(db.pending_msgs(), 0);
        assert_eq!(db.pending_events(), 0);
        assert_eq!(db.pending_bytes(), 0);
        assert_eq!(db.pending_reads(), 0);
        assert_eq!(db.pending_read_bytes(), 0);
        assert_eq!(db.api_pending(), 0);
        assert_eq!(db.take_errors(), 0, "every injected error was drained");
        assert_eq!(db.take_overloads(), 0);
    });
    db.shutdown();
}

#[test]
fn disk_full_write_paths_report_failure_without_partial_state() {
    // The test-only disk-full override makes every guarded write path
    // refuse before touching the map: the caller sees the failure, the
    // pre-operation state stays, the refusal is counted as a database
    // error and a clean retry (after the override clears) completes.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    rt.block_on(async {
        let kept = event(1, "kept", now, vec![]);
        assert_eq!(db.put(kept.clone(), now).await, PutOutcome::Stored);
        assert!(db.save_groups(groups_snapshot("g-a", now)).await);
        assert!(db.save_roles(roles_snapshot("alpha")).await);
        assert!(
            db.save_access(crate::config::AccessControl::default())
                .await
        );

        faults
            .disk_full
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Put batch: every put is refused with the disk-full reason.
        let rejected = event(1, "rejected", now, vec![]);
        let outcomes = db.put_batch(vec![(rejected.clone(), now)]).await;
        assert!(
            outcomes.iter().all(
                |o| matches!(o, PutOutcome::Invalid(reason) if reason.contains("disk is full"))
            ),
            "a put on a full disk must be refused: {outcomes:?}"
        );
        let by_id = |id: &str| -> Filter {
            serde_json::from_value(serde_json::json!({"ids": [id]})).unwrap()
        };
        assert!(
            db.query(vec![by_id(&rejected.id)], 10, now)
                .await
                .0
                .is_empty()
        );
        assert_eq!(db.take_errors(), 1);

        // Snapshot/access/Blossom writes refuse and leave the old value.
        assert!(!db.save_groups(groups_snapshot("g-b", now)).await);
        let restored = load_groups_restored(&db).await;
        assert!(restored.group("g-a").is_some() && restored.group("g-b").is_none());
        assert_eq!(db.take_errors(), 1);

        assert!(!db.save_roles(roles_snapshot("beta")).await);
        let mut restored_roles = crate::nips::nip43::RoleStore::default();
        restored_roles.restore(
            db.load_roles()
                .await
                .expect_loaded("a persisted role snapshot"),
        );
        assert!(restored_roles.roles.contains_key("alpha"));
        assert!(!restored_roles.roles.contains_key("beta"));
        assert_eq!(db.take_errors(), 1);

        assert!(!db.clear_groups_snapshot().await);
        assert!(db.load_groups().await.is_some());
        assert_eq!(db.take_errors(), 1);

        let access_b = crate::config::AccessControl {
            allowed_kinds: vec![1, 2],
            ..Default::default()
        };
        assert!(!db.save_access(access_b.clone()).await);
        assert!(matches!(
            db.load_access().await,
            LoadAccessOutcome::Loaded(access) if access.allowed_kinds.is_empty()
        ));
        assert_eq!(db.take_errors(), 1);

        let deny_b = vec![("cc".repeat(32), "c".to_string())];
        assert!(!db.save_access_and_pubkeys(&access_b, &deny_b, &[]).await);
        assert_eq!(
            db.load_relay_pubkeys().await.expect("lists"),
            (Vec::new(), Vec::new())
        );
        assert_eq!(db.take_errors(), 1);

        let owner = "dd".repeat(32);
        assert!(
            !db.blossom_add_owner("sha-new", "text/plain", 1, 1, &owner)
                .await
        );
        assert!(db.blossom_list(&owner, 10).await.is_empty());
        assert_eq!(db.take_errors(), 1);
        assert!(
            !db.blossom_add_mappings(vec![(
                "sha-batch".to_string(),
                "text/plain".to_string(),
                1,
                1,
                owner.clone(),
            )])
            .await
        );
        assert!(db.blossom_list(&owner, 10).await.is_empty());
        assert_eq!(db.take_errors(), 1);

        // Disarm: the same writes now commit.
        faults
            .disk_full
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(db.put(rejected.clone(), now).await, PutOutcome::Stored);
        assert!(db.save_groups(groups_snapshot("g-b", now)).await);
        assert!(db.save_roles(roles_snapshot("beta")).await);
        assert!(db.save_access(access_b.clone()).await);
        assert!(db.save_access_and_pubkeys(&access_b, &deny_b, &[]).await);
        assert!(
            db.blossom_add_owner("sha-new", "text/plain", 1, 1, &owner)
                .await
        );
        assert!(
            db.blossom_add_mappings(vec![(
                "sha-batch".to_string(),
                "text/plain".to_string(),
                1,
                1,
                owner.clone(),
            )])
            .await
        );

        writer_barrier(&db, now).await;
        assert_eq!(db.pending_msgs(), 0);
        assert_eq!(db.pending_events(), 0);
        assert_eq!(db.pending_bytes(), 0);
        assert_eq!(db.take_errors(), 0, "every injected error was drained");
        assert_eq!(db.take_overloads(), 0);
    });
    db.shutdown();
}

#[test]
fn disk_full_removals_fail_closed_before_any_side_effect() {
    // A full disk must fail every chunked removal before its first write
    // (no pending record, no tombstone, no marker, nothing removed): the
    // removal is retried once the filesystem has room again.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    let pk = "ab".repeat(32);
    let post = authored_event(1, &pk, "post", now - 10, vec![]);
    let gid = "disk-full-group";
    let tagged = event(1, "group", now - 5, vec![vec!["h".into(), gid.into()]]);
    let wrap_recipient = "cd".repeat(32);
    let wrap = {
        let mut e = event(
            crate::nips::nip62::GIFT_WRAP_KIND,
            "wrap",
            now - 4,
            vec![vec!["p".into(), wrap_recipient.clone()]],
        );
        e.id = nip01::compute_id(&e);
        e
    };
    let expiring = expired_event("expired", now - 3, now);
    let recipient_bytes: [u8; 32] = hex::decode(&wrap_recipient).unwrap().try_into().unwrap();
    rt.block_on(async {
        assert_eq!(db.put(post.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(tagged.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(wrap.clone(), now).await, PutOutcome::Stored);
        db.set_expiry_enabled(false);
        assert_eq!(db.put(expiring.clone(), now).await, PutOutcome::Stored);
        db.set_expiry_enabled(true);

        faults
            .disk_full
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let (removed, state) = db
            .apply_deletion_checked(vec![post.id.clone()], vec![], Some(pk.clone()), now)
            .await;
        assert_eq!(removed, None, "a full-disk deletion must report failure");
        assert!(!state);
        assert!(
            db.pending_deletions().await.expect("pending").is_empty(),
            "a refusal before the walk must not write a delete record"
        );
        assert_eq!(db.take_errors(), 1);

        assert_eq!(
            db.apply_vanish_checked([0xab; 32], now).await,
            None,
            "a full-disk vanish must report failure"
        );
        assert_eq!(
            db.vanish_counts().await.expect("counts"),
            (0, 0),
            "a refusal before the walk must not write a pending vanish"
        );
        assert_eq!(db.take_errors(), 1);

        assert_eq!(
            db.group_purge(gid.to_string(), now).await,
            None,
            "a full-disk purge must report failure, not zero removed"
        );
        assert!(
            db.pending_purges().await.expect("pending").is_empty(),
            "a refusal before the walk must not write a purge record"
        );
        assert_eq!(db.take_errors(), 1);

        assert_eq!(db.purge_expired(now, 0).await, (0, false));
        assert_eq!(db.take_errors(), 1);

        assert_eq!(
            db.delete_gift_wraps_to_checked(recipient_bytes, u64::MAX)
                .await,
            None,
            "a full-disk gift-wrap purge must report failure"
        );
        assert_eq!(db.take_errors(), 1);

        // Nothing moved while the disk was "full".
        let f: Filter = serde_json::from_value(serde_json::json!({"authors": [pk]})).unwrap();
        assert_eq!(db.query(vec![f], 10, now).await.0.len(), 1);
        let h: Filter = serde_json::from_value(serde_json::json!({"#h": [gid]})).unwrap();
        assert_eq!(db.query(vec![h], 10, now).await.0.len(), 1);
        assert_eq!(db.state_stamp().await, Some(0));

        // With room again, every removal completes normally.
        faults
            .disk_full
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            db.apply_deletion_checked(vec![post.id.clone()], vec![], Some(pk.clone()), now)
                .await
                .0,
            Some(1)
        );
        assert_eq!(
            db.apply_vanish_checked([0xab; 32], now).await,
            Some((0, false)),
            "the post was already deleted, only the marker is written"
        );
        assert_eq!(db.group_purge(gid.to_string(), now).await, Some(1));
        db.set_expiry_enabled(true);
        assert_eq!(db.purge_expired(now, 0).await, (1, false));
        assert_eq!(
            db.delete_gift_wraps_to_checked(recipient_bytes, u64::MAX)
                .await,
            Some(1)
        );
        assert_eq!(db.take_errors(), 0);
        assert_eq!(db.take_overloads(), 0);
        writer_barrier(&db, now).await;
        assert_eq!(db.pending_msgs(), 0);
        assert_eq!(db.pending_events(), 0);
    });
    db.shutdown();
}

#[test]
fn nip09_first_chunk_failure_stays_pending_until_startup_resume() {
    // The chunk fault fails before the first removal chunk: nothing is
    // removed, but the request record is already durable. The writer's
    // startup resume (which runs before it serves any message) completes
    // the deletion and reports that it removed a group-state event.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    let pk = "ab".repeat(32);
    let post = authored_event(1, &pk, "post", now - 20, vec![]);
    let moderation = authored_event(9000, &pk, "mod", now - 10, vec![]);
    let author_filter =
        || -> Filter { serde_json::from_value(serde_json::json!({"authors": [pk]})).unwrap() };
    rt.block_on(async {
        assert_eq!(db.put(post.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(moderation.clone(), now).await, PutOutcome::Stored);
        faults
            .chunk_after
            .store(1, std::sync::atomic::Ordering::SeqCst);
        let (removed, state) = db
            .apply_deletion_checked(
                vec![post.id.clone(), moderation.id.clone()],
                vec![],
                Some(pk.clone()),
                now,
            )
            .await;
        assert!(
            removed.is_none(),
            "an interrupted deletion must report failure instead of zero"
        );
        assert!(!state, "nothing was removed yet");
        assert_eq!(
            db.table_counts().await.expect("counts").delete_pending,
            1,
            "the record must survive the failure"
        );
        assert_eq!(
            db.query(vec![author_filter()], 10, now).await.0.len(),
            2,
            "the interrupted walk must leave the history stored"
        );
        assert_eq!(db.state_stamp().await, Some(0));
        assert_eq!(db.take_errors(), 1);
    });
    db.shutdown();

    // A restart resumes the recorded deletion before serving any message.
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
    rt.block_on(async {
        // The write round trip is the barrier that orders the reads after
        // the writer's startup resume.
        assert_eq!(
            db.put(event(1, "barrier", now, vec![]), now).await,
            PutOutcome::Stored
        );
        assert!(
            db.resumed_deletion_state_removed(),
            "the resume removed the moderation event and must surface it"
        );
        assert!(
            db.pending_deletions()
                .await
                .expect("a healthy pending read must answer")
                .is_empty()
        );
        assert_eq!(db.table_counts().await.expect("counts").delete_pending, 0);
        assert_eq!(db.state_stamp().await, Some(1));
        assert!(db.query(vec![author_filter()], 10, now).await.0.is_empty());
    });
    db.shutdown();
}

#[test]
fn nip09_middle_chunk_failure_resumes_at_startup() {
    // Three target chunks (the walk sits at chunk boundaries because the
    // targets exceed `REMOVAL_CHUNK`): the fault fires before the second
    // chunk, leaving the first committed, the state event in the last
    // chunk and the request record durable. The startup resume finishes
    // the remaining chunks and clears the record.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    let pk = "cd".repeat(32);
    let moderation = authored_event(9000, &pk, "mod", now, vec![]);
    let author_filter =
        || -> Filter { serde_json::from_value(serde_json::json!({"authors": [pk]})).unwrap() };
    let mut targets: Vec<String> = (0..(2 * 4096)).map(|i| format!("{i:064x}")).collect();
    targets.push(moderation.id.clone());
    rt.block_on(async {
        assert_eq!(db.put(moderation.clone(), now).await, PutOutcome::Stored);
        faults
            .chunk_after
            .store(2, std::sync::atomic::Ordering::SeqCst);
        let (removed, state) = db
            .apply_deletion_checked(targets.clone(), vec![], Some(pk.clone()), now)
            .await;
        assert!(
            removed.is_none(),
            "the failed middle chunk must report failure"
        );
        assert!(!state, "the state event was not reached yet");
        assert_eq!(db.table_counts().await.expect("counts").delete_pending, 1);
        assert_eq!(
            db.query(vec![author_filter()], 10, now).await.0.len(),
            1,
            "the last chunk must survive the failed earlier chunk"
        );
        assert_eq!(db.state_stamp().await, Some(0));
        assert_eq!(db.take_errors(), 1);
    });
    db.shutdown();

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
    rt.block_on(async {
        assert_eq!(
            db.put(event(1, "barrier", now, vec![]), now).await,
            PutOutcome::Stored
        );
        assert!(
            db.resumed_deletion_state_removed(),
            "the resume must remove the remaining moderation event"
        );
        assert!(
            db.pending_deletions()
                .await
                .expect("a healthy pending read must answer")
                .is_empty()
        );
        assert_eq!(db.state_stamp().await, Some(1));
        assert!(db.query(vec![author_filter()], 10, now).await.0.is_empty());
    });
    db.shutdown();
}

#[test]
fn delegated_address_tombstone_survives_a_mid_walk_crash() {
    // A delegated NIP-09 `a`-tag deletion must not lose its address guard
    // when a crash lands between a committed removal chunk and the
    // post-walk tombstone merge: the guard now rides along in the same
    // chunk transaction as its first removal, so the resume (finding zero
    // versions) still blocks re-publication of old versions. Unmatched
    // delegations still leave no tombstone. Backward compatible: no pending
    // format change, the tombstone key/value are unchanged.
    use secp256k1::{Keypair, Secp256k1};
    use sha2::{Digest, Sha256};
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    let secp = Secp256k1::new();
    let delegator_kp = Keypair::from_seckey_slice(&secp, &[11u8; 32]).unwrap();
    let delegatee_kp = Keypair::from_seckey_slice(&secp, &[12u8; 32]).unwrap();
    let delegator = hex::encode(delegator_kp.x_only_public_key().0.serialize());
    let delegatee = hex::encode(delegatee_kp.x_only_public_key().0.serialize());
    let conditions = "kind=30001";
    let payload = format!("nostr:delegation:{delegatee}:{conditions}");
    let message: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
    let token = secp
        .sign_schnorr_no_aux_rand(&message, &delegator_kp)
        .to_string();
    let mut ev = authored_event(
        30001,
        &delegatee,
        "delegated profile",
        now,
        vec![
            vec!["d".into(), "del".into()],
            vec![
                "delegation".into(),
                delegator.clone(),
                conditions.into(),
                token,
            ],
        ],
    );
    ev.id = nip01::compute_id(&ev);
    let addr = crate::nips::nip09::Address {
        kind: 30001,
        pubkey: delegatee.clone(),
        d: "del".into(),
    };
    rt.block_on(async {
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
        // Fail after the first committed chunk (countdown 2): the chunk
        // holding the removal commits, then the walk errors before the
        // post-walk tombstone merge.
        faults
            .chunk_after
            .store(2, std::sync::atomic::Ordering::SeqCst);
        let (removed, _) = db
            .apply_deletion_checked(vec![], vec![addr.clone()], Some(delegator.clone()), now)
            .await;
        assert!(
            removed.is_none(),
            "the mid-walk crash must report failure"
        );
        // The version is gone.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [30001]})).unwrap();
        assert!(db.query(vec![f], 10, now).await.0.is_empty());
        // A never-stored old version of the same address (different id, no
        // per-id tombstone) must still be blocked by the address guard —
        // without the in-chunk tombstone it would be Stored here.
        let mut older = authored_event(
            30001,
            &delegatee,
            "forged old version",
            now,
            vec![vec!["d".into(), "del".into()]],
        );
        older.id = nip01::compute_id(&older);
        assert!(
            matches!(
                db.put(older.clone(), now).await,
                PutOutcome::PreviouslyDeleted
            ),
            "the crashed delegated deletion must still guard the address"
        );
        // Replaying the request (the startup resume path) completes cleanly
        // and keeps the guard.
        let (removed, _) = db
            .apply_deletion_checked(vec![], vec![addr], Some(delegator), now)
            .await;
        assert_eq!(removed, Some(0));
        assert!(
            matches!(
                db.put(older, now).await,
                PutOutcome::PreviouslyDeleted
            ),
            "the resumed deletion must keep guarding the address"
        );
    });
    db.shutdown();
}

#[test]
fn vanish_first_chunk_failure_stays_pending_until_startup_resume() {
    // The vanish fault fails before the first removal chunk: the pending
    // record is durable, no completed marker exists, the history survives.
    // The restart's startup resume completes the walk, writes the marker
    // and clears the record.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    let pk = "cd".repeat(32);
    let pk_bytes: [u8; 32] = hex::decode(&pk).unwrap().try_into().unwrap();
    let post = authored_event(1, &pk, "post", now - 10, vec![]);
    let moderation = authored_event(9000, &pk, "mod", now - 5, vec![]);
    let author_filter =
        || -> Filter { serde_json::from_value(serde_json::json!({"authors": [pk]})).unwrap() };
    rt.block_on(async {
        assert_eq!(db.put(post.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(moderation.clone(), now).await, PutOutcome::Stored);
        faults
            .chunk_after
            .store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            db.apply_vanish_checked(pk_bytes, now).await,
            None,
            "the interrupted vanish must report failure"
        );
        assert_eq!(
            db.vanish_counts().await.expect("counts"),
            (0, 1),
            "the pending record must exist without a completed marker"
        );
        assert_eq!(db.state_stamp().await, Some(0));
        assert_eq!(db.query(vec![author_filter()], 10, now).await.0.len(), 2);
        assert_eq!(db.take_errors(), 1);
    });
    db.shutdown();
    // The completed marker was not written by the interrupted walk.
    {
        let store = crate::db::store::Store::open(
            &cfg,
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            128,
        )
        .unwrap();
        let rtxn = store.env.read_txn().unwrap();
        assert!(
            store.vanish.get(&rtxn, &pk_bytes).unwrap().is_none(),
            "an interrupted vanish must not write the completed marker"
        );
    }

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
    rt.block_on(async {
        assert_eq!(
            db.put(event(1, "barrier", now, vec![]), now).await,
            PutOutcome::Stored
        );
        assert_eq!(
            db.vanish_counts().await.expect("counts"),
            (1, 0),
            "the startup resume must complete the vanish and clear the record"
        );
        assert_eq!(db.state_stamp().await, Some(1));
        assert!(db.query(vec![author_filter()], 10, now).await.0.is_empty());
        assert!(
            matches!(
                db.put(authored_event(1, &pk, "after", now + 1, vec![]), now + 1)
                    .await,
                PutOutcome::Invalid(reason) if reason.contains("vanish")
            ),
            "the resumed vanish must bar the pubkey"
        );
        assert_eq!(
            db.apply_vanish_checked(pk_bytes, now).await,
            Some((0, false))
        );
    });
    db.shutdown();
}

#[test]
fn vanish_middle_chunk_failure_resumes_at_startup() {
    // 4097 authored events: the moderation state event sorts into the
    // first `by_pubkey` chunk (smallest created_at). Failing before the
    // second chunk leaves the first one removed with the stamp already
    // bumped; the startup resume finishes the rest.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    let base = now - 10_000;
    let pk = "ef".repeat(32);
    let pk_bytes: [u8; 32] = hex::decode(&pk).unwrap().try_into().unwrap();
    let author_filter =
        || -> Filter { serde_json::from_value(serde_json::json!({"authors": [pk]})).unwrap() };
    let mut events: Vec<(Event, u64)> =
        vec![(authored_event(9000, &pk, "mod", base, vec![]), base)];
    for i in 0..4096 {
        events.push((
            authored_event(1, &pk, &format!("post-{i}"), base + 1, vec![]),
            base + 1,
        ));
    }
    rt.block_on(async {
        let outcomes = db.put_batch(events).await;
        assert!(
            outcomes.iter().all(|o| matches!(o, PutOutcome::Stored)),
            "the seed batch must store every event"
        );
        faults
            .chunk_after
            .store(2, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            db.apply_vanish_checked(pk_bytes, now).await,
            None,
            "the failed middle chunk must report failure"
        );
        assert_eq!(db.vanish_counts().await.expect("counts"), (0, 1));
        assert_eq!(
            db.state_stamp().await,
            Some(1),
            "the first chunk committed its state-stamp bump"
        );
        assert_eq!(
            db.query(vec![author_filter()], 10_000, now).await.0.len(),
            1,
            "only the final chunk survives"
        );
        assert_eq!(db.take_errors(), 1);
    });
    db.shutdown();

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
    rt.block_on(async {
        assert_eq!(
            db.put(event(1, "barrier", now, vec![]), now).await,
            PutOutcome::Stored
        );
        assert_eq!(db.vanish_counts().await.expect("counts"), (1, 0));
        assert_eq!(db.state_stamp().await, Some(1));
        assert!(
            db.query(vec![author_filter()], 10_000, now)
                .await
                .0
                .is_empty()
        );
    });
    db.shutdown();
}

#[test]
fn group_purge_first_chunk_failure_resumes_after_restart() {
    // The purge fault fails before the first removal chunk: the marker and
    // the in-progress record are durable (a replay is fail-closed), the
    // history stays stored and the stamp is not bumped (the completion
    // commit did not run). After a restart the caller re-issues the purge,
    // which completes it and clears the record.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    let gid = "first-chunk-group";
    let tagged = |kind: u64, content: &str, created: u64| {
        event(kind, content, created, vec![vec!["h".into(), gid.into()]])
    };
    let history =
        || -> Filter { serde_json::from_value(serde_json::json!({"#h": [gid]})).unwrap() };
    rt.block_on(async {
        assert_eq!(
            db.put(tagged(1, "post", now - 10), now).await,
            PutOutcome::Stored
        );
        assert_eq!(
            db.put(tagged(9000, "mod", now - 5), now).await,
            PutOutcome::Stored
        );
        faults
            .chunk_after
            .store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            db.group_purge(gid.to_string(), now).await,
            None,
            "an interrupted purge reports failure, not zero removed"
        );
        assert_eq!(
            db.pending_purges()
                .await
                .expect("a healthy read must answer"),
            vec![(gid.to_string(), now, u64::MAX)],
            "the interrupted purge must stay resumable"
        );
        assert_eq!(
            db.state_stamp().await,
            Some(0),
            "the completion commit that bumps the stamp did not run"
        );
        assert_eq!(db.query(vec![history()], 10, now).await.0.len(), 2);
        // The marker is already committed: a replayed history event is
        // rejected even though the history is still stored.
        assert_eq!(
            db.put(tagged(1, "replay", now), now).await,
            PutOutcome::PreviouslyDeleted
        );
        assert_eq!(db.take_errors(), 1);
    });
    db.shutdown();

    // The writer only auto-resumes vanish/delete records; the caller
    // re-issues pending purges after startup (idempotent, furthest cut).
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
    rt.block_on(async {
        assert_eq!(
            db.pending_purges()
                .await
                .expect("a healthy read must answer"),
            vec![(gid.to_string(), now, u64::MAX)]
        );
        assert_eq!(db.group_purge(gid.to_string(), now).await, Some(2));
        assert!(
            db.pending_purges()
                .await
                .expect("a healthy read must answer")
                .is_empty(),
            "the completed re-issue must clear the record"
        );
        assert_eq!(db.state_stamp().await, Some(1));
        assert!(db.query(vec![history()], 10, now).await.0.is_empty());
    });
    db.shutdown();
}

#[test]
fn group_purge_middle_chunk_failure_resumes_after_restart() {
    // 4097 h-tagged events: the moderation state event sorts into the first
    // `by_tag` chunk (smallest created_at). The fault fires before the
    // second chunk, leaving the first 4096 removed (the pending record
    // durable and the stamp still untouched, since the completion commit
    // is what bumps it). The re-issued purge after a restart finishes the
    // walk, clears the record and bumps the stamp.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    let base = now - 10_000;
    let gid = "middle-chunk-group";
    let tagged = |kind: u64, content: &str, created: u64| {
        event(kind, content, created, vec![vec!["h".into(), gid.into()]])
    };
    let history =
        || -> Filter { serde_json::from_value(serde_json::json!({"#h": [gid]})).unwrap() };
    let mut events: Vec<(Event, u64)> = vec![(tagged(9000, "mod", base), base)];
    for i in 0..4096 {
        events.push((tagged(1, &format!("g-{i}"), base + 1), base + 1));
    }
    rt.block_on(async {
        let outcomes = db.put_batch(events).await;
        assert!(outcomes.iter().all(|o| matches!(o, PutOutcome::Stored)));
        faults
            .chunk_after
            .store(2, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            db.group_purge(gid.to_string(), now).await,
            None,
            "a failed purge reports failure, not the partial count"
        );
        assert_eq!(
            db.pending_purges()
                .await
                .expect("a healthy read must answer")
                .len(),
            1
        );
        assert_eq!(
            db.state_stamp().await,
            Some(0),
            "the completion commit that bumps the stamp did not run"
        );
        assert_eq!(
            db.query(vec![history()], 10_000, now).await.0.len(),
            1,
            "the final chunk survives"
        );
        assert_eq!(db.take_errors(), 1);
    });
    db.shutdown();

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
    rt.block_on(async {
        assert_eq!(
            db.pending_purges()
                .await
                .expect("a healthy read must answer")
                .len(),
            1
        );
        assert_eq!(db.group_purge(gid.to_string(), now).await, Some(1));
        assert!(
            db.pending_purges()
                .await
                .expect("a healthy read must answer")
                .is_empty()
        );
        assert_eq!(db.state_stamp().await, Some(1));
        assert!(db.query(vec![history()], 10_000, now).await.0.is_empty());
    });
    db.shutdown();
}

#[test]
fn purge_expired_first_and_middle_chunk_failures_leave_a_resumable_backlog() {
    // NIP-40 has no pending record: a failed pass simply stops at the chunk
    // boundary and the next pass resumes it. The first half fails before
    // any removal; the second half fails before the second chunk of a
    // 4098-event backlog (the moderation state event sorts first), leaving
    // the first chunk removed with the stamp already bumped.
    let cfg = config();
    let (db, faults) = open_with_faults(&cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = 1_700_000_000u64;
    let kind_filter =
        || -> Filter { serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap() };
    rt.block_on(async {
        // First-chunk failure: stored while expiry is off, then purged.
        db.set_expiry_enabled(false);
        let e1 = expired_event("e1", now - 3, now);
        let e2 = expired_event("e2", now - 2, now);
        assert_eq!(db.put(e1, now).await, PutOutcome::Stored);
        assert_eq!(db.put(e2, now).await, PutOutcome::Stored);
        db.set_expiry_enabled(true);
        faults
            .chunk_after
            .store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(db.purge_expired(now, 0).await, (0, false));
        assert_eq!(db.take_errors(), 1);
        // The scan hides expired events while NIP-40 is on, so read them
        // with the feature off to observe the stored (unpurged) backlog.
        db.set_expiry_enabled(false);
        assert_eq!(
            db.query(vec![kind_filter()], 10, now).await.0.len(),
            2,
            "a pass that never reached a chunk removes nothing"
        );
        db.set_expiry_enabled(true);
        assert_eq!(db.purge_expired(now, 0).await, (2, false));
        assert!(db.query(vec![kind_filter()], 10, now).await.0.is_empty());

        // Middle-chunk failure: 4098 expired events, the moderation state
        // event with the smallest expiration (first in the expiry index).
        db.set_expiry_enabled(false);
        let mut batch: Vec<(Event, u64)> = Vec::with_capacity(4098);
        let mut state = event(9000, "mod", now - 5, vec![]);
        state.tags = vec![vec!["expiration".into(), (now - 100).to_string()]];
        state.id = nip01::compute_id(&state);
        batch.push((state, now));
        for i in 0..4097 {
            batch.push((expired_event(&format!("x-{i}"), now - 4, now - 50), now));
        }
        let outcomes = db.put_batch(batch).await;
        assert!(outcomes.iter().all(|o| matches!(o, PutOutcome::Stored)));
        db.set_expiry_enabled(true);
        faults
            .chunk_after
            .store(2, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            db.purge_expired(now, 0).await,
            (4096, true),
            "the first chunk committed (with its state event) before the failure"
        );
        assert_eq!(db.state_stamp().await, Some(1));
        assert_eq!(db.take_errors(), 1);
        db.set_expiry_enabled(false);
        assert_eq!(
            db.query(vec![kind_filter()], 10_000, now).await.0.len(),
            2,
            "the second chunk is still purgeable"
        );
        db.set_expiry_enabled(true);
        assert_eq!(
            db.purge_expired(now, 0).await,
            (2, false),
            "the state event was removed by the first pass"
        );
        assert!(
            db.query(vec![kind_filter()], 10_000, now)
                .await
                .0
                .is_empty()
        );

        // No bookkeeping record exists for expiry, and the failure never
        // leaked into the writer's queued-work accounting.
        assert_eq!(db.table_counts().await.expect("counts").purge_pending, 0);
        assert_eq!(db.table_counts().await.expect("counts").delete_pending, 0);
        assert_eq!(db.vanish_counts().await.expect("counts").1, 0);
        assert_eq!(db.take_errors(), 0);
        assert_eq!(db.take_overloads(), 0);
        writer_barrier(&db, now).await;
        assert_eq!(db.pending_msgs(), 0);
        assert_eq!(db.pending_events(), 0);
    });
    db.shutdown();
}
