//! Tests of the group state machine.

use super::*;

fn event(kind: u64, pubkey: &str, h: Option<&str>, tags: Vec<Vec<String>>) -> Event {
    let mut tags = tags;
    if let Some(h) = h {
        tags.insert(0, vec![H.to_string(), h.to_string()]);
    }
    Event {
        id: String::new(),
        pubkey: pubkey.to_string(),
        created_at: 1_600_000_000,
        kind,
        tags,
        content: String::new(),
        sig: String::new(),
    }
}

const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const USER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OTHER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
/// A second admin (distinct from ADMIN) for the last-admin guard tests.
const ADMIN2: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn seeded() -> GroupStore {
    let mut store = GroupStore::default();
    let create = event(CREATE_GROUP, ADMIN, Some("g1"), vec![]);
    store.apply(&create, "", 1, false, false);
    let put_user = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), OTHER.into()]]);
    store.apply(&put_user, "", 1, false, false);
    store
}

#[test]
fn group_cap_rejects_creates_over_the_limit() {
    let mut store = GroupStore::with_cap(2);
    let g1 = event(CREATE_GROUP, ADMIN, Some("g1"), vec![]);
    let g2 = event(CREATE_GROUP, ADMIN, Some("g2"), vec![]);
    let g3 = event(CREATE_GROUP, ADMIN, Some("g3"), vec![]);
    assert!(store.validate_write(&g1).is_ok());
    store.apply(&g1, "", 1, false, false);
    assert!(store.validate_write(&g2).is_ok());
    store.apply(&g2, "", 1, false, false);
    assert_eq!(
        store.validate_write(&g3).unwrap_err(),
        "restricted: group limit reached",
        "a create beyond the cap must be rejected"
    );
    // The apply path (the startup rebuild) must enforce the bound too:
    // a legacy store larger than the cap cannot blow the memory.
    store.apply(&g3, "", 1, false, false);
    assert_eq!(store.groups.len(), 2, "the cap bounds the store size");
    // A create of an EXISTING group (a metadata refresh) is unaffected.
    assert!(store.validate_write(&g1).is_ok());
}

#[test]
fn group_cap_counts_deleted_groups() {
    let mut store = GroupStore::with_cap(2);
    let g1 = event(CREATE_GROUP, ADMIN, Some("g1"), vec![]);
    let g2 = event(CREATE_GROUP, ADMIN, Some("g2"), vec![]);
    let g3 = event(CREATE_GROUP, ADMIN, Some("g3"), vec![]);
    let del1 = event(DELETE_GROUP, ADMIN, Some("g1"), vec![]);
    store.apply(&g1, "", 1, false, false);
    store.apply(&g2, "", 1, false, false);
    store.apply(&del1, "", 2, false, false);
    // g1 is gone but its marker still counts: a new create is rejected.
    assert_eq!(
        store.validate_write(&g3).unwrap_err(),
        "restricted: group limit reached",
        "deleted groups must count toward the budget"
    );
    // Re-creating the DELETED g1 is refused on other grounds.
    assert_eq!(
        store.validate_write(&g1).unwrap_err(),
        "blocked: the group has been deleted"
    );
}

#[test]
fn unlimited_group_cap_allows_any() {
    let mut store = GroupStore::default();
    for i in 0..100 {
        let g = event(CREATE_GROUP, ADMIN, Some(&format!("g{i}")), vec![]);
        assert!(store.validate_write(&g).is_ok());
        store.apply(&g, "", 1, false, false);
    }
    assert_eq!(store.groups.len(), 100);
}

#[test]
fn create_and_admin() {
    let store = seeded();
    let g = store.group("g1").unwrap();
    assert!(g.is_admin(ADMIN));
    // put-user adds a member; without roles they are not an admin.
    assert!(g.is_member(OTHER));
    assert!(!g.is_admin(OTHER));
}

#[test]
fn moderation_requires_admin() {
    let store = seeded();
    let bad = event(9001, OTHER, Some("g1"), vec![vec![P.into(), ADMIN.into()]]);
    assert!(store.validate_write(&bad).is_err());
    let good = event(9001, ADMIN, Some("g1"), vec![vec![P.into(), OTHER.into()]]);
    assert!(store.validate_write(&good).is_ok());
}

#[test]
fn put_user_roles_from_p_tag_extras() {
    // NIP-29: a kind:9000 carries the roles as the elements after the
    // pubkey inside the `p` tag.
    let mut store = seeded();
    let put = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![vec![
            P.into(),
            USER.into(),
            "ceo".into(),
            "secretary".into(),
        ]],
    );
    store.apply(&put, "", 1, false, false);
    let group = store.group("g1").unwrap();
    assert_eq!(
        group.members.get(USER).unwrap(),
        &["ceo".into(), "secretary".into()].into_iter().collect()
    );
    assert!(group.is_admin(USER));
}

#[test]
fn restricted_groups() {
    let mut store = seeded();
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["restricted".into()]]);
    store.apply(&edit, "", 1, false, false);
    let msg_by_user = event(1, USER, Some("g1"), vec![]);
    assert!(store.validate_write(&msg_by_user).is_err());
    // Join requests to an open group (not `closed`) are honored: the
    // user is admitted without privileges.
    let join = event(JOIN, USER, Some("g1"), vec![]);
    assert!(store.validate_write(&join).is_ok());
    store.apply(&join, "", 1, false, false);
    assert!(store.group("g1").unwrap().is_member(USER));
    assert!(!store.group("g1").unwrap().is_admin(USER));
    // A member of a restricted group may post.
    assert!(store.validate_write(&msg_by_user).is_ok());
    // A duplicate join request is rejected with the `duplicate:` prefix.
    let join = event(JOIN, USER, Some("g1"), vec![]);
    assert_eq!(
        store.validate_write(&join).unwrap_err(),
        "duplicate: you are already a member of this group"
    );
    // Removing the user restores the restriction.
    let remove = event(9001, ADMIN, Some("g1"), vec![vec![P.into(), USER.into()]]);
    store.apply(&remove, "", 1, false, false);
    assert!(store.validate_write(&msg_by_user).is_err());
}

#[test]
fn invite_code_admits() {
    let mut store = seeded();
    let invite = event(
        9009,
        ADMIN,
        Some("g1"),
        vec![vec![CODE.into(), "abc".into()]],
    );
    store.apply(&invite, "", 1, false, false);
    let join = event(
        JOIN,
        USER,
        Some("g1"),
        vec![vec![CODE.into(), "abc".into()]],
    );
    assert!(store.validate_write(&join).is_ok());
    store.apply(&join, "", 1, false, false);
    assert!(store.group("g1").unwrap().is_member(USER));
}

#[test]
fn invalid_invite_code_is_final() {
    let mut store = seeded();
    let invite = event(
        9009,
        ADMIN,
        Some("g1"),
        vec![vec![CODE.into(), "abc".into()]],
    );
    store.apply(&invite, "", 1, false, false);
    // On an OPEN group the `code` tag is optional preauthorization: a
    // wrong code does not block the (otherwise honored) join.
    let join = event(
        JOIN,
        USER,
        Some("g1"),
        vec![vec![CODE.into(), "wrong".into()]],
    );
    assert!(store.validate_write(&join).is_ok());
    store.apply(&join, "", 1, false, false);
    assert!(store.group("g1").unwrap().is_member(USER));
    // A closed group honors a valid invite code and rejects a wrong one.
    let stranger = "ee".repeat(32);
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["closed".into()]]);
    store.apply(&edit, "", 1, false, false);
    let join = event(
        JOIN,
        &stranger,
        Some("g1"),
        vec![vec![CODE.into(), "wrong".into()]],
    );
    assert_eq!(
        store.validate_write(&join).unwrap_err(),
        "restricted: invalid invite code (final decision)"
    );
    let join = event(
        JOIN,
        &stranger,
        Some("g1"),
        vec![vec![CODE.into(), "abc".into()]],
    );
    assert!(store.validate_write(&join).is_ok());
}

#[test]
fn put_user_roles_replace_previous_roles() {
    // NIP-29: "the user roles must just be updated": a new kind:9000
    // replaces the previous role set instead of extending it.
    let mut store = seeded();
    let put = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![vec![P.into(), USER.into(), "ceo".into()]],
    );
    store.apply(&put, "", 1, false, false);
    assert!(store.group("g1").unwrap().is_admin(USER));
    let demote = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), USER.into()]]);
    store.apply(&demote, "", 1, false, false);
    let group = store.group("g1").unwrap();
    assert!(group.is_member(USER));
    assert!(
        !group.is_admin(USER),
        "roles without privilege elements are not admins"
    );
}

#[test]
fn last_admin_cannot_be_demoted() {
    // The group must retain at least one admin: a 9000 that would demote
    // every admin (e.g. the creator) to a plain member is rejected, so the
    // creator cannot be silently turned into a mere member.
    let store = seeded();
    // ADMIN is the only admin (creator); demoting them leaves no admin.
    let demote = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), ADMIN.into()]]);
    assert!(
        store.validate_write(&demote).is_err(),
        "last admin cannot be demoted"
    );

    // Demoting the creator while granting roles to another pubkey is fine.
    let transfer = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![
            vec![P.into(), ADMIN.into()],
            vec![P.into(), USER.into(), "admin".into()],
        ],
    );
    assert!(
        store.validate_write(&transfer).is_ok(),
        "a new admin may be granted"
    );
    // The final state decides: a grant and a demotion of the *same*
    // pubkey in one event (tags applied in order) must not bypass the
    // guard — `["p", A, "mod"]` followed by `["p", A]` ends with A
    // demoted, leaving no admin.
    let same_key_demote = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![
            vec![P.into(), ADMIN.into(), "admin".into()],
            vec![P.into(), ADMIN.into()],
        ],
    );
    assert!(
        store.validate_write(&same_key_demote).is_err(),
        "a grant overwritten by a demotion of the same key is still a demotion"
    );
    // The reverse order keeps the grant and is accepted.
    let same_key_grant = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![
            vec![P.into(), ADMIN.into()],
            vec![P.into(), ADMIN.into(), "admin".into()],
        ],
    );
    assert!(
        store.validate_write(&same_key_grant).is_ok(),
        "a demotion overwritten by a grant of the same key keeps an admin"
    );

    // Demoting a non-last admin is still allowed.
    let mut store2 = seeded();
    store2.apply(
        &event(
            9000,
            ADMIN,
            Some("g1"),
            vec![vec![P.into(), USER.into(), "mod".into()]],
        ),
        "",
        1,
        false,
        false,
    );
    let demote_user = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), USER.into()]]);
    assert!(
        store2.validate_write(&demote_user).is_ok(),
        "a non-last admin may be demoted"
    );
}

#[test]
fn closed_group_rejects_joins() {
    // NIP-29: `closed` means join requests are ignored — rejected and
    // not stored; admission happens via an invite code or an admin's
    // kind:9000.
    let mut store = seeded();
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["closed".into()]]);
    store.apply(&edit, "", 1, false, false);
    let join = event(JOIN, USER, Some("g1"), vec![]);
    assert!(store.validate_write(&join).is_err());
}

#[test]
fn subgroups() {
    let mut store = seeded();
    // Create a second group and move g1 under it.
    let create2 = event(CREATE_GROUP, ADMIN, Some("g2"), vec![]);
    store.apply(&create2, "", 1, false, false);
    let adopt = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["parent".into(), "g2".into()]],
    );
    assert!(store.validate_write(&adopt).is_ok());
    store.apply(&adopt, "", 1, false, false);
    assert_eq!(store.group("g1").unwrap().parent.as_deref(), Some("g2"));
    assert_eq!(store.group("g2").unwrap().children, vec!["g1"]);

    // Self-parenting and cycles are rejected.
    let self_cycle = event(
        9002,
        ADMIN,
        Some("g2"),
        vec![vec!["parent".into(), "g2".into()]],
    );
    assert!(store.validate_write(&self_cycle).is_err());
    let cycle = event(
        9002,
        ADMIN,
        Some("g2"),
        vec![vec!["parent".into(), "g1".into()]],
    );
    assert!(store.validate_write(&cycle).is_err());
    // Unknown parent is rejected.
    let ghost = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["parent".into(), "ghost".into()]],
    );
    assert!(store.validate_write(&ghost).is_err());

    // Declaring a child that would close a cycle is rejected: g1 is a
    // child of g2, so a child-tag declaration of g2 on g1 must fail (the
    // downward walk reaches g1 from g2).
    let downward_cycle = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["child".into(), "g2".into()]],
    );
    assert!(
        store.validate_write(&downward_cycle).is_err(),
        "a child declaration that would create a cycle must be rejected"
    );

    // A group cannot declare itself as its own child.
    let self_child = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["child".into(), "g1".into()]],
    );
    assert!(store.validate_write(&self_child).is_err());

    // A metadata edit must carry every existing child (NIP-29).
    let partial_edit = event(9002, ADMIN, Some("g2"), vec![]);
    assert!(
        store.validate_write(&partial_edit).is_err(),
        "a partial edit omitting the child list must be rejected"
    );
    let full_edit = event(
        9002,
        ADMIN,
        Some("g2"),
        vec![vec!["child".into(), "g1".into()]],
    );
    assert!(store.validate_write(&full_edit).is_ok());

    // Deleting a child removes it from the parent's child list.
    let delete_child = event(DELETE_GROUP, ADMIN, Some("g1"), vec![]);
    store.apply(&delete_child, "", 1, false, false);
    assert!(store.group("g1").is_none());
    assert!(store.group("g2").unwrap().children.is_empty());
}

#[test]
fn deleted_group_content_is_hidden() {
    let mut store = seeded();
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["private".into()]]);
    store.apply(&edit, "", 1, false, false);
    let msg = event(1, ADMIN, Some("g1"), vec![]);
    let meta = store.apply(&msg, "", 1, true, false);
    // Before deletion: hidden from outsiders, visible to members.
    assert!(!store.visible_to(&msg, None));
    assert!(store.visible_to(&msg, Some(ADMIN)));
    // After deletion: the history must not become public.
    let delete = event(DELETE_GROUP, ADMIN, Some("g1"), vec![]);
    store.apply(&delete, "", 1, false, false);
    assert!(!store.visible_to(&msg, None));
    assert!(!store.visible_to(&msg, Some(ADMIN)));
    for m in &meta {
        assert!(!store.visible_to(m, Some(ADMIN)));
    }
}

#[test]
fn private_groups_hide_from_non_members() {
    let mut store = seeded();
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["private".into()]]);
    store.apply(&edit, "", 1, false, false);
    let msg = event(1, ADMIN, Some("g1"), vec![]);
    let outsider = "d".repeat(64);
    assert!(!store.visible_to(&msg, Some(&outsider)));
    assert!(store.visible_to(&msg, Some(ADMIN)));
    // OTHER is a member and may read private groups.
    assert!(store.visible_to(&msg, Some(OTHER)));
    let meta = store.apply(&msg, "", 1, true, false);
    for m in &meta {
        assert!(!store.visible_to(m, Some(&outsider)));
    }
}

#[test]
fn rebuild_order_applies_create_before_member_ops() {
    // Within the same second the create (9007) must be applied before member
    // operations (9000) and joins (9021), or the member/join ops are dropped
    // for a not-yet-existing group.
    assert!(group_rank(9007) < group_rank(9000));
    assert!(group_rank(9000) < group_rank(9021));
    assert!(group_rank(9008) < group_rank(9022));

    let mut events = vec![
        event(9000, ADMIN, Some("g1"), vec![vec![P.into(), OTHER.into()]]),
        event(CREATE_GROUP, ADMIN, Some("g1"), vec![]),
        event(JOIN, OTHER, Some("g1"), vec![]),
    ];
    for e in &mut events {
        e.created_at = 1_700_000_000;
    }
    events.sort_by(|a, b| {
        (a.created_at, group_rank(a.kind), a.kind, &a.id).cmp(&(
            b.created_at,
            group_rank(b.kind),
            b.kind,
            &b.id,
        ))
    });
    assert_eq!(events[0].kind, CREATE_GROUP, "create applies first");
    assert_eq!(events[1].kind, 9000, "member op applies second");
    assert_eq!(events[2].kind, JOIN, "join applies last");

    let mut store = GroupStore::default();
    for e in &events {
        store.apply(e, "", 1, false, false);
    }
    let g = store.group("g1").unwrap();
    assert!(g.is_member(OTHER), "the member op and join must both apply");
}

#[test]
fn rebuild_keeps_join_membership() {
    // A honored 9021 JOIN must survive a restart rebuild even though the
    // relay (keyless here) never emits a relay-signed 9000 put-user.
    use crate::db::DbClient;
    use crate::nips::nip01;
    use std::sync::Arc;
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join("nostrfy-nip29-rebuild")
        .join(format!("{:x}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let cfg = crate::config::DatabaseConfig {
        path,
        ..Default::default()
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = 1_700_000_000;
        let mut create = event(CREATE_GROUP, ADMIN, Some("g1"), vec![]);
        create.created_at = now;
        create.id = nip01::compute_id(&create);
        assert_eq!(
            db.put(create.clone(), now).await,
            crate::db::PutOutcome::Stored
        );
        // A plain member JOINs (no relay-signed 9000 is stored on keyless relays).
        let mut join = event(JOIN, OTHER, Some("g1"), vec![]);
        join.created_at = now;
        join.id = nip01::compute_id(&join);
        assert_eq!(
            db.put(join.clone(), now).await,
            crate::db::PutOutcome::Stored
        );

        let mut store = GroupStore::default();
        store.rebuild(&db).await;
        let g = store.group("g1").expect("group rebuilt");
        assert!(g.is_admin(ADMIN), "creator is admin after rebuild");
        assert!(g.is_member(OTHER), "JOIN membership survives rebuild");
    });
}

#[test]
fn rebuild_ghosts_group_whose_only_surviving_events_are_relay_metadata() {
    // A vanished creator leaves the relay-signed 39000-39005 behind (they
    // are not authored by the creator). The rebuild's ghost detection must
    // see them, or the private group's metadata becomes world-readable
    // after a restart.
    use crate::db::DbClient;
    use crate::nips::nip01;
    use std::sync::Arc;
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join("nostrfy-nip29-ghost-meta")
        .join(format!("{:x}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let cfg = crate::config::DatabaseConfig {
        path,
        ..Default::default()
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = 1_700_000_000;
        // Only relay-signed metadata survives: no moderation event. The
        // relay's metadata events are addressable (`d` tag = group id).
        for kind in GROUP_META..=GROUP_PINS {
            let mut meta = Event {
                id: String::new(),
                pubkey: "11".repeat(32),
                created_at: now,
                kind,
                tags: vec![vec![D.to_string(), "g1".to_string()]],
                content: String::new(),
                sig: String::new(),
            };
            meta.id = nip01::compute_id(&meta);
            assert_eq!(
                db.put(meta.clone(), now).await,
                crate::db::PutOutcome::Stored
            );
        }

        let mut store = GroupStore::default();
        store.rebuild(&db).await;
        assert!(
            store.ghost.contains("g1"),
            "a group with only relay metadata must be ghosted"
        );
        assert!(
            !store.visible_gid("g1", true, None),
            "the ghosted group's metadata is withheld"
        );
    });
}

#[test]
fn join_to_unknown_group_is_rejected() {
    // A JOIN for a group that does not exist (yet) would be stored but
    // never honored — the state machine has no group to admit the user
    // into — so it is rejected like every other moderation event for an
    // unknown group. Only a 9007 create-group may target an unknown group.
    let store = GroupStore::default();
    let join = event(JOIN, USER, Some("ghost"), vec![]);
    assert_eq!(
        store.validate_write(&join).unwrap_err(),
        "restricted: unknown group"
    );
    let create = event(CREATE_GROUP, USER, Some("ghost"), vec![]);
    assert!(store.validate_write(&create).is_ok());
}

#[test]
fn livekit_tag_and_single_parent() {
    // NIP-29: a `livekit` tag in the metadata edit is mirrored in the
    // 39000 event, and a 9002 carrying more than one `parent` tag is
    // rejected (the spec allows at most one).
    let mut store = seeded();
    let edit = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["livekit".into()], vec!["supported_kinds".into()]],
    );
    assert!(store.validate_write(&edit).is_ok());
    let meta = store.apply(&edit, "", 1, true, false);
    let meta_ev = meta
        .iter()
        .find(|e| e.kind == GROUP_META)
        .expect("39000 emitted");
    assert!(
        meta_ev
            .tags
            .iter()
            .any(|t| t.first().map(String::as_str) == Some("livekit")),
        "the 39000 must carry the livekit tag"
    );

    let double_parent = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![
            vec!["parent".into(), "g2".into()],
            vec!["parent".into(), "g3".into()],
        ],
    );
    assert_eq!(
        store.validate_write(&double_parent).unwrap_err(),
        "restricted: at most one parent tag is allowed"
    );
}

#[test]
fn last_admin_cannot_be_demoted_or_removed() {
    // The guard covers every path that removes an admin: a 9000 without
    // roles, a 9000 with an all-empty role list, a 9001 remove-user, and
    // a LEAVE by the last admin.
    let mut store = seeded();
    // Give the group a second admin.
    let grant = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![vec![P.into(), ADMIN2.into(), "mod".into()]],
    );
    assert!(store.validate_write(&grant).is_ok());
    store.apply(&grant, "", 2, false, false);

    // ADMIN demotes ADMIN2 (not the last admin): allowed.
    let demote = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), ADMIN2.into()]]);
    assert!(store.validate_write(&demote).is_ok());
    store.apply(&demote, "", 3, false, false);

    // Demoting the last admin with a bare p tag: refused.
    let demote_last = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), ADMIN.into()]]);
    assert!(store.validate_write(&demote_last).is_err());
    // An all-empty role list is a demotion too: refused.
    let empty_roles = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![vec![P.into(), ADMIN.into(), "".into()]],
    );
    assert!(
        store.validate_write(&empty_roles).is_err(),
        "an all-empty role list must not bypass the last-admin guard"
    );
    // Removing the last admin with 9001: refused.
    let remove_last = event(9001, ADMIN, Some("g1"), vec![vec![P.into(), ADMIN.into()]]);
    assert!(store.validate_write(&remove_last).is_err());
    // The last admin leaving: refused.
    let leave = event(9022, ADMIN, Some("g1"), vec![]);
    assert!(store.validate_write(&leave).is_err());
    // Removing a non-last admin is fine.
    let grant2 = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![vec![P.into(), ADMIN2.into(), "mod".into()]],
    );
    store.apply(&grant2, "", 4, false, false);
    let remove2 = event(
        9001,
        ADMIN2,
        Some("g1"),
        vec![vec![P.into(), ADMIN2.into()]],
    );
    assert!(store.validate_write(&remove2).is_ok());
}
