//! Tests of the group state machine.

use super::*;

pub(crate) fn event(kind: u64, pubkey: &str, h: Option<&str>, tags: Vec<Vec<String>>) -> Event {
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

pub(crate) const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(crate) const USER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OTHER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
/// A second admin (distinct from ADMIN) for the last-admin guard tests.
const ADMIN2: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[test]
fn apply_covers_parent_child_roles_pins_and_delete() {
    let mut store = GroupStore::default();
    let now = 1_600_000_000;
    // Create g1 (admin = ADMIN), a child g2, and an unrelated g3.
    store.apply(
        &event(CREATE_GROUP, ADMIN, Some("g1"), vec![]),
        "relay",
        now,
        true,
        false,
    );
    store.apply(
        &event(CREATE_GROUP, ADMIN, Some("g2"), vec![]),
        "relay",
        now,
        true,
        false,
    );
    store.apply(
        &event(CREATE_GROUP, ADMIN, Some("g3"), vec![]),
        "relay",
        now,
        true,
        false,
    );
    // g2 declares g1 as its parent; the back-pointer is assigned.
    let parent2 = event(
        9002,
        ADMIN,
        Some("g2"),
        vec![vec!["parent".into(), "g1".into()]],
    );
    let out = store.apply(&parent2, "relay", now, true, false);
    assert_eq!(store.group("g2").unwrap().parent.as_deref(), Some("g1"));
    assert!(
        store
            .group("g1")
            .unwrap()
            .children
            .contains(&"g2".to_string())
    );
    assert!(
        out.iter()
            .any(|e| e.kind == 39000 && e.tags.iter().any(|t| t[1] == "g2")),
        "the child's metadata is republished"
    );
    // g1 adopts g3 as a child.
    let adopt = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["child".into(), "g3".into()]],
    );
    store.apply(&adopt, "relay", now, true, false);
    assert_eq!(store.group("g3").unwrap().parent.as_deref(), Some("g1"));
    // Adopting again is a no-op; a child already owned elsewhere is not
    // re-parented.
    store.apply(&adopt, "relay", now, true, false);
    assert_eq!(store.group("g3").unwrap().parent.as_deref(), Some("g1"));
    // g1 drops g3 from its children: the back-pointer is cleared.
    let drop_child = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["child".into(), "g4".into()]],
    );
    store.apply(&drop_child, "relay", now, true, false);
    assert_eq!(store.group("g3").unwrap().parent, None);
    // The old parent's metadata is republished when the parent changes.
    let reparent = event(
        9002,
        ADMIN,
        Some("g2"),
        vec![vec!["parent".into(), "g3".into()]],
    );
    store.apply(&reparent, "relay", now, true, false);
    assert_eq!(store.group("g2").unwrap().parent.as_deref(), Some("g3"));
    assert!(
        !store
            .group("g1")
            .unwrap()
            .children
            .contains(&"g2".to_string())
    );
    // Role updates (9000) replace the previous roles.
    store.apply(
        &event(
            9000,
            ADMIN,
            Some("g1"),
            vec![vec![P.into(), USER.into(), "mod".into()]],
        ),
        "relay",
        now,
        true,
        false,
    );
    assert!(
        store
            .group("g1")
            .unwrap()
            .members
            .get(USER)
            .unwrap()
            .contains("mod")
    );
    // 9001 removes a member.
    store.apply(
        &event(9001, ADMIN, Some("g1"), vec![vec![P.into(), USER.into()]]),
        "relay",
        now,
        true,
        false,
    );
    assert!(!store.group("g1").unwrap().members.contains_key(USER));
    // 9009 adds invite codes; 9010 sets pins.
    store.apply(
        &event(
            9009,
            ADMIN,
            Some("g1"),
            vec![vec![CODE.into(), "code1".into()]],
        ),
        "relay",
        now,
        true,
        false,
    );
    assert!(store.group("g1").unwrap().has_invite("code1"));
    let pins = event(
        9010,
        ADMIN,
        Some("g1"),
        vec![
            vec![E.into(), "ab".repeat(32)],
            vec![A.into(), "30078:pk:d".into()],
        ],
    );
    store.apply(&pins, "relay", now, true, false);
    assert_eq!(store.group("g1").unwrap().pins.len(), 2);
    // 9005 (delete event) applies without touching the group state.
    store.apply(
        &event(
            9005,
            ADMIN,
            Some("g1"),
            vec![vec![E.into(), "ab".repeat(32)]],
        ),
        "relay",
        now,
        true,
        false,
    );
    assert!(store.group("g1").is_some());
    // JOIN via a valid invite on a closed group admits the user.
    store.apply(
        &event(9002, ADMIN, Some("g1"), vec![vec!["closed".into()]]),
        "relay",
        now,
        true,
        false,
    );
    let join = event(
        JOIN,
        OTHER,
        Some("g1"),
        vec![vec![CODE.into(), "code1".into()]],
    );
    store.apply(&join, "relay", now, true, false);
    assert!(store.group("g1").unwrap().is_member(OTHER));
    // LEAVE removes the member and republishes.
    let leave = event(LEAVE, OTHER, Some("g1"), vec![]);
    store.apply(&leave, "relay", now, true, false);
    assert!(!store.group("g1").unwrap().is_member(OTHER));
    // DELETE_GROUP removes the group and frees its children.
    store.apply(
        &event(DELETE_GROUP, ADMIN, Some("g2"), vec![]),
        "relay",
        now,
        true,
        false,
    );
    assert!(store.group("g2").is_none());
    assert_eq!(store.group("g3").unwrap().parent, None);
    // privacy_gated: private groups are gated; unknown groups are not.
    store.apply(
        &event(
            9000,
            ADMIN,
            Some("g1"),
            vec![vec![P.into(), USER.into(), "member".into()]],
        ),
        "relay",
        now,
        true,
        false,
    );
    store.apply(
        &event(9002, ADMIN, Some("g1"), vec![vec!["private".into()]]),
        "relay",
        now,
        true,
        false,
    );
    let private_note = event(1, USER, Some("g1"), vec![]);
    assert!(store.privacy_gated(&private_note));
    let unknown = event(1, USER, Some("ghost"), vec![]);
    assert!(!store.privacy_gated(&unknown));
    // visible_to: non-group events are visible; gated content is not.
    let plain = event(1, USER, None, vec![]);
    assert!(store.visible_to(&plain, None));
    assert!(!store.visible_to(&private_note, None));
    assert!(store.visible_to(&private_note, Some(USER)));
}

#[test]
fn parent_side_adoption_moves_the_child_from_its_old_parent() {
    // NIP-29: the parent's `child` list and the child's `parent` tag are two
    // sides of one link. An admin of both may adopt a child through the
    // parent's 9002; the old parent's list must be updated too, or the two
    // directions disagree (a one-way link).
    let mut store = GroupStore::default();
    let now = 1_600_000_000;
    for gid in ["g1", "g2", "g3"] {
        store.apply(
            &event(CREATE_GROUP, ADMIN, Some(gid), vec![]),
            "relay",
            now,
            false,
            false,
        );
    }
    // g3 declares g2 as its parent (the child side).
    let under_g2 = event(
        9002,
        ADMIN,
        Some("g3"),
        vec![vec!["parent".into(), "g2".into()]],
    );
    store.apply(&under_g2, "relay", now, false, false);
    assert_eq!(store.group("g3").unwrap().parent.as_deref(), Some("g2"));
    assert!(
        store
            .group("g2")
            .unwrap()
            .children
            .contains(&"g3".to_string())
    );
    // g1's admin adopts g3 through the parent side.
    let adopt = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["child".into(), "g3".into()]],
    );
    store.apply(&adopt, "relay", now, false, false);
    assert_eq!(store.group("g3").unwrap().parent.as_deref(), Some("g1"));
    assert!(
        store
            .group("g1")
            .unwrap()
            .children
            .contains(&"g3".to_string())
    );
    assert!(
        !store
            .group("g2")
            .unwrap()
            .children
            .contains(&"g3".to_string()),
        "the old parent's child list must be cleared"
    );
}

#[test]
fn vanish_rebuild_recreates_membership_of_private_groups() {
    // ...
}

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
    // Re-creating the DELETED g1 is refused on capacity grounds here (the
    // budget is full); with spare capacity a fresh create resurrects it
    // (see `deleted_group_id_can_be_recreated`).
    assert_eq!(
        store.validate_write(&g1).unwrap_err(),
        "restricted: group limit reached"
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
fn multiple_h_tags_are_rejected() {
    // NIP-29: the `h` tag carries the group id. Accepting two `h` tags would
    // let an event be validated against the first (e.g. an open group) while
    // the stored tag index and subscriptions match the second (e.g. a
    // restricted group), surfacing it in that group's feed.
    let mut store = seeded();
    // A second, unrestricted group as the "validated" face.
    store.apply(
        &event(CREATE_GROUP, ADMIN, Some("g2"), vec![]),
        "",
        1,
        false,
        false,
    );
    // Make g1 restricted: a lone write by USER to g1 must be rejected.
    store.apply(
        &event(9002, ADMIN, Some("g1"), vec![vec!["restricted".into()]]),
        "",
        1,
        false,
        false,
    );
    let mut multi = event(1, USER, Some("g2"), vec![]);
    multi.tags.push(vec![H.to_string(), "g1".to_string()]);
    let err = store.validate_write(&multi).unwrap_err();
    assert!(
        err.contains("only one h tag"),
        "a second h tag must be rejected: {err}"
    );
    // The same event with only the restricted group's h tag is rejected by
    // the restriction rule (not the tag-count rule).
    let single = event(1, USER, Some("g1"), vec![]);
    assert!(
        store
            .validate_write(&single)
            .unwrap_err()
            .contains("members"),
        "the restricted group still gates non-members"
    );
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
    // A LEAVE is exempt from the retain-an-admin guard (NIP-29: any user
    // may leave); see `any_member_can_leave_even_the_last_admin`.
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

#[test]
fn any_member_can_leave_even_the_last_admin() {
    // NIP-29: "Any user can send one of these events to the relay in order
    // to be automatically removed from the group." There is no admin
    // exception, so the last admin's LEAVE is honored; the group then has
    // no admins (only the relay's own key can manage it).
    let mut store = seeded();
    let member_leave = event(LEAVE, OTHER, Some("g1"), vec![]);
    assert!(store.validate_write(&member_leave).is_ok());
    let admin_leave = event(LEAVE, ADMIN, Some("g1"), vec![]);
    assert!(
        store.validate_write(&admin_leave).is_ok(),
        "the last admin's LEAVE must be honored"
    );
    store.apply(&admin_leave, "", 2, false, false);
    assert!(!store.group("g1").unwrap().is_member(ADMIN));
    assert!(!store.group("g1").unwrap().is_admin(ADMIN));
    // With no admins left, no member can issue moderation events.
    let demote = event(9000, USER, Some("g1"), vec![vec![P.into(), OTHER.into()]]);
    assert!(store.validate_write(&demote).is_err());
}

#[test]
fn deleting_a_group_removes_it_and_purges_its_events() {
    // Group deletion (9008) remains the way to remove a group entirely; the
    // relay purges its stored events.
    let mut store = seeded();
    let delete = event(DELETE_GROUP, ADMIN, Some("g1"), vec![]);
    assert!(
        store.validate_write(&delete).is_ok(),
        "an admin can delete the group"
    );
    store.apply(&delete, "", 2, false, false);
    assert!(store.group("g1").is_none(), "the group is removed");
    // The id is tombstoned too: a plain write is blocked until a 9007.
    let write = event(1, USER, Some("g1"), vec![]);
    assert!(store.validate_write(&write).is_err());
}

#[test]
fn relay_key_can_restore_an_adminless_group() {
    // NIP-29 moderation events may come from the relay master key. After the
    // last admin leaves, the operator can restore an admin by signing a 9000
    // with `relay.private_key` (the NIP-11 `self` key).
    let relay_pk = "ff".repeat(64);
    let other_pk = "ee".repeat(64);
    let mut store = seeded();
    let leave = event(LEAVE, ADMIN, Some("g1"), vec![]);
    assert!(store.validate_write(&leave).is_ok());
    store.apply(&leave, "", 2, false, false);
    assert!(!store.group("g1").unwrap().is_admin(ADMIN));
    // A regular key cannot manage the group, with or without the relay-key
    // path...
    let grant_other = event(
        9000,
        &other_pk,
        Some("g1"),
        vec![vec![P.into(), OTHER.into(), "mod".into()]],
    );
    assert!(store.validate_write(&grant_other).is_err());
    assert!(
        store
            .validate_write_for_relay(&grant_other, Some(&relay_pk))
            .is_err(),
        "a non-relay key must not get the master-key exemption"
    );
    // ...but the relay key can.
    let grant_relay = event(
        9000,
        &relay_pk,
        Some("g1"),
        vec![vec![P.into(), OTHER.into(), "mod".into()]],
    );
    assert!(
        store
            .validate_write_for_relay(&grant_relay, Some(&relay_pk))
            .is_ok(),
        "the relay master key may restore an admin"
    );
    assert!(
        store.validate_write(&grant_relay).is_err(),
        "without the relay-key path the relay key is just another pubkey"
    );
}

#[test]
fn parent_side_adopt_requires_child_admin() {
    // A parent admin must not hijack an orphan group by listing it: the
    // author must also administer the child (the child's own 9002 remains
    // the normal parenting path).
    let mut store = seeded();
    let create3 = event(CREATE_GROUP, OTHER, Some("g3"), vec![]);
    store.apply(&create3, "", 1, false, false);
    // ADMIN administers g1 but not g3: parent-side adoption is rejected.
    let adopt = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["child".into(), "g3".into()]],
    );
    assert!(
        store.validate_write(&adopt).is_err(),
        "adopting a group you do not administer must be rejected"
    );
    // Once ADMIN is also an admin of g3, the same edit validates.
    let grant = event(
        9000,
        OTHER,
        Some("g3"),
        vec![vec![P.into(), ADMIN.into(), "mod".into()]],
    );
    assert!(store.validate_write(&grant).is_ok());
    store.apply(&grant, "", 1, false, false);
    assert!(store.validate_write(&adopt).is_ok());
}

#[test]
fn deleted_group_id_can_be_recreated() {
    // A fresh 9007 resurrects a deleted id (the tombstone blocks every
    // other write but not re-creation).
    let mut store = seeded();
    let delete = event(DELETE_GROUP, ADMIN, Some("g1"), vec![]);
    assert!(store.validate_write(&delete).is_ok());
    store.apply(&delete, "", 1, false, false);
    assert!(store.group("g1").is_none());
    let rejoin = event(9021, USER, Some("g1"), vec![]);
    assert!(
        store.validate_write(&rejoin).is_err(),
        "writes to a deleted group stay blocked"
    );
    let recreate = event(CREATE_GROUP, ADMIN, Some("g1"), vec![]);
    assert!(store.validate_write(&recreate).is_ok());
    store.apply(&recreate, "", 1, false, false);
    assert!(
        store.group("g1").is_some(),
        "a fresh create must resurrect the id"
    );
}

#[test]
fn pin_list_is_bounded() {
    // NIP-29 lets the relay limit pins: validation rejects oversized
    // 9010 lists, and apply caps history replayed without validation.
    let mut store = seeded();
    let many: Vec<Vec<String>> = (0..150)
        .map(|i| vec![E.into(), format!("{:064x}", i)])
        .collect();
    let pins = event(9010, ADMIN, Some("g1"), many.clone());
    assert!(
        store.validate_write(&pins).is_err(),
        "an oversized pin list must be rejected"
    );
    store.apply(&pins, "", 1, false, false);
    assert_eq!(
        store.group("g1").unwrap().pins.len(),
        super::MAX_PINS,
        "replayed history must still be capped"
    );
}

#[test]
fn invite_codes_are_bounded() {
    // Invite codes accumulate without consumption: validation rejects
    // overflow and apply stops at the cap even for unvalidated history.
    let mut store = seeded();
    let many: Vec<Vec<String>> = (0..150)
        .map(|i| vec!["code".into(), format!("code-{i}")])
        .collect();
    let invites = event(9009, ADMIN, Some("g1"), many);
    assert!(
        store.validate_write(&invites).is_err(),
        "an oversized invite batch must be rejected"
    );
    store.apply(&invites, "", 1, false, false);
    assert_eq!(
        store.group("g1").unwrap().invites.len(),
        super::MAX_INVITES,
        "replayed history must still be capped"
    );
    // At the cap, one more fresh code is rejected.
    let one_more = event(
        9009,
        ADMIN,
        Some("g1"),
        vec![vec!["code".into(), "extra".into()]],
    );
    assert!(store.validate_write(&one_more).is_err());
}

#[test]
fn group_members_are_bounded() {
    // Without a bound an admin could spam `9000` with fresh pubkeys,
    // growing the member map (and mirrored 39001/39002) without limit.
    let mut store = seeded();
    // Fill to the cap through apply (bypasses validation, like history
    // replay).
    for i in 0..super::MAX_MEMBERS {
        let put = event(
            9000,
            ADMIN,
            Some("g1"),
            vec![vec![P.into(), format!("{:064x}", i), "m".into()]],
        );
        store.apply(&put, "", 1, false, false);
    }
    assert_eq!(store.group("g1").unwrap().members.len(), super::MAX_MEMBERS);
    // A fresh member via 9000 is rejected at the cap...
    let fresh = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![vec![P.into(), "ff".repeat(32), "m".into()]],
    );
    assert!(store.validate_write(&fresh).is_err());
    // ...as is a fresh JOIN, while role changes for existing members
    // still validate.
    let join = event(9021, USER, Some("g1"), vec![]);
    assert!(store.validate_write(&join).unwrap_err().contains("full"));
    let role_change = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![vec![P.into(), format!("{:064x}", 0), "admin".into()]],
    );
    assert!(store.validate_write(&role_change).is_ok());
    // Replay past the cap stays capped.
    let mut huge = Vec::new();
    for i in 0..500 {
        huge.push(vec![P.into(), format!("{:064x}", i + 0x9000), "m".into()]);
    }
    let big = event(9000, ADMIN, Some("g1"), huge);
    store.apply(&big, "", 1, false, false);
    assert_eq!(store.group("g1").unwrap().members.len(), super::MAX_MEMBERS);
}
