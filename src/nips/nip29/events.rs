//! Relay-generated NIP-29 events: metadata (39000), admins (39001),
//! members (39002), pins (39005) and the put-user/remove-user moderation
//! events emitted by the group state machine.

use crate::event::Event;

use super::{D, GROUP_ADMINS, GROUP_MEMBERS, GROUP_META, GROUP_PINS, Group, GroupSettings, H, P};
pub(crate) fn apply_settings(group: &mut Group, event: &Event) {
    let mut settings = GroupSettings::default();
    for tag in &event.tags {
        if tag.is_empty() {
            continue;
        }
        match tag[0].as_str() {
            "name" | "picture" | "banner" | "about" => {
                if let Some(value) = tag.get(1) {
                    match tag[0].as_str() {
                        "name" => settings.name = value.clone(),
                        "picture" => settings.picture = value.clone(),
                        "banner" => settings.banner = value.clone(),
                        _ => settings.about = value.clone(),
                    }
                }
            }
            "private" => settings.private = true,
            "restricted" => settings.restricted = true,
            "closed" => settings.closed = true,
            "hidden" => settings.hidden = true,
            "livekit" => settings.livekit = true,
            "supported_kinds" => {
                settings.supported_kinds =
                    Some(tag[1..].iter().filter_map(|k| k.parse().ok()).collect())
            }
            _ => {}
        }
    }
    group.settings = settings;
}

pub(crate) fn base_event(kind: u64, gid: &str, relay_pubkey: &str, now: u64) -> Event {
    Event {
        id: String::new(),
        pubkey: relay_pubkey.to_string(),
        created_at: now,
        kind,
        tags: vec![vec![D.to_string(), gid.to_string()]],
        content: String::new(),
        sig: String::new(),
    }
}

pub(crate) fn build_meta_event(
    gid: &str,
    group: Option<&Group>,
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let Some(group) = group else {
        return base_event(GROUP_META, gid, relay_pubkey, now);
    };
    let mut event = base_event(GROUP_META, gid, relay_pubkey, now);
    let s = &group.settings;
    for (name, value) in [
        ("name", &s.name),
        ("picture", &s.picture),
        ("banner", &s.banner),
        ("about", &s.about),
    ] {
        if !value.is_empty() {
            event.tags.push(vec![name.to_string(), value.clone()]);
        }
    }
    if s.private {
        event.tags.push(vec!["private".to_string()]);
    }
    if s.restricted {
        event.tags.push(vec!["restricted".into()]);
    }
    if s.closed {
        event.tags.push(vec!["closed".to_string()]);
    }
    if s.hidden {
        event.tags.push(vec!["hidden".into()]);
    }
    if s.livekit {
        event.tags.push(vec!["livekit".into()]);
    }
    if let Some(kinds) = &s.supported_kinds {
        let mut tag = vec!["supported_kinds".to_string()];
        tag.extend(kinds.iter().map(u64::to_string));
        event.tags.push(tag);
    }
    if let Some(parent) = &group.parent {
        event.tags.push(vec!["parent".to_string(), parent.clone()]);
    }
    for child in &group.children {
        event.tags.push(vec!["child".to_string(), child.clone()]);
    }
    event
}

pub(crate) fn build_admins_event(
    gid: &str,
    group: Option<&Group>,
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut event = base_event(GROUP_ADMINS, gid, relay_pubkey, now);
    if let Some(group) = group {
        let mut admins: Vec<(String, Vec<String>)> = group
            .members
            .iter()
            .filter(|(_, roles)| !roles.is_empty())
            .map(|(pk, roles)| {
                // Sorted so the relay-generated event is deterministic
                // across restarts (a HashSet iteration order would change
                // the event id).
                let mut roles: Vec<String> = roles.iter().cloned().collect();
                roles.sort();
                (pk.clone(), roles)
            })
            .collect();
        admins.sort();
        for (pk, roles) in admins {
            let mut tag = vec![P.to_string(), pk];
            tag.extend(roles);
            event.tags.push(tag);
        }
    }
    event
}

pub(crate) fn build_members_event(
    gid: &str,
    group: Option<&Group>,
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut event = base_event(GROUP_MEMBERS, gid, relay_pubkey, now);
    if let Some(group) = group {
        let mut members: Vec<String> = group.members.keys().cloned().collect();
        members.sort();
        for pk in members {
            event.tags.push(vec![P.to_string(), pk]);
        }
    }
    event
}

pub(crate) fn build_pins_event(
    gid: &str,
    group: Option<&Group>,
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut event = base_event(GROUP_PINS, gid, relay_pubkey, now);
    if let Some(group) = group {
        for (tag, value) in &group.pins {
            event.tags.push(vec![tag.clone(), value.clone()]);
        }
    }
    event
}

pub(crate) fn build_put_user(
    gid: &str,
    member: &str,
    roles: &[&str],
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut event = base_event(9000, gid, relay_pubkey, now);
    event.tags[0] = vec![H.to_string(), gid.to_string()];
    let mut tag = vec![P.to_string(), member.to_string()];
    tag.extend(roles.iter().map(|r| r.to_string()));
    event.tags.push(tag);
    event
}

pub(crate) fn build_remove_user(gid: &str, member: &str, relay_pubkey: &str, now: u64) -> Event {
    let mut event = base_event(9001, gid, relay_pubkey, now);
    event.tags[0] = vec![H.to_string(), gid.to_string()];
    event.tags.push(vec![P.to_string(), member.to_string()]);
    event
}

/// `kind:9001` removing several members in one event: the mirror of an
/// admin removal that dropped more than one `p` tag. One event per apply
/// (not one per member): the generated-event dedup keeps the last build
/// per `(kind, d)` slot, and these mirrors carry no `d` tag.
pub(crate) fn build_remove_users(
    gid: &str,
    members: &[String],
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut event = base_event(9001, gid, relay_pubkey, now);
    event.tags[0] = vec![H.to_string(), gid.to_string()];
    for member in members {
        event.tags.push(vec![P.to_string(), member.clone()]);
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group_with_members() -> Group {
        let mut group = Group::default();
        group
            .members
            .entry("admin1".into())
            .or_default()
            .insert("admin".into());
        group
            .members
            .entry("mod1".into())
            .or_default()
            .insert("mod".into());
        group.members.insert("member1".into(), Default::default());
        group.settings.name = "Test Group".into();
        group.settings.private = true;
        group.settings.closed = true;
        group.settings.supported_kinds = Some(vec![1, 7]);
        group.parent = Some("parent-g".into());
        group.children.push("child-g".into());
        group.pins.push(("e".into(), "a".repeat(64)));
        group
    }

    #[test]
    fn builders_produce_spec_shaped_events() {
        let group = group_with_members();
        let now = 1_700_000_000;

        let meta = build_meta_event("g1", Some(&group), "relay", now);
        assert_eq!(meta.kind, GROUP_META);
        assert_eq!(meta.pubkey, "relay");
        assert_eq!(meta.created_at, now);
        assert!(
            meta.tags
                .iter()
                .any(|t| t == &vec!["d".to_string(), "g1".to_string()])
        );
        assert!(
            meta.tags
                .iter()
                .any(|t| t == &vec!["name".to_string(), "Test Group".to_string()])
        );
        assert!(meta.tags.iter().any(|t| t == &vec!["private".to_string()]));
        assert!(meta.tags.iter().any(|t| t == &vec!["closed".to_string()]));
        assert!(meta.tags.iter().any(|t| t
            == &vec![
                "supported_kinds".to_string(),
                "1".to_string(),
                "7".to_string()
            ]));
        assert!(
            meta.tags
                .iter()
                .any(|t| t == &vec!["parent".to_string(), "parent-g".to_string()])
        );
        assert!(
            meta.tags
                .iter()
                .any(|t| t == &vec!["child".to_string(), "child-g".to_string()])
        );

        // Admins: only members with roles, sorted deterministically.
        let admins = build_admins_event("g1", Some(&group), "relay", now);
        assert_eq!(admins.kind, GROUP_ADMINS);
        let admin_tags: Vec<&Vec<String>> = admins.tags.iter().filter(|t| t[0] == P).collect();
        assert_eq!(admin_tags.len(), 2, "admins and mods");
        assert_eq!(admin_tags[0][1], "admin1");
        assert_eq!(admin_tags[1][1], "mod1");
        assert_eq!(admin_tags[1][2], "mod");

        // Members: everyone, plain p tags, sorted.
        let members = build_members_event("g1", Some(&group), "relay", now);
        assert_eq!(members.kind, GROUP_MEMBERS);
        let member_tags: Vec<&String> = members
            .tags
            .iter()
            .filter(|t| t[0] == P)
            .map(|t| &t[1])
            .collect();
        assert_eq!(member_tags, vec!["admin1", "member1", "mod1"]);

        // Pins.
        let pins = build_pins_event("g1", Some(&group), "relay", now);
        assert_eq!(pins.kind, GROUP_PINS);
        assert!(
            pins.tags
                .iter()
                .any(|t| t == &vec!["e".to_string(), "a".repeat(64)])
        );

        // Put/remove user carry the h tag instead of d.
        let put = build_put_user("g1", "member1", &["mod"], "relay", now);
        assert_eq!(put.kind, 9000);
        assert!(
            put.tags
                .iter()
                .any(|t| t == &vec![H.to_string(), "g1".into()])
        );
        assert!(
            put.tags
                .iter()
                .any(|t| t == &vec![P.to_string(), "member1".into(), "mod".into()])
        );
        let remove = build_remove_user("g1", "member1", "relay", now);
        assert_eq!(remove.kind, 9001);
        assert!(
            remove
                .tags
                .iter()
                .any(|t| t == &vec![P.to_string(), "member1".into()])
        );

        // A missing group produces the bare metadata event.
        let bare = build_meta_event("g2", None, "relay", now);
        assert_eq!(bare.kind, GROUP_META);
        assert_eq!(bare.tags.len(), 1);
        let bare_admins = build_admins_event("g2", None, "relay", now);
        assert_eq!(bare_admins.tags.len(), 1);
    }

    #[test]
    fn apply_settings_replaces_entire_settings() {
        let mut group = Group::default();
        group.settings.name = "old".into();
        let mut edit = base_event(9002, "g1", "relay", 1);
        edit.tags[0] = vec![H.to_string(), "g1".into()];
        edit.tags
            .push(vec!["name".to_string(), "new name".to_string()]);
        edit.tags.push(vec!["private".to_string()]);
        edit.tags
            .push(vec!["supported_kinds".to_string(), "30023".to_string()]);
        edit.tags.push(vec![
            "bad_value".to_string(),
            "x".to_string(),
            "y".to_string(),
        ]);
        apply_settings(&mut group, &edit);
        assert_eq!(group.settings.name, "new name");
        assert!(group.settings.private);
        // The old settings are gone (replacement semantics).
        assert!(!group.settings.closed);
        assert_eq!(group.settings.supported_kinds, Some(vec![30023]));
    }
}
