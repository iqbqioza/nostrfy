//! Relay-generated NIP-29 events: metadata (39000), admins (39001),
//! members (39002), roles (39003), participants (39004), pins (39005) and
//! the put-user/remove-user moderation events emitted by the group state
//! machine.

use crate::event::Event;

use super::{
    D, GROUP_ADMINS, GROUP_MEMBERS, GROUP_META, GROUP_PARTICIPANTS, GROUP_PINS, GROUP_ROLES, Group,
    GroupSettings, H, P,
};
/// Applies a kind:9007/9002 metadata event.
///
/// In Buzz mode (`buzz = true`) this is a **partial update**: Buzz clients
/// send only the fields they intend to change, and replacing the whole
/// settings object would silently clear an unrelated `private` flag when a
/// client renames a channel. An absent tag leaves the setting untouched; an
/// explicit empty value clears a string/optional field.
///
/// In plain NIP-29 mode (`buzz = false`) the pre-Buzz behavior is kept:
/// the event replaces the NIP-29 metadata, because NIP-29's `9002` table
/// describes it as carrying "all the fields of group-metadata". Buzz-only
/// settings (topic/purpose/ttl/archived/join_role) are preserved so a
/// normal client's edit cannot wipe them.
pub(crate) fn apply_settings(group: &mut Group, event: &Event, buzz: bool) {
    if !buzz {
        apply_nip29_settings(group, event);
        return;
    }
    for tag in &event.tags {
        if tag.is_empty() {
            continue;
        }
        let value = tag.get(1).map(String::as_str);
        match tag[0].as_str() {
            "name" | "picture" | "banner" | "about" => {
                if let Some(value) = value {
                    match tag[0].as_str() {
                        "name" => group.settings.name = value.to_string(),
                        "picture" => group.settings.picture = value.to_string(),
                        "banner" => group.settings.banner = value.to_string(),
                        _ => group.settings.about = value.to_string(),
                    }
                }
            }
            "topic" => group.settings.topic = value.filter(|v| !v.is_empty()).map(str::to_string),
            "purpose" => {
                group.settings.purpose = value.filter(|v| !v.is_empty()).map(str::to_string)
            }
            "ttl" => {
                group.settings.ttl = value
                    .filter(|v| !v.is_empty())
                    .and_then(|v| v.parse::<u64>().ok())
            }
            "archived" => group.settings.archived = value != Some("false") && value != Some("0"),
            "join_role" => {
                group.settings.join_role = value.filter(|v| !v.is_empty()).map(str::to_string)
            }
            // NIP-CL: `visibility` is the Buzz spelling of the NIP-29
            // private flag; `public` is its explicit inverse.
            "visibility" => match value {
                Some("private") => {
                    group.settings.private = true;
                    // Buzz's private channels are member-only for writes and
                    // joins as well as reads; NIP-CL has no separate flags.
                    group.settings.restricted = true;
                    group.settings.closed = true;
                }
                Some("open" | "public") => {
                    group.settings.private = false;
                    group.settings.restricted = false;
                    group.settings.closed = false;
                }
                _ => {}
            },
            "private" => group.settings.private = true,
            "public" => group.settings.private = false,
            "restricted" => {
                group.settings.restricted = value != Some("false") && value != Some("0")
            }
            "closed" => group.settings.closed = value != Some("false") && value != Some("0"),
            "hidden" => group.settings.hidden = value != Some("false") && value != Some("0"),
            "livekit" => group.settings.livekit = value != Some("false") && value != Some("0"),
            "supported_kinds" => {
                group.settings.supported_kinds =
                    Some(tag[1..].iter().filter_map(|k| k.parse().ok()).collect())
            }
            // NIP-CL labels: `t` tags replace the whole label set. `["t",""]`
            // alone clears it; a 9002 without `t` leaves it unchanged.
            "t" => {}
            _ => {}
        }
    }
    // NIP-CL announce channels: `join_role=guest` means only members (and
    // guests are read-only) may post, which NIP-29 expresses as
    // `restricted`. Changing it back to `member` clears the flag unless the
    // channel is private for another reason.
    if let Some(role) = &group.settings.join_role {
        if role == "member" {
            if !group.settings.private {
                group.settings.restricted = false;
            }
        } else {
            group.settings.restricted = true;
        }
    }
    // Labels are group-level (the channel type never changes); handle them
    // once after the field loop. Only a 9002/9007 that actually carries `t`
    // tags replaces the set.
    if event
        .tags
        .iter()
        .any(|tag| tag.first().is_some_and(|t| t == "t"))
    {
        group.labels = super::label_values(event);
        group.labels.retain(|label| !label.is_empty());
    }
}

/// NIP-29's original whole-metadata semantics for `9002`/`9007`: fields
/// absent from the event are cleared. Buzz-only settings are kept so a plain
/// NIP-29 edit does not erase state that only another Buzz client can see or
/// change.
fn apply_nip29_settings(group: &mut Group, event: &Event) {
    let old = group.settings.clone();
    let mut settings = GroupSettings {
        topic: old.topic,
        purpose: old.purpose,
        ttl: old.ttl,
        archived: old.archived,
        join_role: old.join_role,
        ..GroupSettings::default()
    };
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
    buzz: bool,
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
    if buzz {
        if let Some(topic) = &s.topic {
            event.tags.push(vec!["topic".to_string(), topic.clone()]);
        }
        if let Some(purpose) = &s.purpose {
            event
                .tags
                .push(vec!["purpose".to_string(), purpose.clone()]);
        }
        if let Some(ttl) = s.ttl {
            event.tags.push(vec!["ttl".to_string(), ttl.to_string()]);
        }
        if s.archived {
            event
                .tags
                .push(vec!["archived".to_string(), "true".to_string()]);
        }
    }
    if s.private {
        event.tags.push(vec!["private".to_string()]);
    } else if buzz {
        // NIP-29 expresses a public group by omitting `private`; the
        // explicit tag is a Buzz/NIP-CL aid.
        event.tags.push(vec!["public".to_string()]);
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
    if let Some(join_role) = &s.join_role
        && buzz
    {
        event
            .tags
            .push(vec!["join_role".to_string(), join_role.clone()]);
    }
    if let Some(kinds) = &s.supported_kinds {
        let mut tag = vec!["supported_kinds".to_string()];
        tag.extend(kinds.iter().map(u64::to_string));
        event.tags.push(tag);
    }
    if buzz {
        super::push_channel_identity_tags(&mut event, Some(group), true);
        // Buzz reads a DM's participants from the lowercase `p` tags on its
        // kind:39000 (the kind:39002 roster is a separate query). Only DMs
        // pay this cost, and their participant set is bounded at 64 keys.
        if group.channel_type == "dm" {
            let mut members: Vec<&String> = group.members.keys().collect();
            members.sort();
            for member in members {
                event.tags.push(vec![P.to_string(), member.clone()]);
            }
        }
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
    buzz: bool,
) -> Event {
    let mut event = base_event(GROUP_ADMINS, gid, relay_pubkey, now);
    if buzz {
        super::push_channel_identity_tags(&mut event, group, false);
    }
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
    buzz: bool,
) -> Event {
    let mut event = base_event(GROUP_MEMBERS, gid, relay_pubkey, now);
    if buzz {
        super::push_channel_identity_tags(&mut event, group, false);
    }
    if let Some(group) = group {
        let mut members: Vec<String> = group.members.keys().cloned().collect();
        members.sort();
        for pk in members {
            if !buzz {
                // NIP-29 defines the member list as bare `p` tags.
                event.tags.push(vec![P.to_string(), pk]);
                continue;
            }
            // Buzz reads a member's role from the fourth element of the
            // `p` tag (`["p", pubkey, relay_url, role]`, NIP-29's
            // convention). Without it every member, including an admin,
            // defaults to `member`, and Buzz reports that the member list
            // and role list disagree. Keep the relay URL empty because the
            // event is signed by this relay.
            let role = if group.guests.contains(&pk) {
                "guest".to_string()
            } else if group.bots.contains(&pk) {
                "bot".to_string()
            } else {
                group
                    .members
                    .get(&pk)
                    .map(|roles| {
                        // Prefer the role names Buzz understands; an
                        // arbitrary NIP-29 role is still published verbatim
                        // (and is listed by kind:39003, so the two stay
                        // consistent).
                        if roles.contains("owner") {
                            "owner".to_string()
                        } else if roles.contains("admin") {
                            "admin".to_string()
                        } else if roles.contains("bot") {
                            "bot".to_string()
                        } else {
                            roles
                                .iter()
                                .min()
                                .cloned()
                                .unwrap_or_else(|| "member".to_string())
                        }
                    })
                    .unwrap_or_else(|| "member".to_string())
            };
            event
                .tags
                .push(vec![P.to_string(), pk, String::new(), role]);
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

pub(crate) fn build_roles_event(
    gid: &str,
    group: Option<&Group>,
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut event = base_event(GROUP_ROLES, gid, relay_pubkey, now);
    if let Some(group) = group {
        // NIP-29's `39003` informs clients about the roles in use. This
        // relay keeps no separate role registry (any non-empty role label
        // is an admin role, per the free-form NIP-29 model), so the list
        // is derived from the roles actually assigned to members. Sorted
        // so the relay-generated event is deterministic across restarts
        // (a HashSet iteration order would change the event id).
        let mut roles: Vec<&str> = group
            .members
            .values()
            .flat_map(|roles| roles.iter().map(String::as_str))
            .collect();
        roles.sort_unstable();
        roles.dedup();
        for role in roles {
            event.tags.push(vec!["role".to_string(), role.to_string()]);
        }
    }
    event
}

pub(crate) fn build_participants_event(
    gid: &str,
    participants: &[String],
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut event = base_event(GROUP_PARTICIPANTS, gid, relay_pubkey, now);
    for pubkey in participants {
        event
            .tags
            .push(vec!["participant".to_string(), pubkey.clone()]);
    }
    event
}

/// Buzz `kind:40099` system message. Stored channel-scoped (it carries `h`),
/// so it appears in the channel timeline as a relay-signed row.
pub(crate) fn build_system_message(
    gid: &str,
    actor: &str,
    target: Option<&str>,
    message_type: &str,
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut content = serde_json::Map::new();
    content.insert("type".into(), serde_json::json!(message_type));
    content.insert("actor".into(), serde_json::json!(actor));
    if let Some(target) = target {
        content.insert("target".into(), serde_json::json!(target));
    }
    Event {
        id: String::new(),
        pubkey: relay_pubkey.to_string(),
        created_at: now,
        kind: super::SYSTEM_MESSAGE,
        tags: vec![vec![H.to_string(), gid.to_string()]],
        content: serde_json::Value::Object(content).to_string(),
        sig: String::new(),
    }
}

/// Buzz `kind:44100`/`44101` membership notification. It carries the channel
/// `h` tag for context but is stored community-globally by the relay.
pub(crate) fn build_membership_notice(
    kind: u64,
    gid: &str,
    channel_type: &str,
    target: &str,
    actor: &str,
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let message_type = if kind == super::MEMBER_ADDED {
        "member_added"
    } else {
        "member_removed"
    };
    let content = serde_json::json!({
        "type": message_type,
        "channel_id": gid,
        "actor": actor,
    });
    Event {
        id: String::new(),
        pubkey: relay_pubkey.to_string(),
        created_at: now,
        kind,
        tags: vec![
            vec![P.to_string(), target.to_string()],
            vec![H.to_string(), gid.to_string()],
            vec!["t".to_string(), channel_type.to_string()],
        ],
        content: content.to_string(),
        sig: String::new(),
    }
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

        let meta = build_meta_event("g1", Some(&group), "relay", now, true);
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
        let admins = build_admins_event("g1", Some(&group), "relay", now, true);
        assert_eq!(admins.kind, GROUP_ADMINS);
        let admin_tags: Vec<&Vec<String>> = admins.tags.iter().filter(|t| t[0] == P).collect();
        assert_eq!(admin_tags.len(), 2, "admins and mods");
        assert_eq!(admin_tags[0][1], "admin1");
        assert_eq!(admin_tags[1][1], "mod1");
        assert_eq!(admin_tags[1][2], "mod");

        // Members: everyone, with Buzz's `["p", pubkey, "", role]` shape.
        let members = build_members_event("g1", Some(&group), "relay", now, true);
        assert_eq!(members.kind, GROUP_MEMBERS);
        let member_tags: Vec<&Vec<String>> = members.tags.iter().filter(|t| t[0] == P).collect();
        assert_eq!(member_tags.len(), 3);
        assert_eq!(member_tags[0][1], "admin1");
        assert_eq!(member_tags[0][3], "admin");
        assert_eq!(member_tags[1][1], "member1");
        assert_eq!(member_tags[1][3], "member");
        assert_eq!(member_tags[2][1], "mod1");
        assert_eq!(member_tags[2][3], "mod");
        assert!(
            member_tags.iter().all(|t| t[2].is_empty()),
            "the relay URL is implicit and must stay empty"
        );

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
        let bare = build_meta_event("g2", None, "relay", now, true);
        assert_eq!(bare.kind, GROUP_META);
        assert_eq!(bare.tags.len(), 1);
        let bare_admins = build_admins_event("g2", None, "relay", now, true);
        assert_eq!(bare_admins.tags.len(), 1);
    }

    #[test]
    fn members_event_carries_the_guest_role() {
        let mut group = group_with_members();
        group.members.insert("guest1".into(), Default::default());
        group.guests.insert("guest1".into());
        let members = build_members_event("g1", Some(&group), "relay", 1, true);
        assert!(
            members.tags.iter().any(|t| t
                == &vec![
                    P.to_string(),
                    "guest1".to_string(),
                    String::new(),
                    "guest".to_string()
                ]),
            "a read-only guest must not be reported as a plain member"
        );
    }

    #[test]
    fn apply_settings_updates_only_present_fields() {
        let mut group = Group::default();
        group.settings.name = "old".into();
        group.settings.closed = true;
        let mut edit = base_event(9002, "g1", "relay", 1);
        edit.tags[0] = vec![H.to_string(), "g1".into()];
        edit.tags
            .push(vec!["name".to_string(), "new name".to_string()]);
        edit.tags
            .push(vec!["visibility".to_string(), "private".to_string()]);
        edit.tags
            .push(vec!["supported_kinds".to_string(), "30023".to_string()]);
        edit.tags.push(vec![
            "bad_value".to_string(),
            "x".to_string(),
            "y".to_string(),
        ]);
        apply_settings(&mut group, &edit, true);
        assert_eq!(group.settings.name, "new name");
        assert!(group.settings.private);
        // Absent fields are left alone (Buzz/NIP-CL partial updates).
        assert!(group.settings.closed);
        assert_eq!(group.settings.supported_kinds, Some(vec![30023]));

        // An explicit visibility=open clears the private flag.
        let mut open = base_event(9002, "g1", "relay", 2);
        open.tags[0] = vec![H.to_string(), "g1".into()];
        open.tags
            .push(vec!["visibility".to_string(), "open".to_string()]);
        apply_settings(&mut group, &open, true);
        assert!(!group.settings.private);
    }

    #[test]
    fn plain_nip29_builders_omit_buzz_extensions() {
        let mut group = group_with_members();
        group.settings.private = false;
        let meta = build_meta_event("g1", Some(&group), "relay", 1, false);
        assert!(
            !meta.tags.iter().any(|t| t[0] == "public"),
            "plain NIP-29 expresses a public group by omitting private"
        );
        for extension in [
            "topic",
            "purpose",
            "ttl",
            "archived",
            "join_role",
            "P",
            "created_at",
        ] {
            assert!(
                !meta.tags.iter().any(|t| t[0] == extension),
                "plain NIP-29 metadata must not carry the Buzz tag {extension}: {:?}",
                meta.tags
            );
        }
        assert!(
            !meta.tags.iter().any(|t| t[0] == "t"),
            "NIP-CL channel identity tags are Buzz-only: {:?}",
            meta.tags
        );

        let members = build_members_event("g1", Some(&group), "relay", 1, false);
        assert!(
            members
                .tags
                .iter()
                .filter(|t| t[0] == P)
                .all(|t| t.len() == 2),
            "plain NIP-29 39002 uses bare p tags: {:?}",
            members.tags
        );
        let admins = build_admins_event("g1", Some(&group), "relay", 1, false);
        assert!(
            !admins.tags.iter().any(|t| t[0] == "t" || t[0] == "P"),
            "Buzz identity tags must not leak into a plain 39001: {:?}",
            admins.tags
        );
    }

    #[test]
    fn plain_nip29_edit_replaces_metadata() {
        let mut group = Group::default();
        group.settings.name = "old".into();
        group.settings.closed = true;
        group.settings.topic = Some("keep me".into());
        let mut edit = base_event(9002, "g1", "relay", 1);
        edit.tags[0] = vec![H.to_string(), "g1".into()];
        edit.tags.push(vec!["name".into(), "new".into()]);
        // Plain NIP-29: a 9002 carries the whole metadata. The absent
        // `closed` tag clears it.
        apply_settings(&mut group, &edit, false);
        assert_eq!(group.settings.name, "new");
        assert!(!group.settings.closed);
        assert_eq!(
            group.settings.topic.as_deref(),
            Some("keep me"),
            "a plain edit must not wipe Buzz-only state"
        );
    }
}
