//! Relay-generated NIP-29 events: metadata (39000), admins (39001),
//! members (39002), roles (39003), participants (39004), pins (39005) and
//! the put-user/remove-user moderation events emitted by the group state
//! machine.

use crate::event::Event;

use super::{
    D, GROUP_ADMINS, GROUP_MEMBERS, GROUP_META, GROUP_PARTICIPANTS, GROUP_PINS, GROUP_ROLES, Group,
    GroupSettings, H, JOIN_MIRROR_TAG, P,
};
fn has_tag(event: &Event, name: &str) -> bool {
    event
        .tags
        .iter()
        .any(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
}

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
/// normal client's edit cannot wipe them. `history` marks a rebuild replay:
/// a stored `visibility=private` is then honored as a privacy floor even
/// with Buzz disabled, so turning the compatibility layer off cannot expose
/// a Buzz-created private channel whose only privacy marker is NIP-CL's tag.
pub(crate) fn apply_settings(group: &mut Group, event: &Event, buzz: bool, history: bool) {
    if !buzz {
        apply_nip29_settings(group, event, history);
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
                    // A DM/system channel also hides its metadata from
                    // non-members; `private` alone only gates messages.
                    if matches!(group.channel_type.as_str(), "dm" | "system") {
                        group.settings.hidden = true;
                    }
                }
                Some("open" | "public") => {
                    group.settings.private = false;
                    group.settings.restricted = false;
                    group.settings.closed = false;
                    // An explicit open DM/system channel is meant to make
                    // its metadata reachable again.
                    if matches!(group.channel_type.as_str(), "dm" | "system") {
                        group.settings.hidden = false;
                    }
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
    // channel is private for another reason. Re-derive only when this event
    // actually carries join_role, so an explicit `restricted` tag is not
    // overwritten by the old value in a partial edit.
    if has_tag(event, "join_role")
        && !has_tag(event, "restricted")
        && let Some(role) = &group.settings.join_role
    {
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

/// The privacy floor for a stored Buzz/NIP-CL create replayed while Buzz is
/// off. Plain NIP-29 `9007` carries no metadata (live creates keep their
/// pre-Buzz default settings), but a Buzz-created private channel may carry
/// only `visibility=private` on its create; dropping that on a rebuild would
/// expose its stored messages.
pub(crate) fn apply_plain_create_privacy(group: &mut Group, event: &Event) {
    for tag in &event.tags {
        let value = tag.get(1).map(String::as_str);
        match tag.first().map(String::as_str) {
            Some("visibility") if value == Some("private") => {
                group.settings.private = true;
                group.settings.restricted = true;
                group.settings.closed = true;
            }
            Some("private") => group.settings.private = true,
            Some("restricted") => group.settings.restricted = true,
            Some("closed") => group.settings.closed = true,
            Some("hidden") => group.settings.hidden = true,
            _ => {}
        }
    }
}

/// NIP-29's original whole-metadata semantics for `9002`/`9007`: fields
/// absent from the event are cleared. Buzz-only settings are kept so a plain
/// NIP-29 edit does not erase state that only another Buzz client can see or
/// change. A stored Buzz partial edit on a Buzz-origin group (non-empty
/// `channel_type` or `buzz_metadata`) is replayed as partial even with the
/// compatibility layer disabled; a **live** plain edit keeps only the
/// privacy floor and otherwise follows NIP-29 whole-metadata replacement.
fn apply_nip29_settings(group: &mut Group, event: &Event, history: bool) {
    let old = group.settings.clone();
    // A Buzz-created channel always carries a channel_type. A plain-origin
    // group edited by Buzz carries `buzz_metadata`; both must keep the
    // partial-edit privacy floor after Buzz is disabled. A genuinely plain
    // group has neither and keeps the original whole-metadata semantics.
    let buzz_origin = !group.channel_type.is_empty() || group.buzz_metadata;
    let partial = history && buzz_origin;
    let mut settings = GroupSettings {
        topic: old.topic,
        purpose: old.purpose,
        ttl: old.ttl,
        archived: old.archived,
        join_role: old.join_role,
        ..GroupSettings::default()
    };
    if partial {
        // A stored Buzz edit represents only the fields it carried; preserve
        // the rest while rebuilding a Buzz-created channel instead of
        // applying plain NIP-29's whole-metadata replacement.
        settings.name = old.name;
        settings.picture = old.picture;
        settings.banner = old.banner;
        settings.about = old.about;
        settings.private = old.private;
        settings.restricted = old.restricted;
        settings.closed = old.closed;
        settings.hidden = old.hidden;
        settings.livekit = old.livekit;
        settings.supported_kinds = old.supported_kinds;
    } else if buzz_origin {
        // A live plain edit after Buzz was disabled is still NIP-29 whole
        // metadata for ordinary clients, but a missing privacy tag must not
        // expose stored private/hidden content. The explicit privacy tags
        // below can still open the group.
        settings.private = old.private;
        settings.restricted = old.restricted;
        settings.closed = old.closed;
        settings.hidden = old.hidden;
    }
    for tag in &event.tags {
        if tag.is_empty() {
            continue;
        }
        let value = tag.get(1).map(String::as_str);
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
            "public" if buzz_origin => settings.private = false,
            "restricted" if buzz_origin => {
                settings.restricted = value != Some("false") && value != Some("0")
            }
            "closed" if buzz_origin => {
                settings.closed = value != Some("false") && value != Some("0")
            }
            "hidden" if buzz_origin => {
                settings.hidden = value != Some("false") && value != Some("0")
            }
            "livekit" if buzz_origin => {
                settings.livekit = value != Some("false") && value != Some("0")
            }
            "restricted" => settings.restricted = true,
            "closed" => settings.closed = true,
            "hidden" => settings.hidden = true,
            "livekit" => settings.livekit = true,
            "topic" if buzz_origin => {
                settings.topic = value.filter(|v| !v.is_empty()).map(str::to_string)
            }
            "purpose" if buzz_origin => {
                settings.purpose = value.filter(|v| !v.is_empty()).map(str::to_string)
            }
            "ttl" if buzz_origin => {
                settings.ttl = value
                    .filter(|v| !v.is_empty())
                    .and_then(|v| v.parse::<u64>().ok())
            }
            "archived" if buzz_origin => {
                settings.archived = value != Some("false") && value != Some("0")
            }
            "join_role" if buzz_origin => {
                settings.join_role = value.filter(|v| !v.is_empty()).map(str::to_string)
            }
            // A Buzz-created private channel has no NIP-29 `private` tag;
            // turning Buzz off must not make its stored messages
            // world-readable, whether the edit is live or replayed. On a
            // plain group, only `visibility=private` is honored as a
            // history privacy floor; on a Buzz-origin group,
            // `visibility=open` is the explicit transition that clears the
            // Buzz privacy.
            "visibility" if buzz_origin || history => match value {
                Some("private") => {
                    settings.private = true;
                    settings.restricted = true;
                    settings.closed = true;
                    if matches!(group.channel_type.as_str(), "dm" | "system") {
                        settings.hidden = true;
                    }
                }
                Some("open" | "public") if buzz_origin => {
                    settings.private = false;
                    settings.restricted = false;
                    settings.closed = false;
                    if matches!(group.channel_type.as_str(), "dm" | "system") {
                        settings.hidden = false;
                    }
                }
                _ => {}
            },
            "supported_kinds" => {
                settings.supported_kinds =
                    Some(tag[1..].iter().filter_map(|k| k.parse().ok()).collect())
            }
            _ => {}
        }
    }
    if buzz_origin {
        // Only an event that actually changes join_role may re-derive
        // `restricted`; otherwise an explicit `restricted` tag in the same
        // 9002 would be overwritten by the old join_role.
        if has_tag(event, "join_role")
            && !has_tag(event, "restricted")
            && let Some(role) = &settings.join_role
        {
            if role == "member" {
                // Clearing join_role=guest must not open a private channel.
                settings.restricted &= settings.private;
            } else {
                settings.restricted = true;
            }
        }
        if event
            .tags
            .iter()
            .any(|tag| tag.first().is_some_and(|name| name == "t"))
        {
            group.labels = super::label_values(event);
            group.labels.retain(|label| !label.is_empty());
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
    }
    // Buzz reads a DM's participants from the lowercase `p` tags on its
    // kind:39000 (the kind:39002 roster is a separate query). Keep them even
    // while the Buzz layer is disabled: a DM is a Buzz-only group, and a
    // plain-mode membership edit must not overwrite its metadata without the
    // participant list.
    if group.channel_type == "dm" {
        let mut members: Vec<&String> = group.members.keys().collect();
        members.sort();
        for member in members {
            event.tags.push(vec![P.to_string(), member.clone()]);
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
    buzz: bool,
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
        // Buzz's guest/bot tiers are published in 39002 but are not NIP-29
        // role labels on the member map. List them here as well so the two
        // relay-generated rosters agree; plain mode never writes these sets
        // (and must not expose a stale snapshot's Buzz-only state).
        if buzz {
            roles.extend(group.guests.iter().map(|_| "guest"));
            roles.extend(group.bots.iter().map(|_| "bot"));
        }
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
        .tags
        .push(vec![JOIN_MIRROR_TAG.to_string(), "1".to_string()]);
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
        apply_settings(&mut group, &edit, true, false);
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
        apply_settings(&mut group, &open, true, false);
        assert!(!group.settings.private);
    }

    #[test]
    fn a_plain_mode_dm_meta_still_lists_its_participants() {
        let mut group = Group {
            channel_type: "dm".into(),
            settings: GroupSettings {
                private: true,
                hidden: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        group.members.insert(a.clone(), Default::default());
        group.members.insert(b.clone(), Default::default());
        let meta = build_meta_event("dm-1", Some(&group), "relay", 1, false);
        let participants: Vec<&str> = meta
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|name| name == P))
            .filter_map(|tag| tag.get(1).map(String::as_str))
            .collect();
        assert_eq!(participants.len(), 2);
        assert!(participants.contains(&a.as_str()));
        assert!(participants.contains(&b.as_str()));
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
    fn plain_history_replay_preserves_buzz_private_visibility() {
        // A Buzz private channel is marked with NIP-CL's `visibility`
        // instead of NIP-29's `private`. If Buzz is turned off and the
        // group state is rebuilt from stored events, the privacy flag must
        // survive; otherwise the stored messages become world-readable.
        let mut group = Group::default();
        let mut private = base_event(9002, "g1", "relay", 1);
        private.tags[0] = vec![H.to_string(), "g1".into()];
        private
            .tags
            .push(vec!["visibility".into(), "private".into()]);
        group.channel_type = "stream".into();
        apply_settings(&mut group, &private, false, true);
        assert!(group.settings.private);
        assert!(group.settings.restricted);
        assert!(group.settings.closed);

        // A later stored Buzz 9002 is partial: its missing privacy tags must
        // not clear the private setting during the rebuild.
        let mut rename = base_event(9002, "g1", "relay", 2);
        rename.tags[0] = vec![H.to_string(), "g1".into()];
        rename.tags.push(vec!["name".into(), "renamed".into()]);
        apply_settings(&mut group, &rename, false, true);
        assert!(group.settings.private);
        assert!(group.settings.restricted);
        assert!(group.settings.closed);
        assert_eq!(group.settings.name, "renamed");

        // On a Buzz-origin group, visibility=open is a stored Buzz
        // transition and is honored on replay.
        let mut buzz_origin = Group {
            channel_type: "stream".into(),
            settings: GroupSettings {
                private: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut open = base_event(9002, "g1", "relay", 3);
        open.tags[0] = vec![H.to_string(), "g1".into()];
        open.tags.push(vec!["visibility".into(), "open".into()]);
        apply_settings(&mut buzz_origin, &open, false, true);
        assert!(!buzz_origin.settings.private);

        // Live plain NIP-29 still ignores the Buzz-only visibility tag.
        let mut live = Group::default();
        apply_settings(&mut live, &private, false, false);
        assert!(!live.settings.private);
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
        apply_settings(&mut group, &edit, false, false);
        assert_eq!(group.settings.name, "new");
        assert!(!group.settings.closed);
        assert_eq!(
            group.settings.topic.as_deref(),
            Some("keep me"),
            "a plain edit must not wipe Buzz-only state"
        );
    }
}
