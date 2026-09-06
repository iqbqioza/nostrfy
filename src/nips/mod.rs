//! NIP modules and the documentation registry of the Nostr
//! proposal landscape.

pub mod nip01;
pub mod nip09;
pub mod nip11;
pub mod nip13;
pub mod nip19;
pub mod nip26;
pub mod nip29;
pub mod nip33;
pub mod nip40;
pub mod nip42;
pub mod nip43;
pub mod nip45;
pub mod nip50;
pub mod nip62;
pub mod nip66;
pub mod nip67;
pub mod nip70;
pub mod nip77;
pub mod nip78;
pub mod nip86;
pub mod nip98;

/// Registry of Nostr Improvement Proposals.
///
/// File-storage related NIPs (git NIP-34, file metadata NIP-94, HTTP file
/// storage NIP-96) are deliberately not included per the project rules.
/// The deprecated NIP-04 is also omitted.
///
/// Note: [`Config::supported_nips`] advertises only the relay-side NIPs
/// (see `RELAY_NIPS`); this registry is kept as documentation of the whole
/// landscape.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct NipDef {
    pub num: u16,
    /// Human-readable title; kept for documentation only.
    #[allow(dead_code)]
    pub title: &'static str,
}

/// Client-side NIPs whose identifiers are hexadecimal. They are pure client
/// conventions (no relay behaviour) and NIP-11 only advertises integer NIP
/// numbers, so they are kept here for documentation only. NIP-B7 (Blossom)
/// is file storage and excluded per the project rules; NIP-BE and NIP-EE
/// are unrecommended.
#[allow(dead_code)]
pub const CLIENT_NIPS: &[(&str, &str)] = &[
    ("5A", "Static Websites (nsites)"),
    ("7D", "Forum Threads"),
    ("A0", "Voice Messages"),
    ("A4", "Public Messages"),
    ("B0", "Web Bookmarks"),
    ("BE", "Nostr BLE Communications Protocol (unrecommended)"),
    ("C0", "Code Snippets"),
    ("C7", "Chats"),
    ("CC", "Geocaching"),
    ("EE", "E2EE Messaging using MLS Protocol (unrecommended)"),
    ("F4", "Podcasts"),
];

#[allow(dead_code)]
pub const NIPS: &[NipDef] = &[
    NipDef {
        num: 1,
        title: "Basic Protocol Flow",
    },
    NipDef {
        num: 2,
        title: "Follow List",
    },
    NipDef {
        num: 3,
        title: "OpenTimestamps Attestations",
    },
    NipDef {
        num: 5,
        title: "Mapping Nostr Keys to DNS Identifiers",
    },
    NipDef {
        num: 6,
        title: "Basic Key Derivation",
    },
    NipDef {
        num: 7,
        title: "window.nostr capability",
    },
    NipDef {
        num: 8,
        title: "Handling Mentions",
    },
    NipDef {
        num: 9,
        title: "Event Deletion",
    },
    NipDef {
        num: 10,
        title: "Conventions for e and p tags",
    },
    NipDef {
        num: 11,
        title: "Relay Information Document",
    },
    NipDef {
        num: 13,
        title: "Proof of Work",
    },
    NipDef {
        num: 14,
        title: "Subject tag in text notes",
    },
    NipDef {
        num: 15,
        title: "Nostr Marketplace",
    },
    NipDef {
        num: 17,
        title: "Private Direct Messages",
    },
    NipDef {
        num: 18,
        title: "Reposts",
    },
    NipDef {
        num: 19,
        title: "bech32-encoded entities",
    },
    NipDef {
        num: 21,
        title: "nostr: URI scheme",
    },
    NipDef {
        num: 22,
        title: "Comment",
    },
    NipDef {
        num: 23,
        title: "Long-form Content",
    },
    NipDef {
        num: 24,
        title: "Extra metadata fields",
    },
    NipDef {
        num: 25,
        title: "Reactions",
    },
    NipDef {
        num: 26,
        title: "Delegated Event Signing",
    },
    NipDef {
        num: 27,
        title: "Text Note References",
    },
    NipDef {
        num: 28,
        title: "Public Chat",
    },
    NipDef {
        num: 29,
        title: "Relay-based Groups",
    },
    NipDef {
        num: 30,
        title: "Custom Emoji",
    },
    NipDef {
        num: 31,
        title: "Dealing with Unknown Events",
    },
    NipDef {
        num: 32,
        title: "Labeling",
    },
    NipDef {
        num: 35,
        title: "Torrents",
    },
    NipDef {
        num: 36,
        title: "Sensitive Content",
    },
    NipDef {
        num: 37,
        title: "Draft Events",
    },
    NipDef {
        num: 38,
        title: "User Statuses",
    },
    NipDef {
        num: 39,
        title: "External Identities in Profiles",
    },
    NipDef {
        num: 40,
        title: "Expiration Timestamp",
    },
    NipDef {
        num: 42,
        title: "Authentication of clients to relays",
    },
    NipDef {
        num: 43,
        title: "Relay Access Metadata and Requests",
    },
    NipDef {
        num: 44,
        title: "Encrypted Payloads (Versioned)",
    },
    NipDef {
        num: 45,
        title: "Counting results",
    },
    NipDef {
        num: 46,
        title: "Nostr Connect",
    },
    NipDef {
        num: 47,
        title: "Wallet Connect",
    },
    NipDef {
        num: 48,
        title: "Proxy Tags",
    },
    NipDef {
        num: 49,
        title: "Private Key Encryption",
    },
    NipDef {
        num: 50,
        title: "Search Capability",
    },
    NipDef {
        num: 51,
        title: "Lists",
    },
    NipDef {
        num: 52,
        title: "Calendar Events",
    },
    NipDef {
        num: 53,
        title: "Live Activities",
    },
    NipDef {
        num: 54,
        title: "Wiki",
    },
    NipDef {
        num: 55,
        title: "Android Sign in with Nostr",
    },
    NipDef {
        num: 56,
        title: "Reporting",
    },
    NipDef {
        num: 57,
        title: "Lightning Zaps",
    },
    NipDef {
        num: 58,
        title: "Badges",
    },
    NipDef {
        num: 59,
        title: "Gift Wrap",
    },
    NipDef {
        num: 60,
        title: "Cashu Wallet",
    },
    NipDef {
        num: 61,
        title: "Nutzaps",
    },
    NipDef {
        num: 62,
        title: "Request to Vanish",
    },
    NipDef {
        num: 64,
        title: "Chess (PGN)",
    },
    NipDef {
        num: 65,
        title: "Relay List Metadata",
    },
    NipDef {
        num: 66,
        title: "Relay Discovery and Liveness Monitoring",
    },
    NipDef {
        num: 67,
        title: "EOSE Completeness Hint",
    },
    NipDef {
        num: 68,
        title: "Picture-first feeds",
    },
    NipDef {
        num: 69,
        title: "Peer-to-peer Order events",
    },
    NipDef {
        num: 70,
        title: "Protected Events",
    },
    NipDef {
        num: 71,
        title: "Video Events",
    },
    NipDef {
        num: 72,
        title: "Moderated Communities",
    },
    NipDef {
        num: 73,
        title: "External Content",
    },
    NipDef {
        num: 75,
        title: "Zap Goals",
    },
    NipDef {
        num: 77,
        title: "Negentropy Syncing",
    },
    NipDef {
        num: 78,
        title: "Application-specific data",
    },
    NipDef {
        num: 84,
        title: "Highlights",
    },
    NipDef {
        num: 85,
        title: "Trusted Assertions",
    },
    NipDef {
        num: 86,
        title: "Relay Management API",
    },
    NipDef {
        num: 87,
        title: "Cashu and Fedimint Discoverability",
    },
    NipDef {
        num: 88,
        title: "Polls",
    },
    NipDef {
        num: 89,
        title: "Recommended Application Handlers",
    },
    NipDef {
        num: 90,
        title: "Data Vending Machines",
    },
    NipDef {
        num: 92,
        title: "Media Attachments Metadata",
    },
    NipDef {
        num: 98,
        title: "HTTP Auth",
    },
    NipDef {
        num: 99,
        title: "Classified Listings",
    },
];
