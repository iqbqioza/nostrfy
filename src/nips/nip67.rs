//! NIP-67: EOSE Completeness Hint.
//!
//! The relay appends a hint array to `EOSE` messages: `["EOSE", sub, ["finish"]]`
//! when every servable stored event was delivered, `["EOSE", sub, ["more"]]`
//! when a limit stopped the scan early, and `["EOSE", sub, ["auth", "finish"]]`
//! when stored events matching the filters were withheld pending NIP-42 AUTH
//! (protected events, gift wraps, NIP-78 owner data, private groups). The
//! `"auth"` hint is always preceded by an `AUTH` challenge, per the spec. The
//! `more` flag is computed by the database scan (`db::scan`), the `auth` flag
//! by the connection's visibility rules in `ws::handle_req`, and the message is
//! built in `ws::finish_pending_req`; this module exists to document the NIP.
