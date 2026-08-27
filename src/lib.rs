#![forbid(unsafe_code)]

//! The Party: the thing that has identities.
//!
//! Not a credential store and not a role. It is the actor, per ADR-0007 and
//! ADR-0008, and its identities are how it is recognised. Security roles stay
//! separate under ADR-0009: a Party is recognised, a role is granted.

pub mod identity;

pub use identity::{
    mechanism, Assurance, CredentialRef, Direction, Identity, IdentityClass, IdentityContext,
    Layer, Mechanism,
};

use xmip_core::PartyId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartyKind {
    Person,
    Organization,
    System,
    Service,
}

/// One actor, and every way it is recognised in either direction.
///
/// **A Party is a shortcut to an Identity, and grants nothing.** Resolving a
/// credential to a Party is a registry lookup, not a decision: the arrival is
/// authenticated and authorized at runtime whether or not it resolved to
/// something with a name. Being a known Party is not a permission, and ADR-0009
/// keeps the two apart — a Party is recognised, a role is granted.
///
/// What the registry buys is one place to edit. The alternative — credentials
/// configured inline on every Receive and Send Location — makes a partner's
/// certificate rotation a search across the estate rather than one edit, and
/// leaves nothing able to answer "what does partner-x use to reach us, and what
/// do we use to reach them". ADR-0019 clause 4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Party {
    pub party_id: PartyId,
    pub kind: PartyKind,
    pub name: String,
    pub identities: Vec<Identity>,
}

impl Party {
    #[must_use]
    pub fn new(party_id: PartyId, kind: PartyKind, name: impl Into<String>) -> Self {
        Self {
            party_id,
            kind,
            name: name.into(),
            identities: Vec::new(),
        }
    }

    #[must_use]
    pub fn with(mut self, identity: Identity) -> Self {
        self.identities.push(identity);
        self
    }

    /// Every identity this Party is recognised by, or presents.
    pub fn facing(&self, direction: Direction) -> impl Iterator<Item = &Identity> {
        self.identities
            .iter()
            .filter(move |identity| identity.direction == direction)
    }

    /// The value this Party carries under one mechanism, in one direction.
    ///
    /// Both are required. Asking for "the mutual-tls identity" without saying
    /// which way it faces is the question ADR-0019 clause 4 refuses: the
    /// certificate a partner presents to Xmip is not the one Xmip presents to
    /// that partner, and answering with either would be right half the time.
    #[must_use]
    pub fn identity(&self, mechanism: &str, direction: Direction) -> Option<&str> {
        self.facing(direction)
            .find(|identity| identity.mechanism.name() == mechanism)
            .map(|identity| identity.value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partner() -> Party {
        Party::new(PartyId::new(1), PartyKind::Organization, "partner-x")
            .with(Identity::accepted(
                mechanism::mutual_tls(),
                "CN=partner-x.example",
            ))
            .with(Identity::accepted(mechanism::oauth2(), "sub=partner-x"))
            .with(Identity::accepted(
                mechanism::edi_x12_interchange(),
                "ISA06=PARTNERX",
            ))
            .with(Identity::presented(
                mechanism::ssh_key(),
                "SHA256:abc",
                CredentialRef::new("ssh-agent", "xmip-outbound"),
            ))
    }

    #[test]
    fn receive_process_and_send_all_reach_the_same_registry() {
        // One Party, four ways in and one way out. The alternative —
        // credentials inline on every Receive and Send Location — makes a
        // certificate rotation a search across the estate rather than one edit.
        let party = partner();

        assert_eq!(party.facing(Direction::Accepted).count(), 3);
        assert_eq!(party.facing(Direction::Presented).count(), 1);
    }

    #[test]
    fn a_party_known_only_by_an_edi_identifier_still_resolves() {
        // X12 over a drop folder is a real deployment and Xmip carries it. What
        // the registry must not do is make it look like every other accepted
        // identity — authorization has to be able to tell the difference.
        let claims_only = Party::new(PartyId::new(2), PartyKind::Organization, "partner-y").with(
            Identity::accepted(mechanism::edi_x12_interchange(), "ISA06=PARTNERY"),
        );

        assert_eq!(
            claims_only.identity("edi-x12-interchange", Direction::Accepted),
            Some("ISA06=PARTNERY")
        );
        assert!(!claims_only
            .facing(Direction::Accepted)
            .any(|identity| identity.mechanism.authenticates()));
    }

    #[test]
    fn a_party_holds_identities_in_several_classes_at_once() {
        let classes: Vec<IdentityClass> = partner()
            .facing(Direction::Accepted)
            .map(|identity| identity.mechanism.class())
            .collect();

        assert!(classes.contains(&IdentityClass::HighAssurance));
        assert!(classes.contains(&IdentityClass::Federated));
        assert!(classes.contains(&IdentityClass::SharedSecret));
    }

    #[test]
    fn direction_is_part_of_the_question() {
        let party = partner();

        assert_eq!(
            party.identity("mutual-tls", Direction::Accepted),
            Some("CN=partner-x.example")
        );
        assert_eq!(party.identity("mutual-tls", Direction::Presented), None);
        assert_eq!(
            party.identity(mechanism::ssh_key().name(), Direction::Presented),
            Some("SHA256:abc")
        );
    }

    #[test]
    fn a_mechanism_names_itself_so_a_lookup_cannot_drift() {
        // `identity` takes a string because configuration arrives as strings,
        // and a string lookup silently returns None when a mechanism is
        // renamed. Anything inside Xmip asks the mechanism rather than
        // spelling the name again.
        let party = partner();

        for mechanism in [mechanism::mutual_tls(), mechanism::oauth2()] {
            assert!(
                party
                    .identity(mechanism.name(), Direction::Accepted)
                    .is_some(),
                "{} is declared on the Party and was not found",
                mechanism.name()
            );
        }
    }

    #[test]
    fn identity_travels_on_both_layers_for_one_party() {
        let party = partner();

        let transport = party
            .facing(Direction::Accepted)
            .filter(|identity| identity.mechanism.layer() == Layer::Transport)
            .count();
        let message = party
            .facing(Direction::Accepted)
            .filter(|identity| identity.mechanism.layer() == Layer::Message)
            .count();

        // Neither substitutes for the other. The transport says who opened the
        // connection; the message says on whose behalf the content was made.
        assert_eq!(transport, 2);
        assert_eq!(message, 1);
    }

    #[test]
    fn an_unknown_mechanism_is_absent_rather_than_guessed() {
        assert_eq!(partner().identity("kerberos", Direction::Accepted), None);
    }
}
