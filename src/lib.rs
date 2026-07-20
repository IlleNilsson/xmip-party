#![forbid(unsafe_code)]

use xmip_core::PartyId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PartyKind {
    Person,
    Organization,
    System,
    Service,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Party {
    pub party_id: PartyId,
    pub kind: PartyKind,
    pub name: String,
    pub identifiers: Vec<(String, String)>,
}

impl Party {
    pub fn identifier(&self, scheme: &str) -> Option<&str> {
        self.identifiers
            .iter()
            .find(|(candidate, _)| candidate == scheme)
            .map(|(_, value)| value.as_str())
    }
}
