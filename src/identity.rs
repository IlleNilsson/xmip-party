//! One way a Party is recognised, or one Xmip acts under on its behalf.
//!
//! The vocabulary — [`Mechanism`], [`Purpose`], [`CredentialRef`],
//! [`IdentityContext`] — lives in `xmip-core`, because the three gates need it
//! and none of them depends on the Party. What is left here is the Party's own
//! half: the stored identity, which is a matcher for the two purposes that
//! verify something arriving and a credential reference for the two that
//! produce proof. ADR-0019 clause 4.

use xmip_core::{CredentialRef, IdentityContext, Mechanism, Purpose};

/// One way a Party is recognised, or one Xmip acts under on its behalf.
///
/// The purposes carry different things, and that asymmetry is the point:
///
/// - **Receive** carries a *matcher* — `CN=partner-x.example`, `sub=partner-x`,
///   `ISA06=PARTNERX`. Comparing an arriving credential against it needs no
///   secret, so nothing secret is stored.
/// - **Process** and **Send** carry a [`CredentialRef`] as well, because both
///   mean producing the proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub mechanism: Mechanism,
    pub purpose: Purpose,
    /// The value under that mechanism.
    pub value: String,
    /// Where the material lives. Always `None` for [`Purpose::Receive`].
    pub credential: Option<CredentialRef>,
}

impl Identity {
    /// An operator driving Xmip through one of its surfaces. Matched, like an
    /// arrival, and no secret is kept.
    #[must_use]
    pub fn operating(mechanism: Mechanism, value: impl Into<String>) -> Self {
        Self {
            mechanism,
            purpose: Purpose::Operate,
            value: value.into(),
            credential: None,
        }
    }

    /// Something arriving is matched against. No secret is needed or kept.
    #[must_use]
    pub fn receiving(mechanism: Mechanism, value: impl Into<String>) -> Self {
        Self {
            mechanism,
            purpose: Purpose::Receive,
            value: value.into(),
            credential: None,
        }
    }

    /// What a Process runs as, and therefore what decides its host process.
    #[must_use]
    pub fn processing(
        mechanism: Mechanism,
        value: impl Into<String>,
        credential: CredentialRef,
    ) -> Self {
        Self {
            mechanism,
            purpose: Purpose::Process,
            value: value.into(),
            credential: Some(credential),
        }
    }

    /// Something Xmip offers as a client. Presenting needs the material, so
    /// this names where it is kept.
    #[must_use]
    pub fn sending(
        mechanism: Mechanism,
        value: impl Into<String>,
        credential: CredentialRef,
    ) -> Self {
        Self {
            mechanism,
            purpose: Purpose::Send,
            value: value.into(),
            credential: Some(credential),
        }
    }

    /// The identity context this runs under. ADR-0022 clause 2.
    ///
    /// Only meaningful for [`Purpose::Process`] and [`Purpose::Send`], which
    /// hold credential material that a host process would keep in memory. A
    /// receive-side matcher holds nothing, so it isolates nothing.
    #[must_use]
    pub fn context(&self) -> Option<IdentityContext> {
        if !self.purpose.needs_credential() {
            return None;
        }

        let context = IdentityContext::new(&self.mechanism).with("principal", self.value.clone());

        Some(match &self.credential {
            Some(credential) => context.with("credential", credential.to_string()),
            None => context,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmip_core::mechanism;

    #[test]
    fn receiving_stores_a_matcher_and_the_other_two_store_a_reference() {
        let receiving = Identity::receiving(mechanism::mutual_tls(), "CN=partner-x.example");
        let sending = Identity::sending(
            mechanism::ssh_key(),
            "SHA256:abc",
            CredentialRef::new("ssh-agent", "xmip-outbound"),
        );

        // Nothing secret is kept for the receive side, because matching an
        // arriving credential against a name needs no secret.
        assert!(receiving.credential.is_none());
        assert!(!receiving.purpose.needs_credential());
        assert_eq!(
            sending.credential.as_ref().map(ToString::to_string),
            Some("ssh-agent:xmip-outbound".to_string())
        );
    }

    #[test]
    fn what_a_process_runs_as_decides_its_host_process() {
        // ADR-0022 clause 3. Two Processes under different service accounts
        // cannot share a host process, because a process holds tickets and
        // session keys and the operating system is the only thing enforcing
        // the boundary.
        let one = Identity::processing(
            mechanism::kerberos(),
            "svc-orders@CORP.EXAMPLE",
            CredentialRef::new("windows-credential-manager", "svc-orders"),
        );
        let other = Identity::processing(
            mechanism::kerberos(),
            "svc-billing@CORP.EXAMPLE",
            CredentialRef::new("windows-credential-manager", "svc-billing"),
        );

        let one = one.context().expect("a process runs as something");
        let other = other.context().expect("a process runs as something");

        assert!(!one.may_share_host_process(&other));
    }

    #[test]
    fn a_receive_matcher_isolates_nothing_because_it_holds_nothing() {
        let matcher = Identity::receiving(mechanism::mutual_tls(), "CN=partner-x.example");

        assert!(matcher.context().is_none());
    }

    #[test]
    fn an_operator_is_a_party_recognised_the_same_way_as_any_other() {
        // A person driving the CLI, the PowerShell module or either GUI. The
        // passkey exists for exactly this population.
        let operator = Identity::operating(mechanism::passkey(), "ilian@consid.se");

        assert_eq!(operator.purpose, Purpose::Operate);
        assert!(!operator.purpose.needs_credential());
        assert!(operator.credential.is_none());
        assert!(operator.context().is_none());
    }
}
