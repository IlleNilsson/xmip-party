//! What a Party is recognised by, what it presents, and what may run beside
//! what.
//!
//! Three accepted decisions meet here. ADR-0019 makes the Party the identity
//! holder in both directions. ADR-0022 classifies every identity by how it is
//! proven and forbids two identity contexts from sharing a host process.
//! ADR-0009 keeps roles out of it: a Party is recognised, a role is granted.
//!
//! The mechanism table below is sorted against
//! `xmip-core-authenticate/docs/identity-by-technology.md`, and every name is
//! the last segment of the repository that implements it, so
//! `Mechanism::name()` and `xmip-core-authenticate-<name>` cannot drift apart.

use std::collections::BTreeMap;
use std::fmt;

/// What an identity is configured for.
///
/// A Party's identities are per purpose because they genuinely differ, and they
/// differ in kind rather than only in value. Two of the four match something
/// arriving and need no secret; two produce proof and name where the material
/// is kept. ADR-0019 clause 4.
///
/// ```text
/// Receive    a partner arrives          matcher
/// Operate    a person drives Xmip       matcher
/// Process    Xmip runs as somebody      credential
/// Send       Xmip is the client         credential
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Purpose {
    /// Verified when it arrives. A Receive Location names the Parties it takes,
    /// and an arriving credential is compared against a stored matcher.
    Receive,
    /// What a Process runs as.
    ///
    /// The consequential one. ADR-0022 clause 3 gives a host process the work
    /// of exactly one identity context, so this identity is not only what the
    /// Process acts as — it decides which host process the Process can be
    /// placed in, and therefore how many host processes a node runs.
    Process,
    /// Offered when Xmip is the client. ADR-0006 resolves which one, inheriting
    /// up through Send Port and Send Port Group to the Sending Process.
    Send,
    /// Who is driving Xmip itself.
    ///
    /// The CLI, the PowerShell module, the MAUI desktop GUI and the Blazor web
    /// GUI all authenticate somebody, and that somebody is a Party like any
    /// other — a person rather than a trading partner, but recognised the same
    /// way. ADR-0014.
    ///
    /// Matched, not presented: the operator proves themselves to Xmip, so this
    /// stores a matcher and no secret, exactly as [`Purpose::Receive`] does.
    ///
    /// ADR-0009 still applies. Recognising an operator is not granting them
    /// anything; a Party is recognised, a role is granted.
    Operate,
}

impl Purpose {
    /// Whether this purpose requires credential material rather than a matcher.
    ///
    /// Receiving and operating both compare an arriving credential against a
    /// stored name and need no secret. Processing and sending mean producing
    /// proof, so both name where the material is kept.
    #[must_use]
    pub const fn needs_credential(self) -> bool {
        matches!(self, Self::Process | Self::Send)
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Receive => "receive",
            Self::Process => "process",
            Self::Send => "send",
            Self::Operate => "operate",
        })
    }
}

/// Where an identity travels.
///
/// The line, from ADR-0019 clause 5, needs no other concept: anything Xmip can
/// read *before* Message creation is transport, anything requiring the Message
/// to exist is message.
///
/// RFC 9421 HTTP Message Signatures is the case that proves the rule is about
/// readability rather than about what is proven. It signs selected headers and
/// the body — so what it proves is content integrity — but it is read before
/// Message creation, and Xmip therefore treats it as transport.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Layer {
    /// Who opened the connection.
    Transport,
    /// On whose behalf the content was produced.
    Message,
}

/// How an identity is proven. ADR-0022 clause 1.
///
/// A property of the proof, not of who holds it and not of how much it is
/// trusted. A Party may hold identities in several classes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IdentityClass {
    /// Cryptographic proof bound to a named principal.
    HighAssurance,
    /// Asserted by a trusted third party.
    Federated,
    /// A secret both sides hold.
    SharedSecret,
    /// No identity is claimed. A context like any other, and the cheapest to
    /// isolate — also the one most likely to be reached by an attacker.
    Anonymous,
}

impl fmt::Display for IdentityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HighAssurance => "highAssurance",
            Self::Federated => "federated",
            Self::SharedSecret => "sharedSecret",
            Self::Anonymous => "anonymous",
        })
    }
}

/// Whether a mechanism can settle the second gate, or only the first.
///
/// ADR-0019 clause 2 orders the gates: identity, then authentication, then
/// authorization. Most of the estate does both boxes at once — a client
/// certificate names a Party *and* proves it. Some mechanisms only ever do the
/// first.
///
/// X12's ISA06 and EDIFACT's UNB S002 name the counterparty and carry no
/// cryptography whatever. `identity-by-technology.md` calls treating them as
/// authentication "the classic B2B mistake": they are enough to route and bill
/// a Journey, and proving the claim is the transport's job, or AS2's. HL7's
/// MSH-3 is the same shape in healthcare, and MLLP gives it nothing to lean on.
///
/// **This is what the protocol provides, not a choice Xmip makes.** X12 was
/// standardised without cryptography and HL7 v2 travels over a framing protocol
/// with no security whatever. Xmip covers them because they are most of the
/// installed base, and it covers them honestly — recording that a name was
/// claimed rather than that a claim was proven.
///
/// This value does not gate anything on its own. Every arrival is authenticated
/// and authorized at runtime regardless, and authorization is where "may a
/// Party recognised only by an ISA06 send this contract on this Path" is
/// answered. The distinction exists so that question has something true to read.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Assurance {
    /// Names a Party. Proves nothing.
    Identifies,
    /// Names a Party and proves the claim.
    Authenticates,
}

/// A way of proving identity, and the three facts that follow from it.
///
/// **None of `class`, `layer` or `assurance` is configurable.** ADR-0022
/// clause 1: an operator who could declare an API key `highAssurance` would
/// have declared away the only thing the classification is for. ADR-0019
/// clause 5 says the same of the layer — feasibility is a property of the
/// technology, and a file dropped in a folder carries no transport credential
/// however the TOML reads.
///
/// A mechanism is declared by the module that implements it, through
/// [`Mechanism::declare`], and is never built from configuration.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Mechanism {
    name: String,
    class: IdentityClass,
    layer: Layer,
    assurance: Assurance,
}

impl Mechanism {
    /// Declared by the module that implements the mechanism.
    ///
    /// Not reachable from TOML, which is the point. A provider adding
    /// `xmip-acme-authenticate-scim` states its own class, layer and assurance
    /// because it is the only code that knows them; an operator deploying it
    /// does not get to disagree.
    #[must_use]
    pub fn declare(
        name: impl Into<String>,
        class: IdentityClass,
        layer: Layer,
        assurance: Assurance,
    ) -> Self {
        Self {
            name: name.into(),
            class,
            layer,
            assurance,
        }
    }

    /// The last segment of the repository that implements it —
    /// `xmip-core-authenticate-<name>`, or `xmip-core-identify-<name>`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn class(&self) -> IdentityClass {
        self.class
    }

    #[must_use]
    pub const fn layer(&self) -> Layer {
        self.layer
    }

    #[must_use]
    pub const fn assurance(&self) -> Assurance {
        self.assurance
    }

    /// Whether this mechanism can settle the authentication gate on its own.
    #[must_use]
    pub const fn authenticates(&self) -> bool {
        matches!(self.assurance, Assurance::Authenticates)
    }
}

/// The mechanisms Xmip itself implements, sorted as
/// `identity-by-technology.md` sorts them.
///
/// Here so that `mutual-tls` means the same thing in every module rather than
/// being re-declared, differently, in each one.
pub mod mechanism {
    use super::{Assurance::*, IdentityClass::*, Layer::*, Mechanism};

    // -- Transport: cryptographic proof bound to a principal ---------------

    /// RFC 8446. The channel proves the client.
    #[must_use]
    pub fn mutual_tls() -> Mechanism {
        Mechanism::declare("mutual-tls", HighAssurance, Transport, Authenticates)
    }

    /// RFC 4559 Negotiate/SPNEGO, and GSSAPI over SFTP, NFS, Kafka and
    /// PostgreSQL. One mechanism, many carriers.
    #[must_use]
    pub fn kerberos() -> Mechanism {
        Mechanism::declare("kerberos", HighAssurance, Transport, Authenticates)
    }

    /// An X.509 certificate outside a TLS handshake — S/MIME in AS2, an Oracle
    /// wallet, an OPC UA application instance certificate.
    #[must_use]
    pub fn certificate() -> Mechanism {
        Mechanism::declare("certificate", HighAssurance, Transport, Authenticates)
    }

    /// SSH-2 public key. RFC 4252.
    #[must_use]
    pub fn ssh_key() -> Mechanism {
        Mechanism::declare("ssh-key", HighAssurance, Transport, Authenticates)
    }

    /// WebAuthn and FIDO2. A key pair bound to a principal and to an origin,
    /// with the private half unable to leave its authenticator.
    ///
    /// Absent from `identity-by-technology.md`, which sorted the integration
    /// estate rather than the operator surfaces. It reaches Xmip through the
    /// GUIs rather than through a transport.
    #[must_use]
    pub fn passkey() -> Mechanism {
        Mechanism::declare("passkey", HighAssurance, Transport, Authenticates)
    }

    /// `SO_PEERCRED` on a Unix socket, the caller SID on a named pipe.
    ///
    /// The kernel vouches for it and it is never presented at all, which makes
    /// it stronger than most credentials and unlike all of them.
    #[must_use]
    pub fn peer_credentials() -> Mechanism {
        Mechanism::declare("peer-credentials", HighAssurance, Transport, Authenticates)
    }

    /// RFC 9421 HTTP Message Signatures. Signs selected headers and the body,
    /// and is still transport: it is readable before Message creation.
    #[must_use]
    pub fn http_message_signature() -> Mechanism {
        Mechanism::declare(
            "http-message-signature",
            HighAssurance,
            Transport,
            Authenticates,
        )
    }

    // -- Transport: asserted by a third party -------------------------------

    /// RFC 6749.
    #[must_use]
    pub fn oauth2() -> Mechanism {
        Mechanism::declare("oauth2", Federated, Transport, Authenticates)
    }

    /// OIDC Core 1.0.
    #[must_use]
    pub fn oidc() -> Mechanism {
        Mechanism::declare("oidc", Federated, Transport, Authenticates)
    }

    // -- Transport: a secret both sides hold --------------------------------

    /// RFC 7617.
    #[must_use]
    pub fn basic() -> Mechanism {
        Mechanism::declare("basic", SharedSecret, Transport, Authenticates)
    }

    /// RFC 7616.
    #[must_use]
    pub fn digest() -> Mechanism {
        Mechanism::declare("digest", SharedSecret, Transport, Authenticates)
    }

    /// RFC 6750 — carriage, not issuance.
    ///
    /// `sharedSecret` rather than `federated` on purpose. A bearer token by
    /// itself proves possession and nothing else; whether an issuer stands
    /// behind it is a fact about [`oauth2`] or [`oidc`], which are separate
    /// mechanisms for exactly that reason.
    #[must_use]
    pub fn bearer() -> Mechanism {
        Mechanism::declare("bearer", SharedSecret, Transport, Authenticates)
    }

    /// No standard. Vendor convention, universally.
    #[must_use]
    pub fn api_key() -> Mechanism {
        Mechanism::declare("api-key", SharedSecret, Transport, Authenticates)
    }

    /// RFC 5802. Kafka, PostgreSQL, MySQL `caching_sha2_password`.
    #[must_use]
    pub fn scram() -> Mechanism {
        Mechanism::declare("scram", SharedSecret, Transport, Authenticates)
    }

    /// Username and password over a protected channel — FTPS, SASL PLAIN,
    /// a SQL login.
    #[must_use]
    pub fn password() -> Mechanism {
        Mechanism::declare("password", SharedSecret, Transport, Authenticates)
    }

    /// AWS Signature Version 4.
    #[must_use]
    pub fn sigv4() -> Mechanism {
        Mechanism::declare("sigv4", SharedSecret, Transport, Authenticates)
    }

    /// Azure Shared Key and SAS tokens.
    #[must_use]
    pub fn shared_access_signature() -> Mechanism {
        Mechanism::declare(
            "shared-access-signature",
            SharedSecret,
            Transport,
            Authenticates,
        )
    }

    /// The path, the permissions and the source address of a drop folder.
    ///
    /// ADR-0019 clause 7: a partner drop folder is not an absence of identity.
    /// The circumstance *is* the transport identity, and it is authenticated as
    /// that — weakly, and on the record.
    #[must_use]
    pub fn circumstance() -> Mechanism {
        Mechanism::declare("circumstance", SharedSecret, Transport, Authenticates)
    }

    // -- Transport: nothing claimed -----------------------------------------

    /// ADR-0019 clause 2: an authenticated outcome, not a skipped gate. The
    /// claim is "nobody", it is verified as such, and authorization then
    /// decides whether nobody may post here.
    #[must_use]
    pub fn anonymous() -> Mechanism {
        Mechanism::declare("anonymous", Anonymous, Transport, Authenticates)
    }

    // -- Message: proof inside the payload -----------------------------------

    /// OASIS WSS 1.1 — UsernameToken, X.509 and SAML token profiles.
    #[must_use]
    pub fn ws_security() -> Mechanism {
        Mechanism::declare("ws-security", HighAssurance, Message, Authenticates)
    }

    /// RFC 7515 JWS, and RFC 7519 JWT inside a payload.
    #[must_use]
    pub fn jws() -> Mechanism {
        Mechanism::declare("jws", HighAssurance, Message, Authenticates)
    }

    /// W3C XMLDSIG, RFC 3275.
    #[must_use]
    pub fn xml_signature() -> Mechanism {
        Mechanism::declare("xml-signature", HighAssurance, Message, Authenticates)
    }

    /// RFC 8551. The sender half of AS2.
    #[must_use]
    pub fn s_mime() -> Mechanism {
        Mechanism::declare("s-mime", HighAssurance, Message, Authenticates)
    }

    /// RFC 6376. Proves the message was signed by the claimed domain and is
    /// unaltered.
    #[must_use]
    pub fn dkim() -> Mechanism {
        Mechanism::declare("dkim", HighAssurance, Message, Authenticates)
    }

    /// ISO 9735-5/6/7 AUTACK. EDIFACT with cryptography actually applied.
    #[must_use]
    pub fn autack() -> Mechanism {
        Mechanism::declare("autack", HighAssurance, Message, Authenticates)
    }

    // -- Message: a name, and nothing behind it ------------------------------

    /// X12 ISA05–ISA08. **Identifies. Does not authenticate.**
    ///
    /// Enough to route and bill a Journey. Proving it is the transport's job,
    /// or AS2's.
    #[must_use]
    pub fn edi_x12_interchange() -> Mechanism {
        Mechanism::declare("edi-x12-interchange", SharedSecret, Message, Identifies)
    }

    /// EDIFACT UNB S002 and S003. **Identifies. Does not authenticate.**
    #[must_use]
    pub fn edifact_interchange() -> Mechanism {
        Mechanism::declare("edifact-interchange", SharedSecret, Message, Identifies)
    }

    /// HL7 v2.x MSH-3 and MSH-4. **Identifies. Does not authenticate.**
    ///
    /// MLLP is a framing protocol with no security whatever, carrying
    /// healthcare data, so for most HL7 deployments this is the only identity
    /// present anywhere.
    #[must_use]
    pub fn hl7_sending_application() -> Mechanism {
        Mechanism::declare(
            "hl7-sending-application",
            SharedSecret,
            Message,
            Identifies,
        )
    }
}

/// The material a presented identity is proven with.
///
/// A reference, never the secret. ADR-0019 clause 4 makes the Party the
/// identity holder and explicitly not a credential store: the secret lives in
/// whatever the deployment uses — a certificate store, a key vault, an SSH
/// agent, a TPM — and Xmip carries the name of it.
///
/// A Party that held the bytes would put every partner secret in every
/// configuration export, every backup and every support bundle.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialRef {
    /// Which store — `windows-certificate-store`, `azure-key-vault`,
    /// `ssh-agent`, `file`, `environment`.
    pub store: String,
    /// The name within that store.
    pub reference: String,
}

impl CredentialRef {
    #[must_use]
    pub fn new(store: impl Into<String>, reference: impl Into<String>) -> Self {
        Self {
            store: store.into(),
            reference: reference.into(),
        }
    }
}

impl fmt::Display for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.store, self.reference)
    }
}

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

/// The full set of facts under which a credential operates. ADR-0022 clause 2.
///
/// Two credentials share a context only when **every** fact matches, which is
/// why this compares structurally rather than by principal name.
///
/// The case that decides the shape: constrained and unconstrained Kerberos
/// delegation are distinct contexts even for the same principal, because
/// unconstrained delegation makes a ticket usable against services the
/// constrained case cannot reach. Treating them as one because the account name
/// matches is the specific mistake this exists to prevent.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityContext {
    mechanism: String,
    class: IdentityClass,
    facts: BTreeMap<String, String>,
}

impl IdentityContext {
    #[must_use]
    pub fn new(mechanism: &Mechanism) -> Self {
        Self {
            mechanism: mechanism.name().to_string(),
            class: mechanism.class(),
            facts: BTreeMap::new(),
        }
    }

    /// Add a fact. A later value for the same key replaces an earlier one.
    #[must_use]
    pub fn with(mut self, fact: impl Into<String>, value: impl Into<String>) -> Self {
        self.facts.insert(fact.into(), value.into());
        self
    }

    #[must_use]
    pub fn mechanism(&self) -> &str {
        &self.mechanism
    }

    #[must_use]
    pub const fn class(&self) -> IdentityClass {
        self.class
    }

    #[must_use]
    pub fn fact(&self, name: &str) -> Option<&str> {
        self.facts.get(name).map(String::as_str)
    }

    /// Whether these two may run in one host process. ADR-0022 clause 3.
    ///
    /// A host process runs the work of one identity context, because a process
    /// holds tickets, tokens, session keys and connection handles, and process
    /// isolation is the boundary the operating system actually enforces.
    /// Anything finer is a promise made by whatever code happens to be running
    /// — and Xmip loads third-party Modules across a C ABI, so that is not
    /// hypothetical.
    #[must_use]
    pub fn may_share_host_process(&self, other: &Self) -> bool {
        self == other
    }
}

impl fmt::Display for IdentityContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", self.mechanism, self.class)?;

        for (fact, value) in &self.facts {
            write!(f, " {fact}={value}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kerberos(delegation: &str) -> IdentityContext {
        IdentityContext::new(&mechanism::kerberos())
            .with("realm", "CORP.EXAMPLE")
            .with("principal", "xmip/node-a.corp.example")
            .with("delegation-scope", delegation)
    }

    #[test]
    fn delegation_scope_separates_one_principal_into_two_contexts() {
        // The mistake ADR-0022 clause 2 exists to prevent. Same realm, same
        // principal, and a ticket that reaches services the other cannot.
        assert_ne!(kerberos("unconstrained"), kerberos("constrained"));
        assert!(!kerberos("unconstrained").may_share_host_process(&kerberos("constrained")));
    }

    #[test]
    fn identical_facts_are_one_context() {
        assert!(kerberos("constrained").may_share_host_process(&kerberos("constrained")));
    }

    #[test]
    fn anonymous_does_not_share_with_authenticated_work() {
        let open = IdentityContext::new(&mechanism::anonymous());
        let keyed = IdentityContext::new(&mechanism::api_key()).with("key-id", "partner-x");

        assert!(!open.may_share_host_process(&keyed));
    }

    #[test]
    fn class_and_layer_come_from_the_mechanism_not_from_configuration() {
        assert_eq!(mechanism::mutual_tls().class(), IdentityClass::HighAssurance);

        // An API key is a shared secret however anyone would prefer to
        // describe it, and there is no setter to argue with.
        assert_eq!(mechanism::api_key().class(), IdentityClass::SharedSecret);
    }

    #[test]
    fn a_bearer_token_proves_possession_and_not_an_issuer() {
        // RFC 6750 is carriage. Whether an issuer stands behind the token is a
        // fact about oauth2 or oidc, which is why those are separate.
        assert_eq!(mechanism::bearer().class(), IdentityClass::SharedSecret);
        assert_eq!(mechanism::oauth2().class(), IdentityClass::Federated);
    }

    #[test]
    fn a_signed_http_request_is_still_transport() {
        // RFC 9421 signs the body, so what it proves is content integrity. It
        // is read before Message creation, so the layer is transport anyway.
        let signed = mechanism::http_message_signature();

        assert_eq!(signed.layer(), Layer::Transport);
        assert_eq!(signed.class(), IdentityClass::HighAssurance);
    }

    #[test]
    fn edi_interchange_identifiers_name_a_party_and_prove_nothing() {
        // The classic B2B mistake, refused at the type level.
        for claim in [
            mechanism::edi_x12_interchange(),
            mechanism::edifact_interchange(),
            mechanism::hl7_sending_application(),
        ] {
            assert!(
                !claim.authenticates(),
                "{} carries no cryptography",
                claim.name()
            );
        }

        // AUTACK is EDIFACT with the cryptography actually applied, and does.
        assert!(mechanism::autack().authenticates());
    }

    #[test]
    fn a_drop_folder_is_an_identity_rather_than_the_absence_of_one() {
        let folder = mechanism::circumstance();

        assert_eq!(folder.layer(), Layer::Transport);
        assert_ne!(folder.class(), IdentityClass::Anonymous);
        assert!(folder.authenticates());
    }

    #[test]
    fn a_kernel_vouched_identity_is_never_presented_and_still_proves_most() {
        assert_eq!(
            mechanism::peer_credentials().class(),
            IdentityClass::HighAssurance
        );
    }

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

    #[test]
    fn a_context_reads_as_something_an_operator_can_act_on() {
        // The failure in ADR-0022 clause 5 must name both contexts. That is
        // only useful if a context prints as more than a type name.
        assert_eq!(
            kerberos("constrained").to_string(),
            "kerberos[highAssurance] delegation-scope=constrained principal=xmip/node-a.corp.example realm=CORP.EXAMPLE"
        );
    }
}
