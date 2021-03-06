//! *Pure-Rust X.509 certificate serialization*
//!
//! `x509` is a crate providing serialization APIs for X.509 v3 ([RFC 5280]) certificates,
//! implemented using the `cookie-factory` combinatorial serializer framework.
//!
//! [RFC 5280]: https://tools.ietf.org/html/rfc5280

use cookie_factory::{GenResult, WriteContext};
use std::io::Write;

pub mod der;

/// A trait for objects which represent ASN.1 `AlgorithmIdentifier`s.
pub trait AlgorithmIdentifier {
    type AlgorithmOid: der::Oid;

    /// Returns the object identifier for this `AlgorithmIdentifier`.
    fn algorithm(&self) -> Self::AlgorithmOid;

    /// Writes the parameters for this `AlgorithmIdentifier`, if any.
    fn parameters<W: Write>(&self, w: WriteContext<W>) -> GenResult<W>;
}

/// A trait for objects which represent ASN.1 `SubjectPublicKeyInfo`s.
pub trait SubjectPublicKeyInfo {
    type AlgorithmId: AlgorithmIdentifier;
    type SubjectPublicKey: AsRef<[u8]>;

    /// Returns the [`AlgorithmIdentifier`] for this public key.
    fn algorithm_id(&self) -> Self::AlgorithmId;

    /// Returns the encoded public key.
    fn public_key(&self) -> Self::SubjectPublicKey;
}

#[derive(Clone)]
enum RdnType {
    Country,
    Organization,
    OrganizationalUnit,
    CommonName,
}

/// An X.509 RelativeDistinguishedName.
#[derive(Clone)]
pub struct RelativeDistinguishedName<'a> {
    typ: RdnType,
    value: &'a str,
}

impl<'a> RelativeDistinguishedName<'a> {
    /// Constructs a Country RDN.
    ///
    /// # Panics
    /// Panics if `value.len() > 64`.
    pub fn country(value: &'a str) -> Self {
        assert!(value.len() <= 64);

        RelativeDistinguishedName {
            typ: RdnType::Country,
            value,
        }
    }

    /// Constructs an Organization RDN.
    ///
    /// # Panics
    /// Panics if `value.len() > 64`.
    pub fn organization(value: &'a str) -> Self {
        assert!(value.len() <= 64);

        RelativeDistinguishedName {
            typ: RdnType::Organization,
            value,
        }
    }

    /// Constructs an OrganizationalUnit RDN.
    ///
    /// # Panics
    /// Panics if `value.len() > 64`.
    pub fn organizational_unit(value: &'a str) -> Self {
        assert!(value.len() <= 64);

        RelativeDistinguishedName {
            typ: RdnType::OrganizationalUnit,
            value,
        }
    }

    /// Constructs a CommonName RDN.
    ///
    /// # Panics
    /// Panics if `value.len() > 64`.
    pub fn common_name(value: &'a str) -> Self {
        assert!(value.len() <= 64);

        RelativeDistinguishedName {
            typ: RdnType::CommonName,
            value,
        }
    }
}

/// A certificate extension.
pub struct Extension<'a, O: der::Oid + 'a> {
    /// An OID that specifies the format and definitions of the extension.
    oid: O,
    /// Whether the information in the extension is important.
    ///
    /// ```text
    /// Each extension in a certificate may be designated as critical or non-critical. A
    /// certificate using system MUST reject the certificate if it encounters a critical
    /// extension it does not recognize; however, a non-critical extension may be ignored
    /// if it is not recognized.
    /// ```
    critical: bool,
    /// The DER encoding of an ASN.1 value corresponding to the extension type identified
    /// by `oid`.
    value: &'a [u8],
}

impl<'a, O: der::Oid + 'a> Extension<'a, O> {
    /// Constructs an extension.
    ///
    /// If this extension is not recognized by a certificate-using system, it will be
    /// ignored.
    ///
    /// `oid` is an OID that specifies the format and definitions of the extension.
    ///
    /// `value` is the DER encoding of an ASN.1 value corresponding to the extension type
    /// identified by `oid`.
    pub fn regular(oid: O, value: &'a [u8]) -> Self {
        Extension {
            oid,
            critical: false,
            value,
        }
    }

    /// Constructs a critical extension.
    ///
    /// If this extension is not recognized by a certificate-using system, the certificate
    /// will be rejected.
    ///
    /// `oid` is an OID that specifies the format and definitions of the extension.
    ///
    /// `value` is the DER encoding of an ASN.1 value corresponding to the extension type
    /// identified by `oid`.
    pub fn critical(oid: O, value: &'a [u8]) -> Self {
        Extension {
            oid,
            critical: true,
            value,
        }
    }
}

/// X.509 serialization APIs.
pub mod write {
    use chrono::{DateTime, Datelike, TimeZone, Utc};
    use cookie_factory::{
        combinator::{cond, slice},
        multi::all,
        sequence::pair,
        SerializeFn, WriteContext,
    };
    use std::io::Write;

    use crate::{Extension, RdnType, RelativeDistinguishedName};

    use super::{
        der::{write::*, Oid},
        AlgorithmIdentifier, SubjectPublicKeyInfo,
    };

    /// X.509 versions that we care about.
    #[derive(Clone, Copy)]
    enum Version {
        V3,
    }

    impl From<Version> for usize {
        fn from(version: Version) -> usize {
            match version {
                Version::V3 => 2,
            }
        }
    }

    /// Object identifiers used internally by X.509.
    enum InternalOid {
        Country,
        Organization,
        OrganizationalUnit,
        CommonName,
    }

    impl AsRef<[u64]> for InternalOid {
        fn as_ref(&self) -> &[u64] {
            match self {
                InternalOid::Country => &[2, 5, 4, 6],
                InternalOid::Organization => &[2, 5, 4, 10],
                InternalOid::OrganizationalUnit => &[2, 5, 4, 11],
                InternalOid::CommonName => &[2, 5, 4, 3],
            }
        }
    }

    impl Oid for InternalOid {}

    impl<'a> RelativeDistinguishedName<'a> {
        fn oid(&self) -> InternalOid {
            match self.typ {
                RdnType::Country => InternalOid::Country,
                RdnType::CommonName => InternalOid::CommonName,
                RdnType::Organization => InternalOid::Organization,
                RdnType::OrganizationalUnit => InternalOid::OrganizationalUnit,
            }
        }
    }

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// TBSCertificate  ::=  SEQUENCE  {
    ///      version         [0]  EXPLICIT Version DEFAULT v1,
    ///      ...
    ///      }
    ///
    /// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    /// ```
    fn version<W: Write>(version: Version) -> impl SerializeFn<W> {
        // TODO: Omit version if V1, once x509-parser correctly handles this.
        der_explicit(0, der_integer_usize(version.into()))
    }

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1.1.2):
    /// ```text
    /// AlgorithmIdentifier  ::=  SEQUENCE  {
    ///      algorithm               OBJECT IDENTIFIER,
    ///      parameters              ANY DEFINED BY algorithm OPTIONAL  }
    /// ```
    pub fn algorithm_identifier<'a, W: Write + 'a, Alg: AlgorithmIdentifier>(
        algorithm_id: &'a Alg,
    ) -> impl SerializeFn<W> + 'a {
        der_sequence((
            der_oid(algorithm_id.algorithm()),
            move |w: WriteContext<Vec<u8>>| algorithm_id.parameters(w),
        ))
    }

    /// Encodes an X.509 RelativeDistinguishedName.
    ///
    /// From [RFC 5280 section 4.1.2.4](https://tools.ietf.org/html/rfc5280#section-4.1.2.4):
    /// ```text
    /// RelativeDistinguishedName ::=
    ///   SET SIZE (1..MAX) OF AttributeTypeAndValue
    ///
    /// AttributeTypeAndValue ::= SEQUENCE {
    ///   type     AttributeType,
    ///   value    AttributeValue }
    ///
    /// AttributeType ::= OBJECT IDENTIFIER
    ///
    /// AttributeValue ::= ANY -- DEFINED BY AttributeType
    /// ```
    ///
    /// From [RFC 5280 appendix A.1](https://tools.ietf.org/html/rfc5280#appendix-A.1):
    /// ```text
    /// X520CommonName ::= CHOICE {
    ///      teletexString     TeletexString   (SIZE (1..ub-common-name)),
    ///      printableString   PrintableString (SIZE (1..ub-common-name)),
    ///      universalString   UniversalString (SIZE (1..ub-common-name)),
    ///      utf8String        UTF8String      (SIZE (1..ub-common-name)),
    ///      bmpString         BMPString       (SIZE (1..ub-common-name)) }
    ///
    /// ub-common-name INTEGER ::= 64
    /// ```
    fn relative_distinguished_name<'a, W: Write + 'a>(
        rdn: &'a RelativeDistinguishedName<'a>,
    ) -> impl SerializeFn<W> + 'a {
        der_set((der_sequence((
            der_oid(rdn.oid()),
            der_utf8_string(&rdn.value),
        )),))
    }

    /// Encodes an X.509 Name.
    ///
    /// From [RFC 5280 section 4.1.2.4](https://tools.ietf.org/html/rfc5280#section-4.1.2.4):
    /// ```text
    /// Name ::= CHOICE { -- only one possibility for now --
    ///   rdnSequence  RDNSequence }
    ///
    /// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    /// ```
    fn name<'a, W: Write + 'a>(
        name: &'a [RelativeDistinguishedName<'a>],
    ) -> impl SerializeFn<W> + 'a {
        der_sequence((all(name.iter().map(relative_distinguished_name)),))
    }

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// Time ::= CHOICE {
    ///      utcTime        UTCTime,
    ///      generalTime    GeneralizedTime }
    ///
    /// CAs conforming to this profile MUST always encode certificate
    /// validity dates through the year 2049 as UTCTime; certificate validity
    /// dates in 2050 or later MUST be encoded as GeneralizedTime.
    /// ```
    fn time<W: Write>(t: DateTime<Utc>) -> impl SerializeFn<W> {
        pair(
            cond(t.year() < 2050, der_utc_time(t)),
            cond(t.year() >= 2050, der_generalized_time(t)),
        )
    }

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// Validity ::= SEQUENCE {
    ///      notBefore      Time,
    ///      notAfter       Time }
    ///
    /// To indicate that a certificate has no well-defined expiration date,
    /// the notAfter SHOULD be assigned the GeneralizedTime value of
    /// 99991231235959Z.
    /// ```
    fn validity<W: Write>(
        not_before: DateTime<Utc>,
        not_after: Option<DateTime<Utc>>,
    ) -> impl SerializeFn<W> {
        der_sequence((
            time(not_before),
            time(not_after.unwrap_or_else(|| Utc.ymd(9999, 12, 31).and_hms(23, 59, 59))),
        ))
    }

    /// Encodes a `PublicKeyInfo` as an ASN.1 `SubjectPublicKeyInfo` using DER.
    ///
    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
    ///      algorithm            AlgorithmIdentifier,
    ///      subjectPublicKey     BIT STRING  }
    /// ```
    fn subject_public_key_info<'a, W: Write + 'a, PKI: SubjectPublicKeyInfo>(
        subject_pki: &'a PKI,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            der_sequence((
                algorithm_identifier(&subject_pki.algorithm_id()),
                der_bit_string(subject_pki.public_key().as_ref()),
            ))(w)
        }
    }

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// Extension  ::=  SEQUENCE  {
    ///      extnID      OBJECT IDENTIFIER,
    ///      critical    BOOLEAN DEFAULT FALSE,
    ///      extnValue   OCTET STRING
    ///                  -- contains the DER encoding of an ASN.1 value
    ///                  -- corresponding to the extension type identified
    ///                  -- by extnID
    ///      }
    /// ```
    fn extension<'a, W: Write + 'a, O: Oid + 'a>(
        extension: &'a Extension<'a, O>,
    ) -> impl SerializeFn<W> + 'a {
        der_sequence((
            der_oid(&extension.oid),
            der_default(der_boolean, extension.critical, false),
            der_octet_string(extension.value),
        ))
    }

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// TBSCertificate  ::=  SEQUENCE  {
    ///      ...
    ///      extensions      [3]  EXPLICIT Extensions OPTIONAL
    ///                           -- If present, version MUST be v3
    ///      }
    ///
    /// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
    /// ```
    fn extensions<'a, W: Write + 'a, O: Oid + 'a>(
        exts: &'a [Extension<'a, O>],
    ) -> impl SerializeFn<W> + 'a {
        cond(
            !exts.is_empty(),
            der_explicit(3, der_sequence((all(exts.iter().map(extension)),))),
        )
    }

    /// Encodes a version 1 X.509 `TBSCertificate` using DER.
    ///
    /// `extensions` is optional; if empty, no extensions section will be serialized. Due
    /// to the need for an `O: Oid` type parameter, users who do not have any extensions
    /// should use the following workaround:
    ///
    /// ```ignore
    /// let exts: &[Extension<'_, &[u64]>] = &[];
    /// x509::write::tbs_certificate(
    ///     serial_number,
    ///     signature,
    ///     issuer,
    ///     not_before,
    ///     not_after,
    ///     subject,
    ///     subject_pki,
    ///     exts,
    /// );
    /// ```
    ///
    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// TBSCertificate  ::=  SEQUENCE  {
    ///      version         [0]  EXPLICIT Version DEFAULT v1,
    ///      serialNumber         CertificateSerialNumber,
    ///      signature            AlgorithmIdentifier,
    ///      issuer               Name,
    ///      validity             Validity,
    ///      subject              Name,
    ///      subjectPublicKeyInfo SubjectPublicKeyInfo,
    ///      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                           -- If present, version MUST be v2 or v3
    ///      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                           -- If present, version MUST be v2 or v3
    ///      extensions      [3]  EXPLICIT Extensions OPTIONAL
    ///                           -- If present, version MUST be v3
    ///      }
    ///
    /// CertificateSerialNumber  ::=  INTEGER
    ///
    /// Certificate users MUST be able to handle serialNumber values up to 20 octets.
    /// Conforming CAs MUST NOT use serialNumber values longer than 20 octets.
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `serial_number.len() > 20`
    pub fn tbs_certificate<'a, W: Write + 'a, Alg, PKI, O: Oid + 'a>(
        serial_number: &'a [u8],
        signature: &'a Alg,
        issuer: &'a [RelativeDistinguishedName<'a>],
        not_before: DateTime<Utc>,
        not_after: Option<DateTime<Utc>>,
        subject: &'a [RelativeDistinguishedName<'a>],
        subject_pki: &'a PKI,
        exts: &'a [Extension<'a, O>],
    ) -> impl SerializeFn<W> + 'a
    where
        Alg: AlgorithmIdentifier,
        PKI: SubjectPublicKeyInfo,
    {
        assert!(serial_number.len() <= 20);

        der_sequence((
            version(Version::V3),
            der_integer(serial_number),
            algorithm_identifier(signature),
            name(issuer),
            validity(not_before, not_after),
            name(subject),
            subject_public_key_info(subject_pki),
            extensions(exts),
        ))
    }

    /// Encodes an X.509 certificate using DER.
    ///
    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// Certificate  ::=  SEQUENCE  {
    ///      tbsCertificate       TBSCertificate,
    ///      signatureAlgorithm   AlgorithmIdentifier,
    ///      signatureValue       BIT STRING  }
    /// ```
    ///
    /// Use [`tbs_certificate`] to serialize the certificate itself, then sign it and call
    /// this function with the serialized `TBSCertificate` and signature.
    pub fn certificate<'a, W: Write + 'a, Alg: AlgorithmIdentifier>(
        cert: &'a [u8],
        signature_algorithm: &'a Alg,
        signature: &'a [u8],
    ) -> impl SerializeFn<W> + 'a {
        der_sequence((
            slice(cert),
            algorithm_identifier(signature_algorithm),
            der_bit_string(signature),
        ))
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::{
        write, AlgorithmIdentifier, Extension, RelativeDistinguishedName, SubjectPublicKeyInfo,
    };

    struct MockAlgorithmId;

    impl AlgorithmIdentifier for MockAlgorithmId {
        type AlgorithmOid = &'static [u64];

        fn algorithm(&self) -> Self::AlgorithmOid {
            &[1, 1, 1, 1]
        }

        fn parameters<W: std::io::Write>(
            &self,
            w: cookie_factory::WriteContext<W>,
        ) -> cookie_factory::GenResult<W> {
            Ok(w)
        }
    }

    struct MockPublicKeyInfo;

    impl SubjectPublicKeyInfo for MockPublicKeyInfo {
        type AlgorithmId = MockAlgorithmId;
        type SubjectPublicKey = Vec<u8>;

        fn algorithm_id(&self) -> Self::AlgorithmId {
            MockAlgorithmId
        }

        fn public_key(&self) -> Self::SubjectPublicKey {
            vec![]
        }
    }

    #[test]
    fn names() {
        const COUNTRY: &str = "NZ";
        const ORGANIZATION: &str = "ACME";
        const ORGANIZATIONAL_UNIT: &str = "Road Runner";
        const COMMON_NAME: &str = "Test-in-a-Box";

        let subject = &[
            RelativeDistinguishedName::country(COUNTRY),
            RelativeDistinguishedName::organization(ORGANIZATION),
            RelativeDistinguishedName::organizational_unit(ORGANIZATIONAL_UNIT),
            RelativeDistinguishedName::common_name(COMMON_NAME),
        ];
        let exts: &[Extension<'_, &[u64]>] = &[];

        let mut tbs_cert = vec![];
        cookie_factory::gen(
            write::tbs_certificate(
                &[],
                &MockAlgorithmId,
                &[],
                Utc::now(),
                None,
                subject,
                &MockPublicKeyInfo,
                exts,
            ),
            &mut tbs_cert,
        )
        .unwrap();

        let mut data = vec![];
        cookie_factory::gen(
            write::certificate(&tbs_cert, &MockAlgorithmId, &[]),
            &mut data,
        )
        .unwrap();

        let (_, cert) = x509_parser::parse_x509_certificate(&data).unwrap();

        assert_eq!(
            cert.subject()
                .iter_country()
                .map(|c| c.as_str())
                .collect::<Result<Vec<_>, _>>(),
            Ok(vec![COUNTRY])
        );
        assert_eq!(
            cert.subject()
                .iter_organization()
                .map(|c| c.as_str())
                .collect::<Result<Vec<_>, _>>(),
            Ok(vec![ORGANIZATION])
        );
        assert_eq!(
            cert.subject()
                .iter_organizational_unit()
                .map(|c| c.as_str())
                .collect::<Result<Vec<_>, _>>(),
            Ok(vec![ORGANIZATIONAL_UNIT])
        );
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .map(|c| c.as_str())
                .collect::<Result<Vec<_>, _>>(),
            Ok(vec![COMMON_NAME])
        );
    }

    #[test]
    fn extensions() {
        let signature = MockAlgorithmId;
        let not_before = Utc::now();
        let subject_pki = MockPublicKeyInfo;
        let exts = &[
            Extension::regular(&[1u64, 2, 3, 4][..], &[1, 2, 3]),
            Extension::critical(&[1u64, 4, 5, 6][..], &[7, 7, 7]),
        ];

        let mut tbs_cert = vec![];
        cookie_factory::gen(
            write::tbs_certificate(
                &[],
                &signature,
                &[],
                not_before,
                None,
                &[],
                &subject_pki,
                exts,
            ),
            &mut tbs_cert,
        )
        .unwrap();

        let mut data = vec![];
        cookie_factory::gen(
            write::certificate(&tbs_cert, &MockAlgorithmId, &[]),
            &mut data,
        )
        .unwrap();

        let (_, cert) = x509_parser::parse_x509_certificate(&data).unwrap();

        assert_eq!(
            cert.validity().not_before.timestamp(),
            not_before.timestamp()
        );

        for ext in exts {
            let oid = x509_parser::der_parser::oid::Oid::from(ext.oid).unwrap();
            if let Some(extension) = cert.extensions().get(&oid) {
                assert_eq!(extension.critical, ext.critical);
                assert_eq!(extension.value, ext.value);
            } else {
                panic!();
            }
        }
    }
}
