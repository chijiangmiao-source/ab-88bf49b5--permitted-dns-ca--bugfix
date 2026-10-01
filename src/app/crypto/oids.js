/**
 * Object identifiers used by the verifier.
 * Only P-256 ECDSA / SHA-256 certificates are accepted, so the set is small.
 */
export const OID = Object.freeze({
  // Algorithm identifiers
  EC_PUBLIC_KEY: '1.2.840.10045.2.1',
  ECDSA_WITH_SHA256: '1.2.840.10045.4.3.2',
  P256: '1.2.840.10045.3.1.7',

  // Extensions
  SUBJECT_KEY_IDENTIFIER: '2.5.29.14',
  KEY_USAGE: '2.5.29.15',
  SUBJECT_ALT_NAME: '2.5.29.17',
  BASIC_CONSTRAINTS: '2.5.29.19',
  NAME_CONSTRAINTS: '2.5.29.30',
  AUTHORITY_KEY_IDENTIFIER: '2.5.29.35',

  // Name attributes
  AT_COMMON_NAME: '2.5.4.3',
  AT_ORGANIZATION: '2.5.4.10',
  AT_ORGANIZATIONAL_UNIT: '2.5.4.11',
  AT_COUNTRY: '2.5.4.6',
  AT_STATE: '2.5.4.8',
  AT_LOCALITY: '2.5.4.7',

  // General name tag numbers (context-specific, primitive/constructed)
  GN_RFC822_NAME: 1,
  GN_DNS_NAME: 2,
  GN_DIRECTORY_NAME: 4,
  GN_IP_ADDRESS: 7,
});

export const ALG_LABEL = Object.freeze({
  [OID.EC_PUBLIC_KEY]: 'ecPublicKey',
  [OID.ECDSA_WITH_SHA256]: 'ecdsa-with-SHA256',
  [OID.P256]: 'prime256v1 (P-256)',
});
