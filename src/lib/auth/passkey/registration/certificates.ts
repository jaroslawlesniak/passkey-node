import { AsnSerializer, id_ce_basicConstraints, AsnParser, BasicConstraints, AuthorityKeyIdentifier, SubjectKeyIdentifier, CRLDistributionPoints, id_ce_authorityKeyIdentifier, id_ce_subjectKeyIdentifier, id_ce_cRLDistributionPoints, CertificateList, Certificate } from '@/lib/asn'
import { mapX509SignatureAlgToCOSEAlg, verifySignature } from '../utils';
import { toBuffer } from '@/lib/base64';
import { CAAuthorityInfo, CertificateInfo, Issuer, ParsedCertInfo, Subject } from '../types';
import { toDataView, toHex } from '@/lib/uint';
import { TPM_ALG, TPM_ST } from './constants';

/**
 * Take a certificate in PEM format and convert it to bytes
 */
export function convertPEMToBytes(pem: string): Uint8Array {
  const certBase64 = pem
    .replace('-----BEGIN CERTIFICATE-----', '')
    .replace('-----END CERTIFICATE-----', '')
    .replace(/[\n ]/g, '');

  return toBuffer(certBase64, 'base64');
}

const cacheRevokedCerts: { [certAuthorityKeyID: string]: CAAuthorityInfo } = {};

/**
 * A method to pull a CRL from a certificate and compare its serial number to the list of revoked
 * certificate serial numbers within the CRL.
 *
 * CRL certificate structure referenced from https://tools.ietf.org/html/rfc5280#page-117
 */
export async function isCertRevoked(cert: Certificate): Promise<boolean> {
  const { extensions } = cert.tbsCertificate;

  if (!extensions) {
    return false;
  }

  let extAuthorityKeyID: AuthorityKeyIdentifier | undefined;
  let extSubjectKeyID: SubjectKeyIdentifier | undefined;
  let extCRLDistributionPoints: CRLDistributionPoints | undefined;

  extensions.forEach((ext) => {
    if (ext.extnID === id_ce_authorityKeyIdentifier) {
      extAuthorityKeyID = AsnParser.parse(
        ext.extnValue,
        AuthorityKeyIdentifier,
      );
    } else if (ext.extnID === id_ce_subjectKeyIdentifier) {
      extSubjectKeyID = AsnParser.parse(ext.extnValue, SubjectKeyIdentifier);
    } else if (ext.extnID === id_ce_cRLDistributionPoints) {
      extCRLDistributionPoints = AsnParser.parse(
        ext.extnValue,
        CRLDistributionPoints,
      );
    }
  });

  // Check to see if we've got cached info for the cert's CA
  let keyIdentifier: string | undefined = undefined;

  if (extAuthorityKeyID && extAuthorityKeyID.keyIdentifier) {
    keyIdentifier = toHex(
      new Uint8Array(extAuthorityKeyID.keyIdentifier.buffer),
    );
  } else if (extSubjectKeyID) {
    /**
     * We might be dealing with a self-signed root certificate. Check the
     * Subject key Identifier extension next.
     */
    keyIdentifier = toHex(new Uint8Array(extSubjectKeyID.buffer));
  }

  const certSerialHex = toHex(
    new Uint8Array(cert.tbsCertificate.serialNumber),
  );

  if (keyIdentifier) {
    const cached = cacheRevokedCerts[keyIdentifier];
    if (cached) {
      const now = new Date();
      // If there's a nextUpdate then make sure we're before it
      if (!cached.nextUpdate || cached.nextUpdate > now) {
        return cached.revokedCerts.indexOf(certSerialHex) >= 0;
      }
    }
  }

  const crlURL = extCRLDistributionPoints?.[0].distributionPoint?.fullName?.[0]
    .uniformResourceIdentifier;

  // If no URL is provided then we have nothing to check
  if (!crlURL) {
    return false;
  }

  // Download and read the CRL
  let certListBytes: ArrayBuffer;
  try {
    const respCRL = await fetch(crlURL);
    certListBytes = await respCRL.arrayBuffer();
  } catch (_err) {
    return false;
  }

  let data: CertificateList;
  try {
    data = AsnParser.parse(certListBytes, CertificateList);
  } catch (_err) {
    // Something was malformed with the CRL, so pass
    return false;
  }

  const newCached: CAAuthorityInfo = {
    revokedCerts: [],
    nextUpdate: undefined,
  };

  // nextUpdate
  if (data.tbsCertList.nextUpdate) {
    newCached.nextUpdate = data.tbsCertList.nextUpdate.getTime();
  }

  // revokedCertificates
  const revokedCerts = data.tbsCertList.revokedCertificates;

  if (revokedCerts) {
    for (const cert of revokedCerts) {
      const revokedHex = toHex(
        new Uint8Array(cert.userCertificate),
      );
      newCached.revokedCerts.push(revokedHex);
    }

    // Cache the results
    if (keyIdentifier) {
      cacheRevokedCerts[keyIdentifier] = newCached;
    }

    return newCached.revokedCerts.indexOf(certSerialHex) >= 0;
  }

  return false;
}

/**
 * Traverse an array of PEM certificates and ensure they form a proper chain
 * @param certificates Typically the result of `x5c.map(convertASN1toPEM)`
 * @param rootCertificates Possible root certificates to complete the path
 */
export async function validateCertificatePath(
  certificates: string[],
  rootCertificates: string[] = [],
): Promise<boolean> {
  if (rootCertificates.length === 0) {
    // We have no root certs with which to create a full path, so skip path validation
    // TODO: Is this going to be acceptable default behavior??
    return true;
  }

  let invalidSubjectAndIssuerError = false;
  let certificateNotYetValidOrExpiredErrorMessage = undefined;
  for (const rootCert of rootCertificates) {
    try {
      const certsWithRoot = certificates.concat([rootCert]);
      await _validatePath(certsWithRoot);
      // If we successfully validated a path then there's no need to continue. Reset any existing
      // errors that were thrown by earlier root certificates
      invalidSubjectAndIssuerError = false;
      certificateNotYetValidOrExpiredErrorMessage = undefined;
      break;
    } catch (err) {
      if (err instanceof InvalidSubjectAndIssuer) {
        invalidSubjectAndIssuerError = true;
      } else if (err instanceof CertificateNotYetValidOrExpired) {
        certificateNotYetValidOrExpiredErrorMessage = err.message;
      } else {
        throw err;
      }
    }
  }

  // We tried multiple root certs and none of them worked
  if (invalidSubjectAndIssuerError) {
    throw new InvalidSubjectAndIssuer();
  } else if (certificateNotYetValidOrExpiredErrorMessage) {
    throw new CertificateNotYetValidOrExpired(
      certificateNotYetValidOrExpiredErrorMessage,
    );
  }

  return true;
}

async function _validatePath(certificates: string[]): Promise<boolean> {
  if (new Set(certificates).size !== certificates.length) {
    throw new Error('Invalid certificate path: found duplicate certificates');
  }

  // From leaf to root, make sure each cert is issued by the next certificate in the chain
  for (let i = 0; i < certificates.length; i += 1) {
    const subjectPem = certificates[i];

    const isLeafCert = i === 0;
    const isRootCert = i + 1 >= certificates.length;

    let issuerPem = '';
    if (isRootCert) {
      issuerPem = subjectPem;
    } else {
      issuerPem = certificates[i + 1];
    }

    const subjectInfo = getCertificateInfo(convertPEMToBytes(subjectPem));
    const issuerInfo = getCertificateInfo(convertPEMToBytes(issuerPem));

    const x509Subject = subjectInfo.parsedCertificate;

    // Check for certificate revocation
    const subjectCertRevoked = await isCertRevoked(x509Subject);

    if (subjectCertRevoked) {
      throw new Error(`Found revoked certificate in certificate path`);
    }

    // Check that intermediate certificate is within its valid time window
    const { notBefore, notAfter } = issuerInfo;

    const now = new Date(Date.now());
    if (notBefore > now || notAfter < now) {
      if (isLeafCert) {
        throw new CertificateNotYetValidOrExpired(
          `Leaf certificate is not yet valid or expired: ${issuerPem}`,
        );
      } else if (isRootCert) {
        throw new CertificateNotYetValidOrExpired(
          `Root certificate is not yet valid or expired: ${issuerPem}`,
        );
      } else {
        throw new CertificateNotYetValidOrExpired(
          `Intermediate certificate is not yet valid or expired: ${issuerPem}`,
        );
      }
    }

    if (subjectInfo.issuer.combined !== issuerInfo.subject.combined) {
      throw new InvalidSubjectAndIssuer();
    }

    // Verify the subject certificate's signature with the issuer cert's public key
    const data = AsnSerializer.serialize(x509Subject.tbsCertificate);
    const signature = x509Subject.signatureValue;
    const signatureAlgorithm = mapX509SignatureAlgToCOSEAlg(
      x509Subject.signatureAlgorithm.algorithm,
    );
    const issuerCertBytes = convertPEMToBytes(issuerPem);

    const verified = await verifySignature({
      data: new Uint8Array(data),
      signature: new Uint8Array(signature),
      x509Certificate: issuerCertBytes,
      hashAlgorithm: signatureAlgorithm,
    });

    if (!verified) {
      throw new Error('Invalid certificate path: invalid signature');
    }
  }

  return true;
}

// Custom errors to help pass on certain errors
class InvalidSubjectAndIssuer extends Error {
  constructor() {
    const message = 'Subject issuer did not match issuer subject';
    super(message);
    this.name = 'InvalidSubjectAndIssuer';
  }
}

class CertificateNotYetValidOrExpired extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CertificateNotYetValidOrExpired';
  }
}

const issuerSubjectIDKey: { [key: string]: 'C' | 'O' | 'OU' | 'CN' } = {
  '2.5.4.6': 'C',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.3': 'CN',
};

/**
 * Extract PEM certificate info
 *
 * @param pemCertificate Result from call to `convertASN1toPEM(x5c[0])`
 */
export function getCertificateInfo(
  leafCertBuffer: Uint8Array,
): CertificateInfo {
  const x509 = AsnParser.parse(leafCertBuffer, Certificate);
  const parsedCert = x509.tbsCertificate;

  // Issuer
  const issuer: Issuer = { combined: '' };
  parsedCert.issuer.forEach(([iss]) => {
    const key = issuerSubjectIDKey[iss.type];
    if (key) {
      issuer[key] = iss.value.toString();
    }
  });
  issuer.combined = issuerSubjectToString(issuer);

  // Subject
  const subject: Subject = { combined: '' };
  parsedCert.subject.forEach(([iss]) => {
    const key = issuerSubjectIDKey[iss.type];
    if (key) {
      subject[key] = iss.value.toString();
    }
  });
  subject.combined = issuerSubjectToString(subject);

  let basicConstraintsCA = false;
  if (parsedCert.extensions) {
    // console.log(parsedCert.extensions);
    for (const ext of parsedCert.extensions) {
      if (ext.extnID === id_ce_basicConstraints) {
        const basicConstraints = AsnParser.parse(
          ext.extnValue,
          BasicConstraints,
        );
        basicConstraintsCA = basicConstraints.cA;
      }
    }
  }

  return {
    issuer,
    subject,
    version: parsedCert.version,
    basicConstraintsCA,
    notBefore: parsedCert.validity.notBefore.getTime(),
    notAfter: parsedCert.validity.notAfter.getTime(),
    parsedCertificate: x509,
  };
}

/**
 * Stringify the parts of Issuer or Subject info for easier comparison of subject issuers with
 * issuer subjects.
 *
 * The order might seem arbitrary, because it is. It should be enough that the two are stringified
 * in the same order.
 */
function issuerSubjectToString(input: Issuer | Subject): string {
  const parts: string[] = [];

  if (input.C) {
    parts.push(input.C);
  }

  if (input.O) {
    parts.push(input.O);
  }

  if (input.OU) {
    parts.push(input.OU);
  }

  if (input.CN) {
    parts.push(input.CN);
  }

  return parts.join(' : ');
}

/**
 * Cut up a TPM attestation's certInfo into intelligible chunks
 */
export function parseCertInfo(certInfo: Uint8Array): ParsedCertInfo {
  let pointer = 0;
  const dataView = toDataView(certInfo);

  // Get a magic constant
  const magic = dataView.getUint32(pointer);
  pointer += 4;

  // Determine the algorithm used for attestation
  const typeBuffer = dataView.getUint16(pointer);
  pointer += 2;
  const type = TPM_ST[typeBuffer];

  // The name of a parent entity, can be ignored
  const qualifiedSignerLength = dataView.getUint16(pointer);
  pointer += 2;
  const qualifiedSigner = certInfo.slice(
    pointer,
    pointer += qualifiedSignerLength,
  );

  // Get the expected hash of `attsToBeSigned`
  const extraDataLength = dataView.getUint16(pointer);
  pointer += 2;
  const extraData = certInfo.slice(pointer, pointer += extraDataLength);

  // Information about the TPM device's internal clock, can be ignored
  const clock = certInfo.slice(pointer, pointer += 8);
  const resetCount = dataView.getUint32(pointer);
  pointer += 4;
  const restartCount = dataView.getUint32(pointer);
  pointer += 4;
  const safe = !!certInfo.slice(pointer, pointer += 1);

  const clockInfo = { clock, resetCount, restartCount, safe };

  // TPM device firmware version
  const firmwareVersion = certInfo.slice(pointer, pointer += 8);

  // Attested Name
  const attestedNameLength = dataView.getUint16(pointer);
  pointer += 2;
  const attestedName = certInfo.slice(pointer, pointer += attestedNameLength);
  const attestedNameDataView = toDataView(attestedName);

  // Attested qualified name, can be ignored
  const qualifiedNameLength = dataView.getUint16(pointer);
  pointer += 2;
  const qualifiedName = certInfo.slice(pointer, pointer += qualifiedNameLength);

  const attested = {
    nameAlg: TPM_ALG[attestedNameDataView.getUint16(0)],
    nameAlgBuffer: attestedName.slice(0, 2),
    name: attestedName,
    qualifiedName,
  };

  return {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clockInfo,
    firmwareVersion,
    attested,
  };
}
