use ark_std::rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{crypto::sig, encode::Tagged, NodeId, SwafeError};

const VALIDITY_PERIOD: Duration = Duration::from_secs(5 * 60);

/// Email possession certificate issued by Swafe
#[derive(Clone, Serialize, Deserialize)]
pub struct EmailCertificate {
    /// Signed object
    pub msg: EmailCertificateMessage,

    /// Swafe signature on Object
    pub sig: sig::Signature,
}

/// Token created by user for a specific node
#[derive(Clone, Serialize, Deserialize)]
pub struct EmailCertToken {
    /// Signature on node_id using user's secret key
    user_sig: sig::Signature,

    /// Certificate for the email possession
    cert: EmailCertificate,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EmailCertificateMessage {
    user_pk: sig::VerificationKey,
    email: String,
    timestamp: u64,
}

impl Tagged for EmailCertificateMessage {
    const SEPARATOR: &'static str = "v0:email-cert";
}

/// EmailCert implementation following Swafe specification
pub struct EmailCert;

impl EmailCert {
    /// Issue an email possession certificate
    /// This is called by Swafe after verifying email ownership via magic link
    pub fn issue<R: Rng + CryptoRng>(
        rng: &mut R,
        swafe_keypair: &sig::SigningKey,
        user_pk: &sig::VerificationKey,
        email: String,
    ) -> EmailCertificate {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let msg = EmailCertificateMessage {
            user_pk: user_pk.clone(),
            email,
            timestamp,
        };

        let sig = swafe_keypair.sign(rng, &msg);

        EmailCertificate { msg, sig }
    }

    /// Create a token for a specific node
    /// Returns EmailCert.Token(cert, sk_user, node_id)
    pub fn token<R: Rng + CryptoRng>(
        rng: &mut R,
        cert: &EmailCertificate,
        user_sk: &sig::SigningKey,
        node_id: &NodeId,
    ) -> EmailCertToken {
        EmailCertToken {
            user_sig: user_sk.sign(rng, node_id),
            cert: cert.clone(),
        }
    }

    /// Verify the email certificate and token.
    /// On Execution Engine, the system time should be passed from the EE context.
    pub fn verify<'a>(
        swafe_pk: &sig::VerificationKey,
        node_id: &NodeId,
        token: &'a EmailCertToken,
        now: SystemTime,
    ) -> Result<(&'a str, &'a sig::VerificationKey), SwafeError> {
        // Verify Swafe signature on certificate
        swafe_pk.verify(&token.cert.sig, &token.cert.msg)?;

        // Verify user signature on node_id
        token.cert.msg.user_pk.verify(&token.user_sig, node_id)?;

        // convert UNIX timestamp (u64) to SystemTime
        let ts = UNIX_EPOCH
            .checked_add(Duration::from_secs(token.cert.msg.timestamp))
            .ok_or(SwafeError::CertificateExpired)?;

        // Check if certificate is from the future
        if ts > now {
            return Err(SwafeError::CertificateFromFuture);
        }

        // Check if certificate is expired
        if now
            .duration_since(ts)
            .map_err(|_| SwafeError::CertificateExpired)?
            > VALIDITY_PERIOD
        {
            return Err(SwafeError::CertificateExpired);
        }

        Ok((&token.cert.msg.email, &token.cert.msg.user_pk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_email_cert_basic_functionality() {
        let mut rng = thread_rng();

        // Generate Swafe key pair (certificate authority)
        let swafe_keypair = sig::SigningKey::gen(&mut rng);
        let swafe_pk = swafe_keypair.verification_key();

        // Generate user key pair
        let user_keypair = sig::SigningKey::gen(&mut rng);
        let user_pk = user_keypair.verification_key();

        let email = "user@example.com".to_string();
        let node_id = "node:test".parse().unwrap();

        // Test certificate issuance
        let cert = EmailCert::issue(&mut rng, &swafe_keypair, &user_pk, email.clone());

        assert_eq!(cert.msg.email, email);
        assert_eq!(cert.msg.user_pk, user_pk);

        // Test token creation
        let token = EmailCert::token(&mut rng, &cert, &user_keypair, &node_id);

        // Test successful verification
        let (verified_email, _verified_user_pk) =
            EmailCert::verify(&swafe_pk, &node_id, &token, SystemTime::now()).unwrap();

        assert_eq!(verified_email, email);

        // Test verification with wrong Swafe public key
        let wrong_swafe_keypair = sig::SigningKey::gen(&mut rng);
        let wrong_swafe_pk = wrong_swafe_keypair.verification_key();

        assert!(EmailCert::verify(&wrong_swafe_pk, &node_id, &token, SystemTime::now()).is_err());

        // Test verification with wrong node ID
        let wrong_node_id = "node:wrong".parse().unwrap();
        assert!(EmailCert::verify(&swafe_pk, &wrong_node_id, &token, SystemTime::now()).is_err());

        // Test verification with wrong token (created by different user)
        let wrong_user_keypair = sig::SigningKey::gen(&mut rng);
        let wrong_token = EmailCert::token(&mut rng, &cert, &wrong_user_keypair, &node_id);

        assert!(EmailCert::verify(&swafe_pk, &node_id, &wrong_token, SystemTime::now()).is_err());
    }

    #[test]
    fn test_email_cert_serialization() {
        let mut rng = thread_rng();

        // Generate keys
        let swafe_keypair = sig::SigningKey::gen(&mut rng);
        let swafe_pk = swafe_keypair.verification_key();
        let user_keypair = sig::SigningKey::gen(&mut rng);
        let user_pk = user_keypair.verification_key();

        let email = "test@example.com".to_string();
        let node_id = "node:test789".parse().unwrap();

        // Create certificate and token
        let certificate = EmailCert::issue(&mut rng, &swafe_keypair, &user_pk, email.clone());

        let token = EmailCert::token(&mut rng, &certificate, &user_keypair, &node_id);

        // Test JSON serialization/deserialization
        let cert_json = serde_json::to_string(&certificate).unwrap();
        let cert_deserialized: EmailCertificate = serde_json::from_str(&cert_json).unwrap();

        assert_eq!(certificate.msg.email, cert_deserialized.msg.email);
        assert_eq!(certificate.msg.timestamp, cert_deserialized.msg.timestamp);
        assert_eq!(certificate.msg.user_pk, cert_deserialized.msg.user_pk);

        let token_json = serde_json::to_string(&token).unwrap();
        let token_deserialized: EmailCertToken = serde_json::from_str(&token_json).unwrap();

        // Verify the deserialized structures still work
        let (verified_email, _verified_user_pk) =
            EmailCert::verify(&swafe_pk, &node_id, &token_deserialized, SystemTime::now()).unwrap();

        assert_eq!(verified_email, email);
    }
}
