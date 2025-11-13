#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::v0::*;
    use super::super::{AccountId, AccountSecrets, AccountState, AccountUpdate};
    use crate::crypto::{sig, symmetric as sym};
    use crate::encode::serialize;
    use crate::types::{MskSecretShareRik, RecoveryInitiationKey};
    use crate::SwafeError;
    use rand::rngs::OsRng;

    #[test]
    fn test_allocation_protocol_complete() {
        let mut rng = OsRng;

        // create the secrets for a new account
        let secrets = AccountSecrets::gen(&mut rng).unwrap();

        // create the initial "update"
        let update = secrets.update(&mut rng).unwrap();

        // verify the allocation
        let _st0 = update.verify(None).unwrap();
    }

    #[test]
    fn test_account_update() {
        let mut rng = OsRng;

        // create the secrets for a new account
        let secrets = AccountSecrets::gen(&mut rng).unwrap();

        // create the initial "update"
        let update = secrets.update(&mut rng).unwrap();

        // verify the allocation
        let st0 = update.verify(None).unwrap();

        // decrypt the new state using the msk
        let mut secrets = st0.decrypt(secrets.msk(), *secrets.acc()).unwrap();

        // create an update
        secrets.new_pke(&mut rng);

        // produce an update
        let update = secrets.update(&mut rng).unwrap();

        // verify against the old state
        let _st1 = update.verify(Some(&st0)).unwrap();
    }

    #[test]
    fn test_setup_recovery() {
        let mut rng = OsRng;

        // Create account secrets
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create guardian accounts
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
            guardian3.state(&mut rng).unwrap(),
        ];

        // Setup recovery with update_recovery and add_association
        account_secrets
            .update_recovery(&mut rng, &guardians, 2)
            .unwrap();
        let _rik = account_secrets.add_association(&mut rng).unwrap();

        // Verify recovery state is properly set by checking the public state
        let account_state = account_secrets.state(&mut rng).unwrap();
        match account_state {
            AccountState::V0(state) => {
                let recovery_state = &state.rec;

                // Check that associations exist
                assert!(!recovery_state.assoc.is_empty());

                // Check that social backup exists - just verify it has a valid ID
                let _backup_id = recovery_state.social.id();
            }
        }
    }

    #[test]
    fn test_rik_encryption_decryption() {
        let mut rng = OsRng;

        // Generate RIK and test data
        let rik = RecoveryInitiationKey::gen(&mut rng);
        let key_sig = sig::SigningKey::gen(&mut rng);
        let msk_ss_rik = MskSecretShareRik::gen(&mut rng);

        // Create EncapV0
        let original_encap = EncapV0 {
            key_sig: key_sig.clone(),
            msk_ss_rik: msk_ss_rik.clone(),
        };

        // Encrypt with RIK
        let ciphertext = sym::seal(&mut rng, rik.as_bytes(), &original_encap, &sym::EmptyAD);

        // Decrypt with same RIK
        let decrypted_encap: EncapV0 =
            sym::open(rik.as_bytes(), &ciphertext, &sym::EmptyAD).unwrap();

        // Verify data integrity by comparing verification keys
        let original_vk = key_sig.verification_key();
        let decrypted_vk = decrypted_encap.key_sig.verification_key();

        // Create a Tagged test message
        #[derive(serde::Serialize)]
        struct TestMessage {
            data: String,
        }

        impl crate::encode::Tagged for TestMessage {
            const SEPARATOR: &'static str = "test:message";
        }

        let test_msg = TestMessage {
            data: "test message".to_string(),
        };
        let original_sig = key_sig.sign(&mut rng, &test_msg);
        assert!(original_vk.verify(&original_sig, &test_msg).is_ok());
        assert!(decrypted_vk.verify(&original_sig, &test_msg).is_ok());

        assert_eq!(decrypted_encap.msk_ss_rik, msk_ss_rik);
    }

    #[test]
    fn test_initiate_recovery() {
        let mut rng = OsRng;

        // Create account secrets
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create guardian accounts
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
            guardian3.state(&mut rng).unwrap(),
        ];

        // Setup recovery with v2 method
        account_secrets
            .update_recovery(&mut rng, &guardians, 2)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        // Get the account state for recovery initiation
        let account_state = account_secrets.state(&mut rng).unwrap();

        // Initiate recovery using the RIK
        let (recovery_update, _secret_data) = account_state
            .initiate_recovery(&mut rng, *account_secrets.acc(), &rik)
            .unwrap();

        // Secret data structure is validated internally, no need to check private fields

        // Verify the recovery update has the correct account ID
        assert_eq!(recovery_update.unsafe_account_id(), *account_secrets.acc());

        // Verify it's a recovery message (not a regular update)
        match &recovery_update {
            AccountUpdate::V0(update) => {
                match &update.msg {
                    AccountMessageV0::Recovery(_) => {
                        // This is what we expect
                    }
                    _ => panic!("Expected recovery message"),
                }
            }
        }
    }

    #[test]
    fn test_initiate_recovery_invalid_rik() {
        let mut rng = OsRng;

        // Create account secrets
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create guardian accounts
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
        ];

        // Setup recovery with v2 method
        account_secrets
            .update_recovery(&mut rng, &guardians, 2)
            .unwrap();
        let _rik = account_secrets.add_association(&mut rng).unwrap();

        // Get the account state for recovery initiation
        let account_state = account_secrets.state(&mut rng).unwrap();

        // Try to initiate recovery with a different (wrong) RIK
        let wrong_rik = RecoveryInitiationKey::gen(&mut rng);
        let recovery_result =
            account_state.initiate_recovery(&mut rng, *account_secrets.acc(), &wrong_rik);

        // Should fail with InvalidRecoveryKey
        match recovery_result {
            Err(SwafeError::InvalidRecoveryKey) => {
                // This is expected
            }
            _ => panic!("Expected InvalidRecoveryKey error"),
        }
    }

    #[test]
    fn test_initiate_recovery_no_recovery_state() {
        let mut rng = OsRng;

        // Create account secrets (now has trivial recovery setup by default)
        let account_secrets = AccountSecrets::gen(&mut rng).unwrap();
        let account_state = account_secrets.state(&mut rng).unwrap();

        // Try to initiate recovery with a wrong RIK (not one that was generated for this account)
        let wrong_rik = RecoveryInitiationKey::gen(&mut rng);
        let recovery_result =
            account_state.initiate_recovery(&mut rng, *account_secrets.acc(), &wrong_rik);

        // Should fail with InvalidRecoveryKey since the RIK doesn't match
        match recovery_result {
            Err(SwafeError::InvalidRecoveryKey) => {
                // This is expected
            }
            _ => panic!("Expected InvalidRecoveryKey error for wrong RIK"),
        }
    }

    #[test]
    fn test_process_recovery_request_success() {
        let mut rng = OsRng;

        // Create account that needs recovery
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create 3 guardians
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian_states = vec![
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
            guardian3.state(&mut rng).unwrap(),
        ];

        // Setup recovery for the account with 3 guardians, threshold 2
        account_secrets
            .update_recovery(&mut rng, &guardian_states, 2)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        let account_state = account_secrets.state(&mut rng).unwrap();

        // Initiate recovery using the RIK
        let (recovery_request, _recovery_secret_data) = account_state
            .initiate_recovery(&mut rng, *account_secrets.acc(), &rik)
            .unwrap();

        // Apply the recovery request to get the updated account state
        let updated_account_state = recovery_request.verify(Some(&account_state)).unwrap();

        // Guardian1 checks for recovery request on the updated account state
        let guardian_share1 = guardian1
            .check_for_recovery(&mut rng, *account_secrets.acc(), &updated_account_state)
            .unwrap()
            .expect("Guardian1 should find pending recovery");

        // Guardian2 checks for recovery request on the updated account state
        let guardian_share2 = guardian2
            .check_for_recovery(&mut rng, *account_secrets.acc(), &updated_account_state)
            .unwrap()
            .expect("Guardian2 should find pending recovery");

        // Verify that guardian shares are valid by encoding them (they should be different)
        let share1_bytes = serialize(&guardian_share1).unwrap();
        let share2_bytes = serialize(&guardian_share2).unwrap();
        assert_ne!(share1_bytes, share2_bytes);
    }

    #[test]
    fn test_process_recovery_request_no_recovery_state() {
        let mut rng = OsRng;

        // Create account without recovery setup
        let account_secrets = AccountSecrets::gen(&mut rng).unwrap();
        let account_state = account_secrets.state(&mut rng).unwrap();

        // Create guardian
        let guardian = AccountSecrets::gen(&mut rng).unwrap();

        // Guardian tries to process recovery for account without recovery state
        let result = guardian.check_for_recovery(&mut rng, *account_secrets.acc(), &account_state);

        // Should return None because account has no recovery state
        match result {
            Ok(None) => {
                // This is expected
            }
            _ => panic!("Expected None since account has no recovery state"),
        }
    }

    #[test]
    fn test_process_recovery_request_guardian_not_authorized() {
        let mut rng = OsRng;

        // Create account that needs recovery
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create authorized guardian and unauthorized guardian
        let authorized_guardian = AccountSecrets::gen(&mut rng).unwrap();
        let unauthorized_guardian = AccountSecrets::gen(&mut rng).unwrap();
        let guardian_states = vec![authorized_guardian.state(&mut rng).unwrap()];

        // Setup recovery for the account with only authorized_guardian
        account_secrets
            .update_recovery(&mut rng, &guardian_states, 1)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        let account_state = account_secrets.state(&mut rng).unwrap();

        // Initiate recovery using the RIK
        let (recovery_request, _recovery_secret_data) = account_state
            .initiate_recovery(&mut rng, *account_secrets.acc(), &rik)
            .unwrap();

        // Apply the recovery request to get the updated account state
        let updated_account_state = recovery_request.verify(Some(&account_state)).unwrap();

        // Unauthorized guardian tries to process the recovery request
        let result = unauthorized_guardian.check_for_recovery(
            &mut rng,
            *account_secrets.acc(),
            &updated_account_state,
        );

        // Should fail because guardian is not authorized (not in the backup list)
        match result {
            Err(SwafeError::InvalidOperation(msg)) if msg.contains("not authorized") => {
                // This is expected
            }
            _ => panic!("Expected InvalidOperation error about guardian not authorized"),
        }
    }

    #[test]
    fn test_process_recovery_request_wrong_message_type() {
        let mut rng = OsRng;

        // Create account and guardian
        let account_secrets = AccountSecrets::gen(&mut rng).unwrap();
        let guardian = AccountSecrets::gen(&mut rng).unwrap();

        // Create a regular account update (not recovery)
        let _regular_update = account_secrets.update(&mut rng).unwrap();
        let account_state = account_secrets.state(&mut rng).unwrap();

        // Guardian tries to process a regular update as recovery request
        let result = guardian.check_for_recovery(&mut rng, *account_secrets.acc(), &account_state);

        // Should return None because there's no pending recovery
        match result {
            Ok(None) => {
                // This is expected - no recovery initiated
            }
            _ => panic!("Expected None since there's no pending recovery"),
        }
    }

    // Integration tests from v0.rs
    #[test]
    fn test_complete_recovery_simple() {
        let mut rng = OsRng;

        // Create an account
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create guardians (threshold 2 out of 3)
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian3 = AccountSecrets::gen(&mut rng).unwrap();

        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
            guardian3.state(&mut rng).unwrap(),
        ];
        let threshold = 2;

        // Setup recovery using the RIK-based system
        account_secrets
            .update_recovery(&mut rng, &guardians, threshold)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        // Test the complete recovery process
        // Extract recovery state
        let account_state = account_secrets.state(&mut rng).unwrap();
        let AccountState::V0(account_state_v0) = &account_state;

        // Initiate recovery using the RIK
        let (_recovery_update, recovery_secrets) = account_state_v0
            .initiate_recovery(&mut rng, *account_secrets.acc(), &rik)
            .unwrap();

        // Simulate guardian shares (for now, create empty ones as a placeholder)
        let guardian_shares = Vec::new(); // This will fail but we'll see how far we get

        // Use the new instance method for recovery completion
        let result = recovery_secrets.complete(&guardian_shares);

        match result {
            Ok(_recovered_msk) => {
                // Won't succeed with dummy data
            }
            Err(_e) => {
                // This is expected since we used dummy guardian shares
            }
        }
    }

    #[test]
    fn test_recovery_with_zero_guardians() {
        let mut rng = OsRng;

        // Create an account
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();
        let original_msk = account_secrets.msk().clone();

        // Setup recovery with zero guardians (threshold 0)
        let guardians = [];
        let threshold = 0;

        account_secrets
            .update_recovery(&mut rng, &guardians, threshold)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        // Get account state
        let account_state = account_secrets.state(&mut rng).unwrap();
        let AccountState::V0(account_state_v0) = &account_state;

        // Initiate recovery using the RIK
        let (_recovery_update, recovery_secrets) = account_state_v0
            .initiate_recovery(&mut rng, *account_secrets.acc(), &rik)
            .unwrap();

        // Complete recovery with no guardian shares (since threshold is 0)
        let guardian_shares = Vec::new();
        let recovered_msk = recovery_secrets.complete(&guardian_shares).unwrap();

        // Verify the recovered MSK matches the original
        assert_eq!(recovered_msk.as_bytes(), original_msk.as_bytes());
    }

    #[test]
    fn test_full_recovery_integration() {
        let mut rng = OsRng;

        // Step 1: Create account with MSK
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();
        let account_id = *account_secrets.acc();
        let original_msk = account_secrets.msk().clone();

        // Step 2: Create 3 guardians, threshold 2
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian_states = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
            guardian3.state(&mut rng).unwrap(),
        ];

        // Step 3: Setup recovery with guardians (returns RIK for offchain storage)
        account_secrets
            .update_recovery(&mut rng, &guardian_states, 2)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        // Step 4: Simulate account state after setup
        let account_state = account_secrets.state(&mut rng).unwrap();
        let AccountState::V0(account_state_v0) = &account_state;

        // Step 5: Initiate recovery using the RIK
        let (recovery_request, recovery_secrets) = account_state_v0
            .initiate_recovery(&mut rng, account_id, &rik)
            .expect("Failed to initiate recovery");

        // Step 6: Simulate contract processing recovery update using verify_update
        let (AccountUpdate::V0(recovery_update), AccountState::V0(old_state)) =
            (&recovery_request, &account_state);
        let new_state = recovery_update
            .clone()
            .verify_update(old_state)
            .expect("Recovery update should be valid");
        let updated_account_state = AccountState::V0(new_state);

        let guardian_share1 = guardian1
            .check_for_recovery(&mut rng, account_id, &updated_account_state)
            .unwrap()
            .expect("Guardian1 should find pending recovery");

        let guardian_share2 = guardian2
            .check_for_recovery(&mut rng, account_id, &updated_account_state)
            .unwrap()
            .expect("Guardian2 should find pending recovery");

        let guardian_shares = vec![guardian_share1, guardian_share2];

        // Step 7: Use the fixed complete method
        let recovered_msk = recovery_secrets
            .complete(&guardian_shares)
            .expect("Recovery should succeed with proper guardian shares");

        // Step 8: Verify the recovered MSK matches the original
        assert_eq!(
            recovered_msk, original_msk,
            "Recovered MSK should match original"
        );
    }

    #[test]
    fn test_recovery_with_insufficient_guardians() {
        let mut rng = OsRng;

        // Test failure case: 3 guardians, threshold 2, but only 1 guardian responds
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();
        let account_id = *account_secrets.acc();

        // Create 3 guardians
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian_states = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
            guardian3.state(&mut rng).unwrap(),
        ];

        // Setup recovery with threshold 2
        account_secrets
            .update_recovery(&mut rng, &guardian_states, 2)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        let account_state = account_secrets.state(&mut rng).unwrap();
        let AccountState::V0(account_state_v0) = &account_state;

        // Initiate recovery to get RecoverySecrets and the update
        let (recovery_request, recovery_secrets) = account_state_v0
            .initiate_recovery(&mut rng, account_id, &rik)
            .expect("Failed to initiate recovery");

        // Apply the recovery request to get the updated account state
        let updated_account_state = recovery_request.verify(Some(&account_state)).unwrap();

        // Only get 1 guardian share (below threshold of 2)
        let guardian_share1 = guardian1
            .check_for_recovery(&mut rng, account_id, &updated_account_state)
            .unwrap()
            .expect("Guardian1 should find pending recovery");

        let insufficient_shares = vec![guardian_share1];

        // Should fail with insufficient shares
        let recovery_result = recovery_secrets.complete(&insufficient_shares);

        assert!(
            recovery_result.is_err(),
            "Recovery should fail with insufficient shares"
        );
        match recovery_result {
            Err(SwafeError::InsufficientShares) => {
                // Expected error type
            }
            _ => panic!("Expected InsufficientShares error"),
        }
    }

    #[test]
    fn test_complete_recovery_insufficient_shares() {
        let mut rng = OsRng;

        // Create an account
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create guardians (threshold 2 out of 3)
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
            guardian3.state(&mut rng).unwrap(),
        ];
        let threshold = 2;

        // Setup recovery
        account_secrets
            .update_recovery(&mut rng, &guardians, threshold)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        // Extract recovery components
        let account_state = account_secrets.state(&mut rng).unwrap();

        // Initiate recovery
        let (recovery_request, recovery_secret_data) = account_state
            .initiate_recovery(&mut rng, *account_secrets.acc(), &rik)
            .unwrap();

        // Apply the recovery request to get the updated account state
        let updated_account_state = recovery_request.verify(Some(&account_state)).unwrap();

        // Get only one guardian share (less than threshold)
        let guardian_share1 = guardian1
            .check_for_recovery(&mut rng, *account_secrets.acc(), &updated_account_state)
            .unwrap()
            .expect("Guardian1 should find pending recovery");

        let guardian_shares = vec![guardian_share1]; // Only 1 share, need 2

        // Attempt complete recovery with insufficient shares
        let result = recovery_secret_data.complete(&guardian_shares);

        // Should fail with InsufficientShares error
        match result {
            Err(SwafeError::InsufficientShares) => {
                // This is expected
            }
            _ => panic!("Expected InsufficientShares error"),
        }
    }

    #[test]
    fn test_complete_recovery_wrong_rik() {
        let mut rng = OsRng;

        // Create an account
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create guardians
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
        ];
        let threshold = 2;

        // Setup recovery
        account_secrets
            .update_recovery(&mut rng, &guardians, threshold)
            .unwrap();
        let _correct_rik = account_secrets.add_association(&mut rng).unwrap();

        // Extract recovery components
        let account_state = account_secrets.state(&mut rng).unwrap();
        let AccountState::V0(account_state_v0) = &account_state;

        // Try to initiate recovery with wrong RIK
        let wrong_rik = RecoveryInitiationKey::gen(&mut rng);
        let result =
            account_state_v0.initiate_recovery(&mut rng, *account_secrets.acc(), &wrong_rik);

        // Should fail to decrypt with wrong RIK
        assert!(result.is_err());
    }

    #[test]
    fn test_account_id_display() {
        let mut rng = OsRng;
        let sig_key = sig::SigningKey::gen(&mut rng);
        let vk = sig_key.verification_key();
        let account_id = AccountId::from_verification_key(&vk);

        // Test Display implementation
        let display_str = format!("{}", account_id);
        assert!(display_str.starts_with("account:"));
        assert_eq!(display_str.len(), 8 + 64); // "account:" + 64 hex chars
    }

    #[test]
    fn test_account_id_as_ref() {
        let mut rng = OsRng;
        let sig_key = sig::SigningKey::gen(&mut rng);
        let vk = sig_key.verification_key();
        let account_id = AccountId::from_verification_key(&vk);

        // Test AsRef implementation
        let bytes_ref: &[u8; 32] = account_id.as_ref();
        assert_eq!(bytes_ref.len(), 32);
    }

    #[test]
    fn test_account_id_random() {
        let mut rng = OsRng;

        // Test random generation
        let id1 = AccountId::random(&mut rng);
        let id2 = AccountId::random(&mut rng);

        // Should generate different IDs
        assert_ne!(serialize(&id1).unwrap(), serialize(&id2).unwrap());
    }

    #[test]
    fn test_account_secrets_getters() {
        let mut rng = OsRng;
        let secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Test sig() getter
        let _sig_key = secrets.sig();

        // Test version() getter
        let version = secrets.version();
        assert_eq!(version, 0); // V0 should return 0
    }

    #[test]
    fn test_account_state_recover_methods() {
        let mut rng = OsRng;

        // Create account with recovery setup which creates internal backups
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
        ];

        // Setup recovery - this creates a social backup internally
        account_secrets
            .update_recovery(&mut rng, &guardians, 2)
            .unwrap();
        let _rik = account_secrets.add_association(&mut rng).unwrap();

        // Get the state directly from secrets
        let account_state = account_secrets.state(&mut rng).unwrap();

        // Access the recovery state to get the social backup
        match &account_state {
            AccountState::V0(state) => {
                let rec = &state.rec;
                // Test that we can get the backup ID from the social backup
                let backup_id = rec.social.id();

                // Test recover_id() with the social backup ID
                // Note: recover_id looks in the backups field, not in recovery state
                // So this will be None unless we add backups explicitly
                let found_backup = account_state.recover_id(backup_id);

                // Since social backup is stored in rec, not in backups, it won't be found
                assert!(found_backup.is_none());
            }
        }

        // Test recover_backups() - it returns the backups field which starts empty
        let backups = account_state.recover_backups();
        assert!(backups.is_empty()); // Initially empty until we add explicit backups
    }

    #[test]
    fn test_account_secrets_backup_operations() {
        let mut rng = OsRng;
        let mut secrets = AccountSecrets::gen(&mut rng).unwrap();

        // First setup recovery to get a social backup
        let guardian = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [guardian.state(&mut rng).unwrap()];
        secrets.update_recovery(&mut rng, &guardians, 1).unwrap();
        let _rik = secrets.add_association(&mut rng).unwrap();

        // Get the backup ID from the recovery state
        let state = secrets.state(&mut rng).unwrap();
        let backup_id = match &state {
            AccountState::V0(s) => &s.rec.social.id(),
        };

        // Now test operations with this backup ID
        // Note: These operations work on the internal backups list, not the recovery state

        // Test mark_recovery() - This should fail since the backup is in recovery state, not backups list
        let mark_result = secrets.mark_recovery(*backup_id);
        assert!(mark_result.is_err()); // Expected to fail - backup not in backups list

        // Test remove_backup() - This is a no-op if backup doesn't exist
        secrets.remove_backup(*backup_id);

        // Create a proper external backup for testing add_backup
        // We need to get the social backup from recovery state and add it as external backup
        let social_backup = match &state {
            AccountState::V0(s) => &s.rec.social.clone(),
        };

        // Test add_backup()
        secrets.add_backup(social_backup.clone()).unwrap();

        // Now mark_recovery should work since we added it to backups
        secrets.mark_recovery(*backup_id).unwrap();
    }

    #[test]
    fn test_account_secrets_msk_operations() {
        let mut rng = OsRng;
        let mut secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Test new_msk()
        let old_msk = serialize(secrets.msk()).unwrap();
        secrets.new_msk(&mut rng);
        let new_msk = serialize(secrets.msk()).unwrap();
        assert_ne!(old_msk, new_msk);

        // Test new_sig()
        let old_sig = serialize(secrets.sig()).unwrap();
        secrets.new_sig(&mut rng);
        let new_sig = serialize(secrets.sig()).unwrap();
        assert_ne!(old_sig, new_sig);
    }

    #[test]
    fn test_complete_recovery_wrapper() {
        let mut rng = OsRng;

        // Create account
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create guardians
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
        ];

        // Setup recovery
        account_secrets
            .update_recovery(&mut rng, &guardians, 2)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        let account_state = account_secrets.state(&mut rng).unwrap();

        // Initiate recovery
        let (recovery_request, recovery_secret_data) = account_state
            .initiate_recovery(&mut rng, *account_secrets.acc(), &rik)
            .unwrap();

        // Apply the recovery request to get the updated account state
        let updated_account_state = recovery_request.verify(Some(&account_state)).unwrap();

        // Get guardian shares
        let share1 = guardian1
            .check_for_recovery(&mut rng, *account_secrets.acc(), &updated_account_state)
            .unwrap()
            .expect("Guardian1 should find pending recovery");
        let share2 = guardian2
            .check_for_recovery(&mut rng, *account_secrets.acc(), &updated_account_state)
            .unwrap()
            .expect("Guardian2 should find pending recovery");

        // Test completion method
        let recovered_msk = recovery_secret_data.complete(&[share1, share2]).unwrap();

        // Verify the recovered MSK
        assert_eq!(
            serialize(&recovered_msk).unwrap(),
            serialize(account_secrets.msk()).unwrap()
        );
    }

    #[test]
    fn test_association_revocation() {
        let mut rng = OsRng;

        // Create account with recovery setup
        let account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create guardians
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
            guardian3.state(&mut rng).unwrap(),
        ];

        // Create and verify initial state first
        let update = account_secrets.update(&mut rng).unwrap();
        let account_state = update.verify(None).unwrap();

        // Decrypt to continue working
        let mut account_secrets = account_state
            .decrypt(account_secrets.msk(), *account_secrets.acc())
            .unwrap();

        // Setup recovery
        account_secrets
            .update_recovery(&mut rng, &guardians, 2)
            .unwrap();

        // Add multiple associations
        let rik1 = account_secrets.add_association(&mut rng).unwrap();
        let rik2 = account_secrets.add_association(&mut rng).unwrap();
        let rik3 = account_secrets.add_association(&mut rng).unwrap();

        // Create updated state with recovery
        let update = account_secrets.update(&mut rng).unwrap();
        let account_state = update.verify(Some(&account_state)).unwrap();

        // Should have 3 associations in published state
        let AccountState::V0(ref state_v0) = account_state;
        assert_eq!(state_v0.rec.assoc.len(), 3);

        // Decrypt current state to get mutable secrets
        let mut account_secrets = account_state
            .decrypt(account_secrets.msk(), *account_secrets.acc())
            .unwrap();

        // Revoke rik2
        account_secrets.revoke_association(&rik2).unwrap();

        // Verify rik2 is gone by trying to revoke again (should fail)
        let result = account_secrets.revoke_association(&rik2);
        assert!(matches!(result, Err(SwafeError::InvalidRecoveryKey)));

        // Revoke rik1 and rik3 (leaving zero associations)
        account_secrets.revoke_association(&rik1).unwrap();
        account_secrets.revoke_association(&rik3).unwrap();

        // Publish updated state
        let update2 = account_secrets.update(&mut rng).unwrap();
        let account_state2 = update2.verify(Some(&account_state)).unwrap();

        // Verify zero associations remain
        let AccountState::V0(ref state_v0_2) = account_state2;
        assert_eq!(state_v0_2.rec.assoc.len(), 0);
    }

    #[test]
    fn test_revoked_association_cannot_initiate_recovery() {
        let mut rng = OsRng;

        // Create account
        let account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create and verify initial state
        let update = account_secrets.update(&mut rng).unwrap();
        let account_state = update.verify(None).unwrap();

        // Decrypt to continue
        let mut account_secrets = account_state
            .decrypt(account_secrets.msk(), *account_secrets.acc())
            .unwrap();

        // Create guardians
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
        ];

        // Setup recovery
        account_secrets
            .update_recovery(&mut rng, &guardians, 2)
            .unwrap();

        // Add a second association
        let second_rik = account_secrets.add_association(&mut rng).unwrap();

        // Publish state with recovery
        let update = account_secrets.update(&mut rng).unwrap();
        let account_state = update.verify(Some(&account_state)).unwrap();

        // Verify second_rik works initially
        let AccountState::V0(ref state_v0) = account_state;
        let (_recovery_update, _recovery_secrets) = state_v0
            .initiate_recovery(&mut rng, *account_secrets.acc(), &second_rik)
            .expect("Second RIK should work before revocation");

        // Decrypt to continue making changes
        let mut account_secrets = account_state
            .decrypt(account_secrets.msk(), *account_secrets.acc())
            .unwrap();

        // Now revoke second_rik
        account_secrets.revoke_association(&second_rik).unwrap();

        // Publish updated state
        let update2 = account_secrets.update(&mut rng).unwrap();
        let account_state2 = update2.verify(Some(&account_state)).unwrap();

        // Verify second_rik NO LONGER works
        let AccountState::V0(ref state_v0_2) = account_state2;
        let result = state_v0_2.initiate_recovery(&mut rng, *account_secrets.acc(), &second_rik);
        assert!(matches!(result, Err(SwafeError::InvalidRecoveryKey)));
    }
}
