use crate::account::{v0::AccountSecrets, AccountState};
use crate::Tagged;
use rand::rngs::OsRng;

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct TestData {
    value: String,
}

impl Tagged for TestData {
    const SEPARATOR: &'static str = "v0:test-data";
}

#[test]
fn test_backup_and_try_decrypt() {
    let mut rng = OsRng;

    // Create accounts - one owner and three guardians
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian3 = AccountSecrets::gen(&mut rng).unwrap();

    // Someone who is not a guardian
    let non_guardian = AccountSecrets::gen(&mut rng).unwrap();

    // Get their public states
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    let guardian2_state = guardian2.state(&mut rng).unwrap();
    let guardian3_state = guardian3.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "secret information".to_string(),
    };

    // Create backup with threshold 2 (need 2 out of 3 guardians)
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "Test Backup".to_string(),
                "A test backup for unit testing".to_string(),
            ),
            &[guardian1_state, guardian2_state, guardian3_state],
            2,
        )
        .unwrap();

    // Test that each guardian can decrypt their share
    assert!(guardian1
        .decrypt_share_backupy(*owner.acc(), &backup)
        .is_some());
    assert!(guardian2
        .decrypt_share_backupy(*owner.acc(), &backup)
        .is_some());
    assert!(guardian3
        .decrypt_share_backupy(*owner.acc(), &backup)
        .is_some());

    // Test that owner cannot decrypt (not a guardian)
    assert!(non_guardian
        .decrypt_share_backupy(*owner.acc(), &backup)
        .is_none());

    // Test that decrypting with the *wrong* account fails
    assert!(guardian1
        .decrypt_share_backupy(*guardian2.acc(), &backup)
        .is_none());
    assert!(guardian2
        .decrypt_share_backupy(*guardian1.acc(), &backup)
        .is_none());
    assert!(guardian2
        .decrypt_share_backupy(*non_guardian.acc(), &backup)
        .is_none());
}

#[test]
fn test_backup_with_zero_threshold() {
    let mut rng = OsRng;

    // Create accounts
    let owner = AccountSecrets::gen(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "zero threshold secret".to_string(),
    };

    // Create backup with threshold 0 and no guardians
    owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "Zero Threshold Backup".to_string(),
                "A backup that only needs master key".to_string(),
            ),
            &[], // No guardians needed for threshold 0
            0,
        )
        .unwrap();

    // With threshold 0, no shares are created
    // The backup exists but contains no share ciphertexts
}

#[test]
fn test_backup_and_recover() {
    let mut rng = OsRng;

    // Create accounts - one owner and three guardians
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian3 = AccountSecrets::gen(&mut rng).unwrap();

    // Get their public states
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    let guardian2_state = guardian2.state(&mut rng).unwrap();
    let guardian3_state = guardian3.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "secret information".to_string(),
    };

    // Create backup with threshold 2 (need 2 out of 3 guardians)
    let backup: BackupCiphertext = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "Test Backup".to_string(),
                "A test backup for unit testing".to_string(),
            ),
            &[guardian1_state, guardian2_state, guardian3_state],
            2,
        )
        .unwrap();

    // Each guardian decrypts their share
    let share1 = guardian1
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();
    let share2 = guardian2
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();
    let share3 = guardian3
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();

    // Each guardian encrypts their share towards the owner
    let owner_st: AccountState = owner.state(&mut rng).unwrap();
    let gs1: GuardianShare = share1.send(&mut rng, &owner_st).unwrap();
    let gs2: GuardianShare = share2.send(&mut rng, &owner_st).unwrap();
    let gs3: GuardianShare = share3.send(&mut rng, &owner_st).unwrap();

    // These shares can be publically verified against the original backup
    // (to prevent resource exchaustion issues / denial-of-service)
    //
    // Doing so, they return unique identifiers for each share
    let id1 = backup.verify(&gs1).unwrap();
    let id2 = backup.verify(&gs2).unwrap();
    let id3 = backup.verify(&gs3).unwrap();
    assert_ne!(id1, id2);
    assert_ne!(id1, id3);
    assert_ne!(id2, id3);

    // Finally, the owner can try to recover the backup:
    // using the encrypted shares and their secret state
    let data_rec = owner.recover(&backup, &[gs1, gs2, gs3]).unwrap();
    assert_eq!(test_data, data_rec)
}

#[test]
fn test_backup_insufficient_guardians() {
    let mut rng = OsRng;

    // Create accounts
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();

    // Get guardian public state
    let guardian1_state = guardian1.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "insufficient guardians".to_string(),
    };

    // Try to create backup with threshold 2 but only 1 guardian
    let result = owner.backup(
        &mut rng,
        &test_data,
        Metadata::new("Bad Backup".to_string(), "This should fail".to_string()),
        &[guardian1_state],
        2,
    );

    // Should fail with InsufficientShares error
    assert!(matches!(result, Err(crate::SwafeError::InsufficientShares)));
}

#[test]
fn test_full_backup_decrypt_flow() {
    let mut rng = OsRng;

    // Create accounts - one owner and three guardians
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian3 = AccountSecrets::gen(&mut rng).unwrap();

    // Get their public states
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    let guardian2_state = guardian2.state(&mut rng).unwrap();
    let guardian3_state = guardian3.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "secret information for full flow test".to_string(),
    };

    // Create backup with threshold 2 (need 2 out of 3 guardians)
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "Full Flow Test".to_string(),
                "Testing the complete backup and recovery flow".to_string(),
            ),
            &[guardian1_state, guardian2_state, guardian3_state],
            2,
        )
        .unwrap();

    // Each guardian decrypts their share
    let share1 = guardian1
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();
    let share2 = guardian2
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();
    let share3 = guardian3
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();

    // Each guardian encrypts their share towards the owner
    let owner_st = owner.state(&mut rng).unwrap();
    let gs1 = share1.send(&mut rng, &owner_st).unwrap();
    let gs2 = share2.send(&mut rng, &owner_st).unwrap();
    let gs3 = share3.send(&mut rng, &owner_st).unwrap();

    // Test recovery with exactly threshold shares (2 out of 3)
    let recovered_data: TestData = owner.recover(&backup, &[gs1.clone(), gs2.clone()]).unwrap();
    assert_eq!(recovered_data, test_data);

    // Test recovery with all shares (more than threshold) - only first threshold shares should be used
    let recovered_data2: TestData = owner.recover(&backup, &[gs1, gs2, gs3]).unwrap();
    assert_eq!(recovered_data2, test_data);
}

#[test]
fn test_backup_decrypt_with_zero_threshold() {
    let mut rng = OsRng;

    // Create owner account
    let owner = AccountSecrets::gen(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "zero threshold secret data".to_string(),
    };

    // Create backup with threshold 0 (only needs master key)
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "Zero Threshold Test".to_string(),
                "Testing backup that only requires master key".to_string(),
            ),
            &[],
            0,
        )
        .unwrap();

    // Decrypt without any shares (threshold is 0)
    let recovered_data: TestData = owner.recover(&backup, &[]).unwrap();
    assert_eq!(recovered_data, test_data);
}

#[test]
fn test_backup_decrypt_insufficient_shares() {
    let mut rng = OsRng;

    // Create accounts
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian3 = AccountSecrets::gen(&mut rng).unwrap();

    // Get their public states
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    let guardian2_state = guardian2.state(&mut rng).unwrap();
    let guardian3_state = guardian3.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "threshold test data".to_string(),
    };

    // Create backup with threshold 2
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "Threshold Test".to_string(),
                "Testing insufficient shares for recovery".to_string(),
            ),
            &[guardian1_state, guardian2_state, guardian3_state],
            2,
        )
        .unwrap();

    // Get only one share (less than threshold)
    let share1 = guardian1
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();
    let owner_st = owner.state(&mut rng).unwrap();
    let gs1 = share1.send(&mut rng, &owner_st).unwrap();

    // Try to decrypt with insufficient shares
    let result: Result<TestData, _> = owner.recover(&backup, &[gs1]);
    assert!(matches!(result, Err(crate::SwafeError::InsufficientShares)));
}

#[test]
fn test_backup_decrypt_invalid_shares() {
    let mut rng = OsRng;

    // Create accounts
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let other_owner = AccountSecrets::gen(&mut rng).unwrap();
    let other_guardian = AccountSecrets::gen(&mut rng).unwrap();

    // Get their public states
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    let guardian2_state = guardian2.state(&mut rng).unwrap();
    let other_guardian_state = other_guardian.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "invalid shares test".to_string(),
    };

    // Create backup with threshold 2
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "Invalid Shares Test".to_string(),
                "Testing detection of invalid shares".to_string(),
            ),
            &[guardian1_state, guardian2_state],
            2,
        )
        .unwrap();

    // Create a different backup with different data
    let other_backup = other_owner
        .backup(
            &mut rng,
            &TestData {
                value: "different data".to_string(),
            },
            Metadata::new("Other Backup".to_string(), "Different backup".to_string()),
            &[other_guardian_state],
            1,
        )
        .unwrap();

    // Get valid share from first backup
    let share1 = guardian1
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();
    let owner_st = owner.state(&mut rng).unwrap();
    let gs1 = share1.send(&mut rng, &owner_st).unwrap();

    // Get share from different backup
    let other_share = other_guardian
        .decrypt_share_backupy(*other_owner.acc(), &other_backup)
        .unwrap();
    let other_owner_st = other_owner.state(&mut rng).unwrap();
    let other_gs = other_share.send(&mut rng, &other_owner_st).unwrap();

    // Try to decrypt with a share from a different backup
    // The invalid share should be ignored, and we should get InsufficientShares since we only have 1 valid share
    let result: Result<TestData, _> = owner.recover(&backup, &[gs1, other_gs]);
    assert!(matches!(result, Err(crate::SwafeError::InsufficientShares)));
}

#[test]
fn test_backup_two_of_three() {
    let mut rng = OsRng;

    // Create accounts
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian3 = AccountSecrets::gen(&mut rng).unwrap();

    // Get their public states
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    let guardian2_state = guardian2.state(&mut rng).unwrap();
    let guardian3_state = guardian3.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "two of three test".to_string(),
    };

    // Create backup with threshold 2
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "2-of-3 Test".to_string(),
                "Testing 2-of-3 threshold".to_string(),
            ),
            &[guardian1_state, guardian2_state, guardian3_state],
            2,
        )
        .unwrap();

    // First two guardians decrypt their shares
    let share1 = guardian1
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();
    let share2 = guardian2
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();

    // Each guardian encrypts their share towards the owner
    let owner_st = owner.state(&mut rng).unwrap();
    let gs1 = share1.send(&mut rng, &owner_st).unwrap();
    let gs2 = share2.send(&mut rng, &owner_st).unwrap();

    // Decrypt backup with 2 shares
    let recovered_data: TestData = owner.recover(&backup, &[gs1, gs2]).unwrap();
    assert_eq!(recovered_data, test_data);
}

#[test]
fn test_simple_backup_decrypt() {
    let mut rng = OsRng;

    // Create accounts
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian = AccountSecrets::gen(&mut rng).unwrap();

    // Get guardian public state
    let guardian_state = guardian.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "simple test".to_string(),
    };

    // Create backup with threshold 1
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new("Simple Test".to_string(), "Testing simple case".to_string()),
            &[guardian_state],
            1,
        )
        .unwrap();

    // Guardian decrypts their share
    let share = guardian
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();

    // Guardian encrypts their share towards the owner
    let owner_st = owner.state(&mut rng).unwrap();
    let gs = share.send(&mut rng, &owner_st).unwrap();

    // Decrypt backup
    let recovered_data: TestData = owner.recover(&backup, &[gs]).unwrap();
    assert_eq!(recovered_data, test_data);
}

#[test]
fn test_backup_with_invalid_shares_ignored() {
    let mut rng = OsRng;

    // Create accounts
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
    let other_owner = AccountSecrets::gen(&mut rng).unwrap();
    let other_guardian = AccountSecrets::gen(&mut rng).unwrap();

    // Get their public states
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    let guardian2_state = guardian2.state(&mut rng).unwrap();
    let guardian3_state = guardian3.state(&mut rng).unwrap();
    let other_guardian_state = other_guardian.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "test with invalid shares".to_string(),
    };

    // Create backup with threshold 2
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "Invalid Shares Test".to_string(),
                "Testing that invalid shares are ignored".to_string(),
            ),
            &[guardian1_state, guardian2_state, guardian3_state],
            2,
        )
        .unwrap();

    // Create a different backup to get an invalid share
    let other_backup = other_owner
        .backup(
            &mut rng,
            &TestData {
                value: "different data".to_string(),
            },
            Metadata::new("Other Backup".to_string(), "Different backup".to_string()),
            &[other_guardian_state],
            1,
        )
        .unwrap();

    // Get valid shares
    let share1 = guardian1
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();
    let share2 = guardian2
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();
    let share3 = guardian3
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();

    // Get invalid share from different backup
    let other_share = other_guardian
        .decrypt_share_backupy(*other_owner.acc(), &other_backup)
        .unwrap();

    // Each guardian encrypts their share towards the owner
    let owner_st = owner.state(&mut rng).unwrap();
    let gs1 = share1.send(&mut rng, &owner_st).unwrap();
    let gs2 = share2.send(&mut rng, &owner_st).unwrap();
    let gs3 = share3.send(&mut rng, &owner_st).unwrap();

    // Invalid share encrypted towards other owner
    let other_owner_st = other_owner.state(&mut rng).unwrap();
    let invalid_gs = other_share.send(&mut rng, &other_owner_st).unwrap();

    // Test recovery with valid + invalid shares - should ignore invalid and succeed
    let shares_with_invalid = vec![
        gs1, invalid_gs, // This should be ignored
        gs2, gs3,
    ];

    let recovered_data: TestData = owner.recover(&backup, &shares_with_invalid).unwrap();
    assert_eq!(recovered_data, test_data);
}

#[test]
fn test_backup_share_verification() {
    let mut rng = OsRng;

    // Create accounts
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian = AccountSecrets::gen(&mut rng).unwrap();

    // Get guardian public state
    let guardian_state = guardian.state(&mut rng).unwrap();

    // Create test data
    let test_data = TestData {
        value: "verification test".to_string(),
    };

    // Create backup
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new(
                "Verification Test".to_string(),
                "Testing share verification".to_string(),
            ),
            &[guardian_state],
            1,
        )
        .unwrap();

    // Guardian decrypts their share
    let share = guardian
        .decrypt_share_backupy(*owner.acc(), &backup)
        .unwrap();

    // Guardian encrypts their share towards the owner
    let owner_st = owner.state(&mut rng).unwrap();
    let gs = share.send(&mut rng, &owner_st).unwrap();

    // Verify the guardian share against the backup
    let _share_id = backup.verify(&gs).unwrap();

    // Test recovery with the verified share
    let recovered_data: TestData = owner.recover(&backup, &[gs]).unwrap();
    assert_eq!(recovered_data, test_data);
}
