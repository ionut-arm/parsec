// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "tpm-provider")]
mod attest_key {
    use e2e_tests::auto_test_keyname;
    use e2e_tests::TestClient;
    use parsec_client::core::interface::requests::{Opcode, ResponseStatus};

    #[test]
    fn attest_key() {
        let key_name = auto_test_keyname!();
        let mut client = TestClient::new();
        let nonce = vec![88, 32];
        if !client.is_operation_supported(Opcode::AttestKey) {
            return;
        }
        client
            .generate_rsa_sign_key(key_name.clone())
            .expect("Failed to generate key");

        let _ = client
            .attest_key_default_attesting(key_name, nonce)
            .expect("Attestation failed");
    }
    #[test]
    fn attest_key_with_non_existing_key() {
        let key_name = auto_test_keyname!();
        let mut client = TestClient::new();
        let nonce = vec![88, 32];
        if !client.is_operation_supported(Opcode::AttestKey) {
            return;
        }

        assert_eq!(
            client
                .attest_key_default_attesting(key_name, nonce)
                .unwrap_err(),
            //I don't think that this is the correct error
            ResponseStatus::PsaErrorDoesNotExist
        );
    }

    #[test]
    fn attest_key_with_unsupported_key() {
        let key_name = auto_test_keyname!();
        let mut client = TestClient::new();
        let nonce = vec![88, 32];
        if !client.is_operation_supported(Opcode::AttestKey) {
            return;
        }

        client
            .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
            .expect("Failed to generate key");

        assert_eq!(
            client
                .attest_key_default_attesting(key_name, nonce)
                .unwrap_err(),
            //I don't think that this is the correct error
            ResponseStatus::PsaErrorCommunicationFailure
        );
    }

    #[test]
    fn list_attestation_metadata() {
        let client = TestClient::new();
        let attestation_metadata = client
            .list_attestation_metadata()
            .expect("failed to get RoT data");
        dbg!(attestation_metadata);
    }
}
