// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use crate::providers::mbed_crypto::key_management;
use log::error;
use parsec_interface::operations::{psa_asymmetric_decrypt, psa_asymmetric_encrypt};
use parsec_interface::requests::{ProviderID, Result};

impl Provider {
    pub(super) fn psa_asymmetric_encrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        let key_name = op.key_name.clone();

        let key_triple = KeyTriple::new(app_name, ProviderID::TrustedService, key_name);
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let key_id = key_management::get_key_id(&key_triple, &*store_handle)?;
        let salt_buff = match &op.salt {
            Some(salt) => salt.to_vec(),
            None => Vec::new(),
        };

        match self
            .context
            .asym_encrypt(key_id, op.alg, op.plaintext.to_vec(), salt_buff)
        {
            Ok(ciphertext) => Ok(psa_asymmetric_encrypt::Result {
                ciphertext: ciphertext.into(),
            }),
            Err(error) => {
                error!("Encrypt status: {}", error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_asymmetric_decrypt_internal(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::TrustedService, op.key_name.clone());
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let key_id = key_management::get_key_id(&key_triple, &*store_handle)?;
        let salt_buff = match &op.salt {
            Some(salt) => salt.to_vec(),
            None => Vec::new(),
        };

        match self
            .context
            .asym_decrypt(key_id, op.alg, op.ciphertext.to_vec(), salt_buff)
        {
            Ok(plaintext) => Ok(psa_asymmetric_decrypt::Result {
                plaintext: plaintext.into(),
            }),
            Err(error) => {
                error!("Decrypt status: {}", error);
                Err(error)
            }
        }
    }
}
