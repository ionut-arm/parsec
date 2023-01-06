// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{utils, Provider};
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use crate::utils::config::{PcrHashAlgType, TpmRotConfig};
use ciborium::{cbor, ser::into_writer};
use log::error;
use parsec_interface::operations::psa_algorithm::Hash;
use parsec_interface::operations::{attest_key, list_attestation_metadata};
use parsec_interface::requests::{ResponseStatus, Result};
use serde_bytes::Bytes;
use std::convert::TryFrom;
use tss_esapi::constants::TpmFormatOneError;
use tss_esapi::error::TpmResponseCode;
use tss_esapi::structures::{PcrSelectionListBuilder, PcrSlot};
use tss_esapi::{abstraction::transient::ObjectWrapper, structures::Auth};
use tss_esapi::{Error, ReturnCode};

impl Provider {
    pub(super) fn attest_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: attest_key::Operation,
    ) -> Result<attest_key::Result> {
        let attest_key::Operation {
            attested_key_name,
            nonce,
            attesting_key_name,
        } = op;

        if attesting_key_name.is_some() {
            error!("Attesting with a non-default key is currently not supported");
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        // Prepare attested key
        let attested_key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            attested_key_name,
        );
        let attested_key_pass_context = self.get_key_ctx(&attested_key_identity)?;
        let attested_key_attributes = self
            .key_info_store
            .get_key_attributes(&attested_key_identity)?;
        let attested_key_params = utils::parsec_to_tpm_params(attested_key_attributes)?;
        let attested_key_auth = Some(
            Auth::try_from(attested_key_pass_context.auth_value().to_vec())
                .map_err(utils::to_response_status)?,
        );
        let attested_key = ObjectWrapper {
            material: attested_key_pass_context.key_material().clone(),
            auth: attested_key_auth,
            params: attested_key_params,
        };

        // Prepare attesting key
        let attesting_key_identity = KeyIdentity::new(
            ApplicationIdentity::new_internal(String::from("tpm-provider")),
            self.provider_identity.clone(),
            String::from("aik"),
        );
        let attesting_key_pass_context = self.get_key_ctx(&attesting_key_identity)?;
        let attesting_key_attributes = self
            .key_info_store
            .get_key_attributes(&attesting_key_identity)?;
        let attesting_key_params = utils::parsec_to_tpm_params(attesting_key_attributes)?;
        let attesting_key_auth = Some(
            Auth::try_from(attesting_key_pass_context.auth_value().to_vec())
                .map_err(utils::to_response_status)?,
        );
        let attesting_key = ObjectWrapper {
            material: attesting_key_pass_context.key_material().clone(),
            auth: attesting_key_auth,
            params: attesting_key_params,
        };

        let mut esapi_context = self
            .esapi_context
            .lock()
            .expect("ESAPI Context lock poisoned");

        let pcr_selection_list = match self.root_of_trust.clone() {
            None => {
                error!("TPM RoT not configured");
                return Err(ResponseStatus::PsaErrorGenericError);
            }
            Some(TpmRotConfig {
                pcr_list: Some(pcr_list),
                pcr_hash_alg: Some(pcr_hash_alg),
            }) => {
                if pcr_list.iter().any(|value| *value > 31) {
                    error!("PCR index invalid in TPM RoT config");
                    return Err(ResponseStatus::PsaErrorGenericError);
                }
                PcrSelectionListBuilder::new()
                    .with_selection(
                        pcr_hash_alg.into(),
                        &pcr_list
                            .iter()
                            .map(|pcr_slot| PcrSlot::try_from(1_u32 << pcr_slot).unwrap())
                            .collect::<Vec<PcrSlot>>(),
                    )
                    .build()
                    .map_err(|e| {
                        format_error!("Failed to create PcrSelectionList", e);
                        key_attest_response_status(e)
                    })?
            }
            _ => {
                error!("TPM attestation invalidly configured (some of the required elements are missing)");
                return Err(ResponseStatus::PsaErrorGenericError);
            }
        };

        let key_statement = esapi_context
            .certify(attested_key.clone(), attesting_key, nonce.clone())
            .map_err(|e| {
                format_error!("Failed to certify", e);
                key_attest_response_status(e)
            })?;

        let platform_statement = esapi_context
            .quote(attested_key, nonce, pcr_selection_list)
            .map_err(|e| {
                format_error!("Failed to quote", e);
                key_attest_response_status(e)
            })?;

        let key_token = key_statement.encode().map_err(|e| {
            format_error!("Failed to encode key attestation token", e);
            key_attest_response_status(e)
        })?;
        let platform_token = platform_statement.encode().map_err(|e| {
            format_error!("Failed to encode platform attestation token", e);
            key_attest_response_status(e)
        })?;
        let mut attestation_token = vec![];
        match cbor!({
            265 => "tag:github.com/parallax-second/key-attestation,2022-11-04",
            "kat" => &Bytes::new(&key_token[..]),
            "pat" => &Bytes::new(&platform_token[..]),
        }) {
            // Serialize CAB
            Ok(value) => match into_writer(&value, &mut attestation_token) {
                Ok(_) => (),
                Err(_) => return Err(ResponseStatus::PsaErrorGenericError),
            },
            Err(_) => return Err(ResponseStatus::PsaErrorGenericError),
        }

        Ok(attest_key::Result {
            attestation_token: attestation_token.into(),
        })
    }

    pub(super) fn list_attestation_metadata_internal(
        &self,
    ) -> Result<list_attestation_metadata::Result> {
        match self.root_of_trust.clone() {
            None => Ok(list_attestation_metadata::Result {
                attestation_metadata: Vec::new(),
            }),
            Some(TpmRotConfig {
                pcr_list: Some(pcr_list),
                pcr_hash_alg: Some(pcr_hash_alg),
            }) => {
                // Prepare attesting key
                let attesting_key_identity = KeyIdentity::new(
                    ApplicationIdentity::new_internal(String::from("tpm-provider")),
                    self.provider_identity.clone(),
                    String::from("aik"),
                );
                let attesting_key_pass_context = self.get_key_ctx(&attesting_key_identity)?;
                let attesting_key_attributes = self
                    .key_info_store
                    .get_key_attributes(&attesting_key_identity)?;
                let pcr_hash = match pcr_hash_alg {
                    PcrHashAlgType::Sha256 => Hash::Sha256,
                };

                Ok(list_attestation_metadata::Result {
                    attestation_metadata: vec![
                        list_attestation_metadata::AttestationMetadata::Tpm {
                            ak_attributes: attesting_key_attributes,
                            ak_public: utils::pub_key_to_bytes(
                                attesting_key_pass_context.key_material().public().clone(),
                                attesting_key_attributes,
                            )?
                            .into(),
                            pcr_list,
                            pcr_hash,
                        },
                    ],
                })
            }
            _ => {
                error!("TPM RoT invalidly configured (some of the required elements are missing)");
                Err(ResponseStatus::PsaErrorGenericError)
            }
        }
    }
}

fn key_attest_response_status(error: Error) -> ResponseStatus {
    match error {
        Error::TssError(e) => match e {
            ReturnCode::Tpm(TpmResponseCode::FormatOne(err))
                if err.error_number() == TpmFormatOneError::BadAuth =>
            {
                error!("Wrong authentication value for attesting key");
                ResponseStatus::PsaErrorGenericError
            }
            ReturnCode::Tpm(TpmResponseCode::FormatOne(err))
                if err.error_number() == TpmFormatOneError::Value =>
            {
                error!("Wrong parameter value for key attestation");
                ResponseStatus::PsaErrorInvalidArgument
            }
            ReturnCode::Tpm(TpmResponseCode::FormatOne(err))
                if err.error_number() == TpmFormatOneError::Size =>
            {
                error!("Wrong parameter size for key attestation");
                ResponseStatus::PsaErrorInvalidArgument
            }
            _ => utils::to_response_status(error),
        },
        _ => utils::to_response_status(error),
    }
}
