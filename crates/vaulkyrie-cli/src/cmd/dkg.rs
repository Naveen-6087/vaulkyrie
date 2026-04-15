use clap::Subcommand;

#[derive(Subcommand)]
pub enum DkgCmd {
    /// Run a full DKG + signing ceremony (default 2-of-3)
    Sign {
        /// Message to sign (hex-encoded)
        #[arg(long)]
        message: String,
    },
    /// Run DKG + signing with custom parameters
    SignCustom {
        /// Message to sign (hex-encoded)
        #[arg(long)]
        message: String,
        #[arg(long, default_value = "2")]
        min_signers: u16,
        #[arg(long, default_value = "3")]
        max_signers: u16,
        /// Comma-separated signer IDs (e.g. "1,3")
        #[arg(long)]
        signers: String,
        /// RNG seed (hex, 32 bytes) — defaults to zeros
        #[arg(long)]
        rng_seed: Option<String>,
    },
    /// Sign a serialized Solana legacy message (built-in test message)
    LegacyMessage,
    /// Run DKG, refresh all shares, and sign with refreshed keys
    Refresh {
        /// Message to sign (hex-encoded)
        #[arg(long)]
        message: String,
    },
}

pub fn run(cmd: DkgCmd) -> Result<(), String> {
    match cmd {
        DkgCmd::Sign { message } => {
            let msg = hex::decode(&message).map_err(|e| format!("invalid hex message: {e}"))?;
            let report = vaulkyrie_sdk::frost::dkg_sign(&msg)
                .map_err(|e| format!("DKG signing failed: {e:?}"))?;
            print_report(&report);
            Ok(())
        }
        DkgCmd::SignCustom {
            message,
            min_signers,
            max_signers,
            signers,
            rng_seed,
        } => {
            let msg = hex::decode(&message).map_err(|e| format!("invalid hex message: {e}"))?;
            let signing_participants: Vec<u16> = signers
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse()
                        .map_err(|e| format!("invalid signer id: {e}"))
                })
                .collect::<Result<_, _>>()?;

            let seed = match rng_seed {
                Some(s) => {
                    let bytes =
                        hex::decode(&s).map_err(|e| format!("invalid hex rng_seed: {e}"))?;
                    if bytes.len() != 32 {
                        return Err("rng_seed must be 32 bytes".into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                None => [0u8; 32],
            };

            let config = vaulkyrie_sdk::frost::HarnessConfig {
                min_signers,
                max_signers,
                signing_participants,
                rng_seed: seed,
            };
            let report = vaulkyrie_sdk::frost::dkg_sign_with_config(&msg, &config)
                .map_err(|e| format!("DKG signing failed: {e:?}"))?;
            print_report(&report);
            Ok(())
        }
        DkgCmd::LegacyMessage => {
            let report = vaulkyrie_sdk::frost::dkg_sign_legacy_message()
                .map_err(|e| format!("legacy message signing failed: {e:?}"))?;
            println!("Legacy message signing succeeded:");
            println!("  message_bytes: {} bytes", report.message_bytes.len());
            print_report(&report.report);
            Ok(())
        }
        DkgCmd::Refresh { message } => {
            let msg = hex::decode(&message).map_err(|e| format!("invalid hex message: {e}"))?;
            let report = vaulkyrie_sdk::frost::dkg_refresh_and_sign(&msg)
                .map_err(|e| format!("refresh signing failed: {e:?}"))?;
            println!("Share refresh succeeded:");
            println!(
                "  original_group_key:  {}",
                hex::encode(report.original_group_public_key)
            );
            println!(
                "  refreshed_group_key: {}",
                hex::encode(report.refreshed_group_public_key)
            );
            let keys_match = report.original_group_public_key == report.refreshed_group_public_key;
            println!("  keys_match: {keys_match}");
            println!("  signature:  {}", hex::encode(report.signature));
            println!("  signer_set: {:?}", report.signer_set);
            Ok(())
        }
    }
}

fn print_report(report: &vaulkyrie_sdk::frost::HarnessReport) {
    println!("DKG + Signing report:");
    println!(
        "  group_public_key: {}",
        hex::encode(&report.group_public_key)
    );
    println!("  signature:        {}", hex::encode(&report.signature));
    println!("  signer_set:       {:?}", report.signer_set);
}
