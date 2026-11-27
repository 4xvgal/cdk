use cdk_common::bitcoin::hashes::{ripemd160, sha256, Hash};

const OP_SIZE: u8 = 0x82;
const OP_EQUAL: u8 = 0x87;
const OP_IF: u8 = 0x63;
const OP_HASH160: u8 = 0xa9;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_ELSE: u8 = 0x67;
const OP_DROP: u8 = 0x75;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
const OP_ENDIF: u8 = 0x68;
const OP_CHECKSIG: u8 = 0xac;

fn take_opcode(script: &[u8], cursor: &mut usize) -> Option<u8> {
    let opcode = *script.get(*cursor)?;
    *cursor += 1;
    Some(opcode)
}

fn take_push<'a>(script: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
    if take_opcode(script, cursor)? != u8::try_from(len).ok()? {
        return None;
    }

    let data = script.get(*cursor..*cursor + len)?;
    *cursor += len;
    Some(data)
}

fn take_pubkey(script: &[u8], cursor: &mut usize) -> Option<()> {
    let pubkey = take_push(script, cursor, 33)?;

    matches!(pubkey.first()?, 0x02 | 0x03).then_some(())
}

/// HASH160 of the preimage committed to by a swap lockup script
///
/// The script is the Electrum swap HTLC template: a size-checked claim branch
/// keyed by HASH160 of the preimage, and a locktime-guarded refund branch. Only
/// the committed hash is returned; the keys, the locktime and the branch layout
/// must match the template exactly.
pub fn swap_script_hash160(script: &[u8]) -> Option<[u8; 20]> {
    let mut cursor = 0;

    if take_opcode(script, &mut cursor)? != OP_SIZE {
        return None;
    }
    if take_push(script, &mut cursor, 1)? != [32] {
        return None;
    }
    if take_opcode(script, &mut cursor)? != OP_EQUAL {
        return None;
    }
    if take_opcode(script, &mut cursor)? != OP_IF {
        return None;
    }
    if take_opcode(script, &mut cursor)? != OP_HASH160 {
        return None;
    }

    let committed: [u8; 20] = take_push(script, &mut cursor, 20)?.try_into().ok()?;

    if take_opcode(script, &mut cursor)? != OP_EQUALVERIFY {
        return None;
    }
    take_pubkey(script, &mut cursor)?;
    if take_opcode(script, &mut cursor)? != OP_ELSE {
        return None;
    }
    if take_opcode(script, &mut cursor)? != OP_DROP {
        return None;
    }

    let locktime_len = usize::from(*script.get(cursor)?);

    if !(1..=4).contains(&locktime_len) {
        return None;
    }
    take_push(script, &mut cursor, locktime_len)?;

    if take_opcode(script, &mut cursor)? != OP_CHECKLOCKTIMEVERIFY {
        return None;
    }
    if take_opcode(script, &mut cursor)? != OP_DROP {
        return None;
    }
    take_pubkey(script, &mut cursor)?;
    if take_opcode(script, &mut cursor)? != OP_ENDIF {
        return None;
    }
    if take_opcode(script, &mut cursor)? != OP_CHECKSIG {
        return None;
    }
    if cursor != script.len() {
        return None;
    }

    Some(committed)
}

/// `true` when `script` is a swap lockup script that pays the preimage of
/// `payment_hash`
pub fn commits_to_payment_hash(script: &[u8], payment_hash: &[u8; 32]) -> bool {
    swap_script_hash160(script)
        .is_some_and(|committed| committed == ripemd160::Hash::hash(payment_hash).to_byte_array())
}

/// P2WSH output script of a lockup redeem script
pub fn p2wsh_script_pubkey(script: &[u8]) -> Vec<u8> {
    let mut script_pubkey = vec![0x00, 0x20];
    script_pubkey.extend_from_slice(sha256::Hash::hash(script).as_byte_array());
    script_pubkey
}

/// Preimage revealed by `witness` for `payment_hash`, if any
pub fn extract_preimage(witness: &[Vec<u8>], payment_hash: &[u8; 32]) -> Option<[u8; 32]> {
    for item in witness {
        let Ok(preimage) = <[u8; 32]>::try_from(item.as_slice()) else {
            continue;
        };

        if &sha256::Hash::hash(&preimage).to_byte_array() == payment_hash {
            return Some(preimage);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use cdk_common::util::hex;

    use super::*;

    const FIXTURE_SCRIPT: &str = "8201208763a914ea4beb47def8492389a1e16634795441e1b8724588210311111111111111111111111111111111111111111111111111111111111111116775022003b1752102222222222222222222222222222222222222222222222222222222222222222268ac";
    const FIXTURE_SCRIPT_PUBKEY: &str =
        "00205c08ce7f0119994146220382364ac736998456dfe0c420fe52fdae2b34642a07";
    const FIXTURE_HASH160: &str = "ea4beb47def8492389a1e16634795441e1b87245";
    const FIXTURE_PAYMENT_HASH: &str =
        "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd";
    const FIXTURE_PREIMAGE: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn script() -> Vec<u8> {
        hex::decode(FIXTURE_SCRIPT).expect("fixture script")
    }

    fn payment_hash() -> [u8; 32] {
        hex::decode(FIXTURE_PAYMENT_HASH)
            .expect("fixture hash")
            .try_into()
            .expect("32-byte hash")
    }

    fn preimage() -> Vec<u8> {
        hex::decode(FIXTURE_PREIMAGE).expect("fixture preimage")
    }

    #[test]
    fn swap_template_commits_to_its_hash160() {
        assert_eq!(
            swap_script_hash160(&script()).map(hex::encode),
            Some(FIXTURE_HASH160.to_string())
        );
    }

    #[test]
    fn swap_template_commits_to_the_payment_hash_preimage() {
        assert!(commits_to_payment_hash(&script(), &payment_hash()));
        assert!(!commits_to_payment_hash(&script(), &[7u8; 32]));
    }

    #[test]
    fn p2wsh_script_pubkey_hashes_the_redeem_script() {
        assert_eq!(
            hex::encode(p2wsh_script_pubkey(&script())),
            FIXTURE_SCRIPT_PUBKEY
        );
    }

    #[test]
    fn claim_witness_reveals_the_preimage() {
        let witness = vec![vec![0x30; 71], preimage(), script()];

        assert_eq!(
            extract_preimage(&witness, &payment_hash()),
            Some(payment_hash_preimage())
        );
    }

    fn payment_hash_preimage() -> [u8; 32] {
        preimage().try_into().expect("32-byte preimage")
    }

    #[test]
    fn witness_without_the_preimage_reveals_nothing() {
        let refund = vec![vec![0x30; 71], Vec::new(), script()];

        assert_eq!(extract_preimage(&refund, &payment_hash()), None);
        assert_eq!(extract_preimage(&[], &payment_hash()), None);
        assert_eq!(
            extract_preimage(&[preimage()], &[7u8; 32]),
            None,
            "a preimage of another hash is not accepted"
        );
    }

    #[test]
    fn rejected_scripts_are_not_swap_templates() {
        let script = script();
        let mut wrong_size = script.clone();
        wrong_size[2] = 31;
        let mut wrong_template = script.clone();
        wrong_template[4] = OP_ELSE;
        let mut trailing = script.clone();
        trailing.push(OP_CHECKSIG);
        let mut bad_pubkey = script.clone();
        bad_pubkey[29] = 0x04;
        let mut huge_locktime = script.clone();
        huge_locktime[64] = 5;

        for (name, candidate) in [
            ("empty", Vec::new()),
            ("wrong preimage size", wrong_size),
            ("wrong opcode", wrong_template),
            ("trailing bytes", trailing),
            ("uncompressed claim key", bad_pubkey),
            ("five-byte locktime", huge_locktime),
            ("truncated", script[..script.len() - 1].to_vec()),
        ] {
            assert_eq!(swap_script_hash160(&candidate), None, "{name}");
            assert!(
                !commits_to_payment_hash(&candidate, &payment_hash()),
                "{name}"
            );
        }
    }
}
