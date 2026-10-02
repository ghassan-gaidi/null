//! Group messaging CLI (Task 5b): pipe-oriented membership verbs over
//! `null-group`. State travels as base64 on stdio (args or stdin) and
//! lives in pipes/shell vars — RAM only, never disk (state blobs carry
//! path seeds + possibly the leaf dk; see `docs/groups.md` §7).
//!
//! Convention: `--state` is optional everywhere (absent = read stdin);
//! every other blob is a required arg. Blobs print as `LABEL:base64` on
//! stdout (scriptable); human chatter goes to stderr.

use anyhow::Result;
use null_crypto::KyberKeypair;
use null_group::{Group, KeyPackage};

use super::GroupCmd;

use super::blob::{b64_decode, b64_encode, grp, hex_encode, read_blob};

fn parse_id32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("member id must be 64 hex chars");
    }
    let mut id = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        id[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    Ok(id)
}

fn print_state(label: &str, g: &Group) {
    println!("{label}:{}", b64_encode(&g.encode_state()));
}

fn random_id() -> [u8; 32] {
    use rand::RngCore;
    let mut id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

pub async fn dispatch(cmd: GroupCmd) -> Result<()> {
    match cmd {
        GroupCmd::Create => {
            let g = Group::create();
            let roster = g.roster();
            if roster.len() != 1 {
                anyhow::bail!("fresh group must hold exactly its creator");
            }
            print_state("STATE", &g);
            println!("MEMBER:{}", hex_encode(&roster[0].0));
        }
        GroupCmd::Keygen { member_id } => {
            let id = match member_id {
                Some(s) => parse_id32(&s)?,
                None => random_id(),
            };
            let kp = KyberKeypair::generate();
            let pkg = KeyPackage {
                member_id: id,
                kyber_ek: kp.ek_bytes(),
                signature_hint: None,
            };
            println!("MEMBER:{}", hex_encode(&id));
            println!("KEYPACKAGE:{}", b64_encode(&pkg.encode()));
            println!("DK:{}", b64_encode(&kp.dk_bytes()));
        }
        GroupCmd::Join {
            welcome,
            keypackage,
            dk,
            member_id,
        } => {
            let w = b64_decode(&welcome)?;
            let kp = grp(KeyPackage::decode(&b64_decode(&keypackage)?), "keypackage")?;
            let pair = grp(
                KyberKeypair::from_parts(&kp.kyber_ek, &b64_decode(&dk)?),
                "keypair",
            )?;
            let id = parse_id32(&member_id)?;
            if id != kp.member_id {
                anyhow::bail!("member id does not match keypackage");
            }
            let g = grp(Group::join(&w, id, &pair), "join")?;
            print_state("STATE", &g);
        }
        GroupCmd::Info { state } => {
            let g = grp(Group::decode_state(&read_blob(&state)?), "state")?;
            let info = g.info();
            println!(
                "INFO group={} epoch={} members={}",
                hex_encode(&info.group_id),
                info.epoch,
                g.member_count()
            );
        }
        GroupCmd::Roster { state } => {
            let g = grp(Group::decode_state(&read_blob(&state)?), "state")?;
            for (id, pos) in g.roster() {
                println!("ROSTER {} {pos}", hex_encode(&id));
            }
        }
        GroupCmd::Add { state, keypackage } => {
            let mut g = grp(Group::decode_state(&read_blob(&state)?), "state")?;
            let kp = grp(KeyPackage::decode(&b64_decode(&keypackage)?), "keypackage")?;
            let (welcome, commit) = grp(g.add(kp), "add")?;
            println!("COMMIT:{}", b64_encode(&commit));
            println!("WELCOME:{}", b64_encode(&welcome));
            print_state("STATE", &g);
        }
        GroupCmd::Remove { state, member_id } => {
            let mut g = grp(Group::decode_state(&read_blob(&state)?), "state")?;
            let id = parse_id32(&member_id)?;
            let commit = grp(g.remove(&id), "remove")?;
            println!("COMMIT:{}", b64_encode(&commit));
            print_state("STATE", &g);
        }
        GroupCmd::Update { state } => {
            let mut g = grp(Group::decode_state(&read_blob(&state)?), "state")?;
            let commit = grp(g.update(), "update")?;
            println!("COMMIT:{}", b64_encode(&commit));
            print_state("STATE", &g);
        }
        GroupCmd::Sync { state, commit } => {
            let mut g = grp(Group::decode_state(&read_blob(&state)?), "state")?;
            grp(g.process_commit(&b64_decode(&commit)?), "sync")?;
            print_state("STATE", &g);
        }
        GroupCmd::Send {
            state,
            sender,
            message,
        } => {
            if message.is_none() && state.is_none() {
                anyhow::bail!(
                    "--message and --state cannot both come from stdin; pass one explicitly"
                );
            }
            let mut g = grp(Group::decode_state(&read_blob(&state)?), "state")?;
            let id = parse_id32(&sender)?;
            let pt = match message {
                Some(m) => m.into_bytes(),
                None => {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                    buf.into_bytes()
                }
            };
            let pkg = grp(g.pack_message(&id, &pt), "send")?;
            println!("PACKAGE:{}", b64_encode(&pkg));
            print_state("STATE", &g);
        }
        GroupCmd::Recv { state, package } => {
            let mut g = grp(Group::decode_state(&read_blob(&state)?), "state")?;
            let pkg = read_blob(&package)?;
            let (from, pt) = grp(g.unpack_message(&pkg), "recv")?;
            println!("FROM:{}", hex_encode(&from));
            println!("MESSAGE:{}", b64_encode(&pt));
            print_state("STATE", &g);
        }
    }
    Ok(())
}
