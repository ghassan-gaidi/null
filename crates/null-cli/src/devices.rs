//! Device roster CLI (Task 6a): pipe-oriented verbs over
//! `null-identity::DeviceSet` — enroll, revoke, list, active (fan-out
//! set), member-id. Carries no secrets (eks are public); same stdio
//! conventions as the group surface (`super::blob`).

use anyhow::Result;
use null_identity::{device_member_id, DeviceSet};

use super::blob::{b64_decode, b64_encode, grp, hex_encode, read_blob};
use super::DevicesCmd;

fn parse_id16(s: &str) -> Result<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("device id must be 32 hex chars");
    }
    let mut id = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        id[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    Ok(id)
}

fn print_set(label: &str, set: &DeviceSet) {
    println!("{label}:{}", b64_encode(&set.encode()));
}

fn load_set(arg: &Option<String>) -> Result<DeviceSet> {
    grp(DeviceSet::decode(&read_blob(arg)?), "roster")
}

pub async fn dispatch(cmd: DevicesCmd) -> Result<()> {
    match cmd {
        DevicesCmd::Enroll {
            set,
            fp,
            device,
            ek,
        } => {
            let mut roster = match set {
                Some(_) => {
                    let s = load_set(&set)?;
                    if let Some(want) = fp {
                        if s.identity_fp() != want {
                            anyhow::bail!("fingerprint mismatch: roster is for another identity");
                        }
                    }
                    s
                }
                None => {
                    let want = fp.ok_or_else(|| {
                        anyhow::anyhow!("fresh roster needs --fp (identity fingerprint)")
                    })?;
                    DeviceSet::new(want)
                }
            };
            let id = parse_id16(&device)?;
            let ek_bytes = b64_decode(&ek)?;
            grp(roster.add_device(id, ek_bytes), "enroll")?;
            print_set("SET", &roster);
        }
        DevicesCmd::Revoke { set, device } => {
            let mut roster = load_set(&set)?;
            let id = parse_id16(&device)?;
            grp(roster.revoke(&id), "revoke")?;
            print_set("SET", &roster);
        }
        DevicesCmd::List { set } => {
            let roster = load_set(&set)?;
            for (id, info) in roster.all_devices() {
                println!(
                    "DEVICE {} revoked={} epoch={}",
                    hex_encode(&id),
                    info.revoked,
                    info.added_epoch
                );
            }
        }
        DevicesCmd::Active { set } => {
            let roster = load_set(&set)?;
            for (id, ek) in roster.active_devices() {
                println!("ACTIVE {} {}", hex_encode(&id), b64_encode(&ek));
            }
        }
        DevicesCmd::MemberId { fp, device } => {
            let id = parse_id16(&device)?;
            let mid = device_member_id(&fp, &id);
            println!("MEMBER:{}", hex_encode(&mid));
        }
    }
    Ok(())
}
