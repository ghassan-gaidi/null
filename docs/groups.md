# Groups — Null-MLS (TreeKEM)

> Status: library + tests only — no `null` CLI surface yet. The API below
> is exercised by tests and `xtask`, not by any shipped binary.

Group messaging uses a real ratchet tree with post-quantum node keys:
**MLS-shaped, not RFC 9420-conformant** — no interop claim is made. The
implementation is `crates/null-group/src/lib.rs` (1203 lines) +
`tree.rs` (636 lines).

## 1. Tree structure

- Complete binary tree in heap indexing: root = 0, `parent`, `left_child`,
  `right_child`, `sibling` are pure index arithmetic (`tree.rs`).
- Leaves hold members; **internal nodes hold ML-KEM-1024 keypairs** derived
  deterministically from path secrets with HKDF-SHA384:

  | Label | Output |
  |---|---|
  | `null-mls-node` | 64 B node secret |
  | `null-mls-path` | 32 B path secret |
  | `null-mls-root` | 48 B group tree secret |

- Path secrets are sealed to the sibling subtree's **resolution** (the
  minimal non-blank cover), so a commit costs **O(log n) encapsulations**
  — proven by test: depth-3 tree (8 members), a commit ships ≤ 3 bundles,
  versus 8 one-per-member in a fan-out design.

## 2. Group operations

### Create
`Group::create` picks a random 32-byte group id, builds `RatchetTree::single()`
(creator at leaf 0).

### Add (invite)
- Rejects the membership cap (`MAX_GROUP_MEMBERS = 50000`, "group full")
  and duplicate members; grows the tree when full.
- The committer refreshes its direct path and builds a `TreeCommit`;
  the joiner receives a **Welcome** sealed to its KeyPackage ek:
  `secret(48) ‖ npath(u32) ‖ [(idx u32, seed 64)…]`, wrapped with Kyber
  encapsulation + ChaCha20-Poly1305 (`null-mls-welcome-wrap`).
- The joiner's exclusive branch nodes stay **blank until its first update**
  (TreeKEM invariant; commented in code).

### Remove (eject)
- Cannot remove self via commit ("delete local state to leave").
- Blanks the removed leaf **and** the off-path nodes on the removed
  member's path; resolutions route around blanks — remaining members get
  post-compromise security immediately.
- The removed member goes **defunct**: all its operations fail loudly
  ("removed from group") and its tree secret zeroizes.

### Update (PCS / key refresh)
- Path refresh, no membership change, epoch bump — the standard
  "self-healing" commit.

## 3. Commit validation (`process_commit`) — why forks die

In strict order:

1. Group id must match.
2. Redelivery of your *own* commit is idempotent only at the same epoch.
3. Epoch must be exactly `self.epoch + 1` (stale-commit rejection).
4. `prev_hash == epoch_hash(tree_secret, epoch)` — otherwise
   **"commit does not chain to current epoch (fork or gap)"**.
5. Tree grows to the declared depth (never regresses).
6. Duplicate adds are rejected.
7. Self-removal → zeroize + defunct.

Fork/gap/replay rejection is tested (tampered `prev_hash` fails chaining;
removed member blocked; premature epoch refused).

## 4. Joining (`join`)

`join(env, member_id, dk)` decapsulates the Welcome ciphertext with the
joiner's long-term Kyber dk, opens exactly `52 + npath*68` bytes, rebuilds
the tree at the declared depth, adopts the path seeds, and keeps its own
leaf key until the first update. **Roster, tree, and path arrive
together** — TOFU by necessity, which is stated rather than hidden.

## 5. Message encryption in groups

Per-sender chains (not a group-wide chain):

```
message_key = HKDF(tree_secret, salt = group_id,
                   info = sender_member_id ‖ seq(8 BE) ‖ epoch(8 BE))
```

Recipients prune their per-sender chains when a committer refreshes paths,
so committers and receivers stay sequence-aligned across commits.

## 6. Wire-format guards (malicious-commit DoS)

- **Depth cap**: `TreeCommit::decode` and `WelcomePkg::decode` reject
  `depth > 20` ("absurd tree depth"). Real 50k-member trees only need
  depth 16; 20 is generous headroom. Without this, a crafted commit could
  force allocation at 2^31 leaves (OOM) or shift-overflow.
- Counters capped on the wire: `adds`/`removes` ≤ `50000`, and
  `blanked`/`updated`/`bundles` each ≤ `1 << 20`.
- Envelope version byte `0x02` on both `TreeCommit` and `WelcomePkg`.

## 7. Limits and non-claims

- Up to `50000` members (the MLS protocol limit).
- MLS-*shaped*: same ideas as RFC 9420 (ratchet trees, resolutions,
  epoch chaining) but a different wire format; **no interop with MLS
  implementations**.
- Availability is **not** claimed against a malicious insider: a committer
  can always withhold commits (deny service). Security properties
  (confidentiality, PCS on removal, fork rejection) still hold.
- Group state is memory-only; a defunct member's group state zeroizes on
  drop.

## 8. Test provenance

- `commit_cost_is_sublinear`: 8 members, ≤ 3 bundles per commit —
  the O(log n) claim.
- `commit_with_absurd_depth_rejected`: depth 21 refused at decode; depth
  20 passes the guard.
- Fork/gap/replay, removal-defunct, welcome-join roundtrips, epoch
  chaining, multi-committer convergence — all in `crates/null-group`.

## 9. Relationship to the rest of the stack

- Group node keys come from `null-crypto`'s deterministic Kyber keygen
  (same FIPS 203 instantiation as the handshake).
- Group messages ride the same 2048-byte frame layer + transport
  multiplexer as 1:1 sessions.
- Multi-device groups: member ids are `SHA3-256("Null-v2.0-device-member:"
  ‖ fingerprint ‖ device_id)`; revocation of a device revokes the member
  slot it occupies (`docs/multidevice.md`).
- The Tamarin models do **not** cover groups (stated out of scope in
  `model/README.md`); group properties are chaos-tested, not machine-proved.