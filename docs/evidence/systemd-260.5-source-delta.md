# systemd v260.5 source delta from audited v260.2 (#444)

This is the ADR-087 gate 5 source review for the systemd build in the pinned
NixOS 26.05 closure of `deploy/nixos/flake.lock`. It covers mountfsd, image
policy and systemd-repart, plus the shared code they reach. The QEMU TCG
evidence lane in `.github/workflows/qemu-closure-evidence.yml` records the same
build at run time. ADR-087 §5 says that any systemd patch-level change makes
earlier runtime evidence invalid until this review and the evidence are
repeated.

## Result

- The packaged version is **v260.5**, not the v260.4 that ADR-087 §5 names
  as "currently". nixos-26.05 moved to v260.5 before the pinned revision.
- `src/mountfsd/`, `src/shared/image-policy.{c,h}`, `src/basic/proc-cmdline.c`,
  `src/basic/constants.h`, `src/shared/varlink-io.systemd.MountFileSystem.c`
  and both mountfsd units are byte-identical in v260.2 and v260.5. Every
  ADR-087 citation into these files (A.1, [A28], [A30], [A31], [A33], [A35])
  still holds, at the same line numbers.
- The functions that ADR-087 Part C.3 relies on in `src/shared/dissect-image.c`
  are byte-identical: `acquire_sig_for_roothash()`,
  `image_policy_check_protection()`, `verity_can_reuse()`,
  `validate_signature_userspace()`, `do_crypt_activate_verity()` and
  `verity_partition()`. Their line numbers moved (see "Line map").
- No commit changes the effective-policy intersection (Part A.1), the
  `systemd.allow_userspace_verity` reader (Part C.3), the `verity.d` search
  path, the verity-sharing override or the signature-partition parser
  (Part B.4).
- Three commits change code that a `MountImage` call reaches. None changes an
  accepted ADR-087 decision. They are listed below with their effect on the
  #444 evidence.
- One manual-page commit documents that mountfsd trusts the kernel's GPT parser.
  ADR-087 already compares the GPT set on the provider side.
- One nixpkgs patch adds a fifth `verity.d` directory. The evidence lane
  records it.

No finding blocks ADR-087 gate 5. The privileged `MountImage` cases (#444
part b) and the cleanup and restart cases (part c) still have to pass on this
build.

## Identity

| Item | Value |
|---|---|
| nixpkgs | `nixos-26.05` at `f1e5c356f35d07e7b71a6b5e6c9338e0b029e0c0` (2026-11-13), narHash `sha256-qXFIqA6FCcx7XeDzw0ZNlkDT9UiCzrNDwK8RuU8RcHM=` |
| systemd package | `pkgs/os-specific/linux/systemd/default.nix`: `version = "260.5"`, `fetchFromGitHub` `systemd/systemd` `rev = "v260.5"`, `hash = "sha256-QLQad4pKkaf99k+ABOaooKi5TSX0iHH9XtMn/fy1rfE="` |
| Audited base | tag `v260.2`, commit `f1d0952a125b96b7ab2f1ff29a87448ade8ac29b` |
| Packaged source | tag `v260.5`, commit `84ff4f0dff41c26472cd48c4c4955c2d77f5ac08` (2026-09-10) |
| Intermediate tags | `v260.3` `7bb0511adaba8e447d53df9b10c70ef6299fbd36`, `v260.4` `ad47ad9cee96df6bb955eef20d6fa2443b235500` |
| Commits | 574 from v260.2 to v260.5: 158 in v260.2..v260.3, 227 in v260.3..v260.4 and 189 in v260.4..v260.5 |
| Build options | nixpkgs leaves the meson options `mountfsd` and `default-mountfsd-trusted-directories` at their defaults (enabled, and `false`) |

Git blob identities in both tags:

| Path | Blob |
|---|---|
| `src/mountfsd/` (tree) | `381f4386e2d37d9b4e20fe700d5b32bab1326dfa` |
| `src/mountfsd/mountwork.c` | `62b39afc871e1fa0228119406a3d4ccfb5dee947` |
| `src/shared/image-policy.c` | `59d1161d04657af195884aca0b978ce6781e6f4b` |
| `src/shared/image-policy.h` | `fe2bf0d20041a6812de7093dac24577da9c13325` |
| `src/basic/proc-cmdline.c` | `eb61b0bc554e2f8f74f7ae54fb45391a22343452` |
| `src/basic/constants.h` | `3dbffdee2633510bddb0483cef941f13a2031d75` |
| `src/shared/varlink-io.systemd.MountFileSystem.c` | `30b1faf8d7aa472274cdb3011e05f41d453e3eaf` |
| `units/systemd-mountfsd.service.in` | `1e996a0def8324ae16befeca7ecda58ce56379c5` |
| `units/systemd-mountfsd.socket` | `a3e19cc418cb5e9e6ea53adae39e93d18bd0e8a6` |

Method: `git diff`, `git log` and `git rev-parse <tag>:<path>` over a clone of
`https://github.com/systemd/systemd`, restricted to `src/mountfsd`,
`src/shared/{dissect-image,image-policy,loop-util,mount-util,cryptsetup-util,discover-image}.*`,
`src/shared/nsresource.*`, `src/nsresourced`, `src/repart`,
`src/basic/{proc-cmdline,constants,env-util,mountpoint-util,namespace-util}.*`,
`src/libsystemd/sd-varlink`, `units/` and `man/systemd-mountfsd.service.xml`. Function identity was checked by
extracting each function body from both tags.

## nixpkgs patches

nixpkgs applies six patches on top of v260.5 (`patches` in the package):

| Patch | Effect on ADR-087 |
|---|---|
| `0001-Don-t-try-to-unmount-nix-or-nix-store.patch` | Shutdown and fstab only. None. |
| `0002-Change-usr-share-zoneinfo-to-etc-zoneinfo.patch` | Time zones only. None. |
| `0003-add-rootprefix-to-lookup-dir-paths.patch` | Adds `PREFIX "/lib/" n` to `CONF_PATHS_NULSTR()` and `CONF_PATHS()` in `src/basic/constants.h`. `PREFIX` is the systemd store path, so systemd also consults `<systemd>/lib/verity.d`. ADR-087 Part C.3 names four `verity.d` directories ([A31]); the packaged build has five. The evidence collector records all five, and the checker requires each to be absent or empty. The certificate store path is immutable, so only a different systemd build can add a certificate there. |
| `0004-path-util.h-add-placeholder-for-DEFAULT_PATH_NORMAL.patch` | `$PATH` default only. None. |
| `0005-core-don-t-taint-on-unmerged-usr.patch` | Taint flags only. None. |
| `0006-timesyncd-disable-NSCD-when-DNSSEC-validation-is-dis.patch` | timesyncd only. None. |

## Commits that reach the `MountImage` path

### `eb08e6d7a21883d5a1144652e5b1f5748e077ce4` (v260.3): loop-util: shortcut block device fd when it carries no partition table

[Commit](https://github.com/systemd/systemd/commit/eb08e6d7a21883d5a1144652e5b1f5748e077ce4).
It adds `probe_partition_table()` to `dissect-image.c` and changes
`loop_device_can_shortcut()`, which reuses a block-device FD instead of
allocating a loop device. The shortcut is taken only under `S_ISBLK()` in
`loop_device_make_internal()`. mountfsd's `MountImage` passes the client's
image FD to `loop_device_make(..., LO_FLAGS_PARTSCAN, ...)`. The provider
always passes a regular file (the held SIM1 image), which takes the
`stat_verify_regular()` branch and still gets a real `loopN` device with
partition scanning. The refactor of `probe_sector_size_harder()` into
`probe_fd_open()` keeps the same behaviour for regular files. The
#440 readback's loop topology (`loopNpK`, loop `backing_file`) is unchanged
for the provider's input. #444 part (b) confirms it on the packaged closure
(owner decision Q8.4).

The same commit adds the `LOOP_DEVICE_MAY_POPULATE_PARTITION_TABLE` flag to
`loop-util.h`. It only matters for block-device input, and mountwork does not
pass it.

### `713420401df53189de820bc599a47ad1897d8e9a` (v260.4): dissect-image: don't assert() on partition geometry from blkid

[Commit](https://github.com/systemd/systemd/commit/713420401df53189de820bc599a47ad1897d8e9a).
In `dissect_image()`, a partition start or size at or above `UINT64_MAX/512`
sectors now returns `EOVERFLOW` instead of aborting on `assert()`. This is a
fail-closed hardening for a malformed GPT. The provider rejects such an image
before the call (SIM1 GPT admission, ADR-087 §2 step 1).

### `e2bd4719272e0c81ad9de851d58f750d2df50d17` (v260.5): dissect-image: tighten error path a bit

[Commit](https://github.com/systemd/systemd/commit/e2bd4719272e0c81ad9de851d58f750d2df50d17).
On a failure inside `dissected_image_decrypt()`, for example a kernel
root-hash signature rejection in `verity_partition()`, systemd now releases
the partitions' decrypted node names, file system types and mount-node FDs.
The `DecryptedImage` cleanup that deactivates the dm devices is unchanged.
This only narrows what a failed attempt leaves behind. #444 part (b) records
the failure-closure cases on this build, and part (c) records resource
absence.

### `963fd1447be548cb6acf0d7d828a3b7512fcff37` (v260.5): man: note that GPT is implicitly trusted by sd-mountfsd

[Commit](https://github.com/systemd/systemd/commit/963fd1447be548cb6acf0d7d828a3b7512fcff37).
Documentation only. `systemd-mountfsd.service(8)` now states that the kernel
parses the image's GPT and that mountfsd applies no policy or checks around
it. This matches ADR-087's design rather than changing it. The provider
compares the exact GPT set against SIM1 before the call (§2 step 1) and reads
it back after activation (§2 step 6, #440).

## Shared code with no effect on `MountImage`

| Commit (tag) | Change | Why it does not apply |
|---|---|---|
| [`606ec729dd94a63e1279d5bf39b5f5707941c783`](https://github.com/systemd/systemd/commit/606ec729dd94a63e1279d5bf39b5f5707941c783) (v260.3) | sd-varlink: disable the event source when freeing a server socket | OOM cleanup in `sd_varlink_server_listen_address()`. No protocol or reply change. |
| [`0bd9ef9e6b1a149c0b818177b00ba05df468a373`](https://github.com/systemd/systemd/commit/0bd9ef9e6b1a149c0b818177b00ba05df468a373) (v260.5) | sd-varlink: fix a memory leak on a failure path | Allocation cleanup only. |
| [`35648a7bb723f9bb0448fa580102ad1841404ace`](https://github.com/systemd/systemd/commit/35648a7bb723f9bb0448fa580102ad1841404ace) (v260.5) | sd-varlink: no disconnect callback for a connection that was never established | Server-side connection accounting. The `MountImage` call, its FD transfer and its reply are unchanged. |
| [`30debb884217b002a2ab7d97d86677020f711a9a`](https://github.com/systemd/systemd/commit/30debb884217b002a2ab7d97d86677020f711a9a), [`34e2caea8bee1ed6965c03ed73b18e17ea1c79c9`](https://github.com/systemd/systemd/commit/34e2caea8bee1ed6965c03ed73b18e17ea1c79c9) (v260.4), [`5b6a24ea78388e97cfb4ddf214ca67a9f4aac31f`](https://github.com/systemd/systemd/commit/5b6a24ea78388e97cfb4ddf214ca67a9f4aac31f) (v260.5) | mount-util: `get_sub_mounts()` and sub-mount cloning | Used by sysext and the service executor. `mountwork.c` does not call them. |
| [`5936a0ee5dff014a1f2d7d489d787a0bd264aaf6`](https://github.com/systemd/systemd/commit/5936a0ee5dff014a1f2d7d489d787a0bd264aaf6) (v260.4) | env-util: NUL-terminate the `replace_env_argv()` output | `ExecStart=` variable expansion. The upstream mountfsd unit uses none. |
| [`0b0e27bc109829c41d9a6db11b850d4649f76843`](https://github.com/systemd/systemd/commit/0b0e27bc109829c41d9a6db11b850d4649f76843) (v260.4) | cryptsetup: skip LUKS2 tokens with JSON errors | LUKS2 tokens only. SIM1 images carry no LUKS partition. |

| [`fa393cb85d808dd54f6261ca4ac38ef78823c37c`](https://github.com/systemd/systemd/commit/fa393cb85d808dd54f6261ca4ac38ef78823c37c), [`5caeb684527a196b46790684c80db13ca0f80250`](https://github.com/systemd/systemd/commit/5caeb684527a196b46790684c80db13ca0f80250) (v260.3) | namespace-util: a complete range assertion in `is_our_namespace()` and a NULL-safe log argument; other `src/basic` assertions | Assertions and logging only. |
| [`6089849fa379717ee606cdd47891938efafe6478`](https://github.com/systemd/systemd/commit/6089849fa379717ee606cdd47891938efafe6478) (v260.4), [`1248eed00864ec1ded8992b51ad6b8511afc166a`](https://github.com/systemd/systemd/commit/1248eed00864ec1ded8992b51ad6b8511afc166a) (v260.5) | `ratelimit.c` and sd-event rate limits use `CLOCK_BOOTTIME`; nsresourced no longer reads a moved-out pointer | mountfsd's worker-spawn limit (`ratelimit_below(&m->worker_ratelimit)` in `mountfsd-manager.c`) now also counts suspended time. That changes only when a new worker may start, not what a worker does. The guest has no suspend. nsresourced is not on the `MountImage` path. |

`src/shared/discover-image.c` also changed, in `image_make()` (symlinks to raw
images) and in image cloning (`machine:` commits
[`c1a735f86c9b90ed179628828537a24f63478d97`](https://github.com/systemd/systemd/commit/c1a735f86c9b90ed179628828537a24f63478d97),
[`80904271f3b11bcc94768e262e0db3ee36284342`](https://github.com/systemd/systemd/commit/80904271f3b11bcc94768e262e0db3ee36284342) and
[`03af188972c854722236ad6e136431cf75d38e70`](https://github.com/systemd/systemd/commit/03af188972c854722236ad6e136431cf75d38e70)).
`mountwork.c` uses only its unchanged `image_search_path` table, for the
trusted-directory check, which the build default disables. The evidence
checker also rejects every `SYSTEMD_MOUNTFSD_*` variable, including
`SYSTEMD_MOUNTFSD_TRUSTED_DIRECTORIES`, in mountfsd's environment.

## systemd-repart

Eight commits changed `src/repart/repart.c`. None touches salt derivation,
Verity formatting, the signature JSON or offline signing (ADR-087 [A1],
[A2], [A34]). `partition_format_verity_hash()` and
`partition_format_verity_sig()` are byte-identical in both tags.

| Commit (tag) | Change |
|---|---|
| [`3a5c0df5c9c498d2d72afc02d9060f25fb1c7439`](https://github.com/systemd/systemd/commit/3a5c0df5c9c498d2d72afc02d9060f25fb1c7439) (v260.3) | Do not set ownership when copying files into vfat or similar file systems |
| [`fca3db239dcc944defde87f6cd555c950d284f0b`](https://github.com/systemd/systemd/commit/fca3db239dcc944defde87f6cd555c950d284f0b) (v260.3) | Fix the rounding direction of `SizeMinBytes=`/`SizeMaxBytes=` |
| [`61331456436fc208e6343d6d16c3f9af84ce1d41`](https://github.com/systemd/systemd/commit/61331456436fc208e6343d6d16c3f9af84ce1d41) (v260.4) | Fix growing the partition before a free area |
| [`94300ba272412f2854f242c95e40e0fa31d15e5d`](https://github.com/systemd/systemd/commit/94300ba272412f2854f242c95e40e0fa31d15e5d) (v260.4) | Report the actual block device size in `currentSizeBytes` (Varlink) |
| [`9fae4232d9713d19ee6db1007723cd9298e1ace5`](https://github.com/systemd/systemd/commit/9fae4232d9713d19ee6db1007723cd9298e1ace5) (v260.4) | Log an allocation failure at debug level in Varlink service mode |
| [`b77ea944058865c73f14b29b113db8891ada32ed`](https://github.com/systemd/systemd/commit/b77ea944058865c73f14b29b113db8891ada32ed) (v260.4) | Skip generated files during dry runs |
| [`b580197dcb19419d321fbf4d673d1f7dc91b3ca5`](https://github.com/systemd/systemd/commit/b580197dcb19419d321fbf4d673d1f7dc91b3ca5) (v260.5) | Fix the `shallow_join_strv()` deduplication scan |
| [`17a690a16bef8d4d37b30b143c94b063142d37f8`](https://github.com/systemd/systemd/commit/17a690a16bef8d4d37b30b143c94b063142d37f8) (v260.5) | Report a failed parent directory time stamp |

The cited lines moved: `verity_salt[SHA256_DIGEST_SIZE]` stays at L421,
`.salt_size = sizeof(p->verity_salt)` moves from L5639 to L5630, the
`certificateFingerprint` pair from L5855 to L5846, and
`derive_salt(context->seed, "verity-salt", ...)` from L7265 to L7264.

## Line map for the ADR-087 `dissect-image.c` citations

Four hunks insert lines: +57 after L356, +2 near L1284, +13 after L3588 and
+5 near L3645. ADR-087 cites v260.2 lines. In v260.5:

| Item ([A27], [A32]) | v260.2 | v260.5 |
|---|---|---|
| `image_policy_check_protection()` | L389 | L446 |
| `acquire_sig_for_roothash()` | L730 | L787 |
| `verity_can_reuse()` | L3097 | L3156 |
| `validate_signature_userspace()` | L3153 | L3212 |
| `systemd.allow_userspace_verity` read, `PROC_CMDLINE_TRUE_WHEN_MISSING` | L3174 | L3233 |
| `do_crypt_activate_verity()` | L3258 | L3317 |
| `$SYSTEMD_DISSECT_VERITY_SIGNATURE` | L3274 | L3333 |
| `verity_partition()` | L3380 | L3439 |
| `$SYSTEMD_VERITY_SHARING` | L3628 | L3700 |
| `dissected_image_load_verity_sig_partition()` | L4099 | L4176 |

## Kernel and cryptsetup in the same closure

ADR-087's kernel facts cite Linux v6.12 and its cryptsetup facts cite 2.8.1.
The closure pins `linuxPackages_6_12` (6.12.117) and cryptsetup 2.8.6.

- Linux v6.12 to v6.12.117, for the ADR-087 kernel sources:
  `certs/Kconfig`, `certs/system_keyring.c`,
  `crypto/asymmetric_keys/x509_public_key.c`,
  `drivers/md/dm-verity-verify-sig.h`, `security/keys/user_defined.c`,
  `lib/hexdump.c`, `include/linux/hex.h` and `security/integrity/Kconfig` are
  identical. The changes elsewhere are:
  - `dm-verity-verify-sig.c` now rejects a repeated `root_hash_sig_key_desc`
    and returns on an invalid key (stricter);
  - `x509_cert_parser.c` checks lengths before tags and parses
    basicConstraints `CA:TRUE` strictly. The description rules of Part C.2
    are unchanged;
  - `dm-verity-target.c` changes corruption counting, adds a post-suspend
    hook and moves `STATUSTYPE_TABLE`, without changing what it emits;
  - `security/keys/` changes the keyring index hash and restriction locking;
  - `drivers/md/Kconfig` gains `MD_LINEAR`. The three dm-verity options are
    unchanged.
- cryptsetup 2.8.1 to 2.8.6: `lib/verity/verity.c` only initialises
  `dmv_flags`. `lib/libdevmapper.c` widens a keyring buffer in the dm-crypt
  table parser. `lib/setup.c` changes BITLK and integrity, not
  `_crypt_load_verity()`. The `cryptsetup:<uuid>-<name>` signature key and the
  `root_hash_sig_key_desc` table argument ([A26]) are unchanged.

## Evidence artifact provenance

Each `qemu-closure-evidence-<architecture>-<sha>` artifact is named after
`github.sha`, which is the merge commit that the `pull_request` run tests.
`host/provenance` records:

- that commit, `git rev-parse HEAD`, the pull request head and the merge
  commit's two parents (the second must be the pull request head);
- the SHA-256 of the checker, the producer script, the flake files, the module,
  the guest, the collector and the certificate.

The checker verifies these against its own checkout, so re-checking an artifact
needs the repository at the tested commit. It puts its own SHA-256 in
`checker-verdict.json`. `SHA256SUMS` hashes every file.

The manifest has no signed provenance, such as a Sigstore attestation. The
workflow runs with `contents: read` only, and attestations need
`id-token: write` and `attestations: write`. The artifact's integrity therefore
rests on GitHub's artifact storage, on the run that produced it and on the
manifest digest printed in that run's step summary.
