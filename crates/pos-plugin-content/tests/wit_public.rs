//! WIT preflight contracts through the public seam; no filesystem fixture is read.

use pos_plugin_content::{validate_plugin_wit_v1, PluginWitContentErrorV1 as Error};
use std::fmt::Write as _;

const WORLD: &[u8] = b"package pigloros:plugin@0.1.0; world community-plugin {}";

// Independent ustar fixtures, constructed without the production reader.
fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (path, source) in files {
        let mut header = [0; 512];
        let (prefix, name) = if path.len() <= 100 {
            ("", *path)
        } else {
            path.rsplit_once('/').unwrap_or(("", *path))
        };
        assert!(name.len() <= 100 && prefix.len() <= 155);
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", source.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        checksum(&mut header);
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(source);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn reheader(bytes: &mut [u8], change: impl FnOnce(&mut [u8])) {
    let header = &mut bytes[..512];
    change(header);
    checksum(header);
}

fn checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let sum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

#[test]
fn accepts_regular_ustar_files_and_both_regular_type_flags() -> Result<(), Error> {
    let mut bytes = archive(&[("main.wit", WORLD)]);
    assert_eq!(validate_plugin_wit_v1(&bytes), Ok(()));
    reheader(&mut bytes, |header| header[156] = 0);
    validate_plugin_wit_v1(&bytes)
}

#[test]
fn resolves_split_packages_and_supplied_dependencies() -> Result<(), Error> {
    assert_eq!(
        validate_plugin_wit_v1(&archive(&[
            (
                "a.wit",
                b"package pigloros:plugin@0.1.0; interface helper {}",
            ),
            ("b.wit", b"world community-plugin { import helper; }"),
        ])),
        Ok(())
    );
    validate_plugin_wit_v1(&archive(&[
        ("deps/other/other.wit", b"package local:other@1.0.0; interface api {}"),
        ("main.wit", b"package pigloros:plugin@0.1.0; world community-plugin { import local:other/api@1.0.0; }"),
    ]))
}

#[test]
fn accepts_exact_archive_file_count_and_path_depth_limits() -> Result<(), Error> {
    let names: Vec<_> = (0..256)
        .map(|index| format!("file-{index:03}.wit"))
        .collect();
    let files: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            (
                name.as_str(),
                if index == 0 { WORLD } else { b"// sibling\n" },
            )
        })
        .collect();
    assert_eq!(validate_plugin_wit_v1(&archive(&files)), Ok(()));
    let name = format!("{}main.wit", "d/".repeat(31));
    assert_eq!(validate_plugin_wit_v1(&archive(&[(&name, WORLD)])), Ok(()));
    let mut bytes = archive(&[("main.wit", WORLD)]);
    bytes.resize(4 * 1024 * 1024, 0);
    validate_plugin_wit_v1(&bytes)
}

#[test]
fn refuses_one_over_each_admissibility_limit() {
    let mut bytes = archive(&[("main.wit", WORLD)]);
    bytes.resize(4 * 1024 * 1024 + 1, 0);
    assert_eq!(validate_plugin_wit_v1(&bytes), Err(Error::BoundsExceeded));
    let names: Vec<_> = (0..257)
        .map(|index| format!("file-{index:03}.wit"))
        .collect();
    let files: Vec<_> = names.iter().map(|name| (name.as_str(), WORLD)).collect();
    assert_eq!(
        validate_plugin_wit_v1(&archive(&files)),
        Err(Error::BoundsExceeded)
    );
    let name = format!("{}main.wit", "d/".repeat(32));
    assert_eq!(
        validate_plugin_wit_v1(&archive(&[(&name, WORLD)])),
        Err(Error::BoundsExceeded)
    );
}

#[test]
fn accepts_full_width_name_and_prefix_without_nul_terminators() -> Result<(), Error> {
    let name = format!("{}.wit", "x".repeat(96));
    assert_eq!(validate_plugin_wit_v1(&archive(&[(&name, WORLD)])), Ok(()));
    let path = format!("{}/{name}", "d".repeat(155));
    assert_eq!(path.len(), 256);
    validate_plugin_wit_v1(&archive(&[(&path, WORLD)]))
}

#[test]
fn refuses_unsafe_paths_order_and_case_or_prefix_collisions() {
    for path in [
        "",
        "/main.wit",
        "../main.wit",
        "./main.wit",
        "a/../main.wit",
        "a//main.wit",
        "a/./main.wit",
        "C:main.wit",
        "a\\main.wit",
        "a\n.wit",
        "é.wit",
    ] {
        assert_eq!(
            validate_plugin_wit_v1(&archive(&[(path, WORLD)])),
            Err(Error::Malformed),
            "{path:?}"
        );
    }
    for (first, second) in [
        ("b.wit", "a.wit"),
        ("a.wit", "a.wit"),
        ("A.wit", "a.wit"),
        ("a.wit", "a.wit/b.wit"),
        ("Z.wit/a.wit", "z.wit"),
    ] {
        assert_eq!(
            validate_plugin_wit_v1(&archive(&[(first, WORLD), (second, WORLD)])),
            Err(Error::Malformed),
            "{first:?}, {second:?}"
        );
    }
}

#[test]
fn refuses_extensions_links_devices_and_non_wit_members() {
    for flag in *b"123456xgLKS" {
        let mut bytes = archive(&[("main.wit", WORLD)]);
        reheader(&mut bytes, |header| header[156] = flag);
        assert_eq!(
            validate_plugin_wit_v1(&bytes),
            Err(Error::UnsupportedFormat),
            "{flag}"
        );
    }
    assert_eq!(
        validate_plugin_wit_v1(&archive(&[("README", WORLD)])),
        Err(Error::UnsupportedFormat)
    );
    assert_eq!(
        validate_plugin_wit_v1(&archive(&[("main.WIT", WORLD)])),
        Err(Error::UnsupportedFormat)
    );
    for field in [257, 263] {
        let mut bytes = archive(&[("main.wit", WORLD)]);
        reheader(&mut bytes, |header| header[field] = b'X');
        assert_eq!(
            validate_plugin_wit_v1(&bytes),
            Err(Error::UnsupportedFormat)
        );
    }
}

#[test]
fn refuses_bad_checksum_numeric_fields_and_ambiguous_header_strings() {
    let bytes = archive(&[("main.wit", WORLD)]);
    let mut changed = bytes.clone();
    changed[148..156].copy_from_slice(b"000000\0 ");
    assert_eq!(validate_plugin_wit_v1(&changed), Err(Error::Malformed));
    for value in [b'8', b'+', 0xff] {
        let mut changed = bytes.clone();
        reheader(&mut changed, |header| header[124] = value);
        assert_eq!(validate_plugin_wit_v1(&changed), Err(Error::Malformed));
    }
    let mut changed = bytes.clone();
    reheader(&mut changed, |header| header[124..136].fill(0));
    assert_eq!(validate_plugin_wit_v1(&changed), Err(Error::Malformed));
    let mut changed = bytes.clone();
    changed[148] = 0xff;
    assert_eq!(validate_plugin_wit_v1(&changed), Err(Error::Malformed));
    for field in [0, 99, 157, 345, 499, 500] {
        let mut changed = bytes.clone();
        reheader(&mut changed, |header| header[field] = 0xff);
        assert_eq!(
            validate_plugin_wit_v1(&changed),
            Err(Error::Malformed),
            "{field}"
        );
    }
}

#[test]
fn refuses_truncated_data_padding_or_end_markers() {
    let bytes = archive(&[("main.wit", WORLD)]);
    for len in [0, 1, 511, 512, 1024, 1536, bytes.len() - 1] {
        assert_eq!(
            validate_plugin_wit_v1(&bytes[..len]),
            Err(Error::Malformed),
            "{len}"
        );
    }
    let mut changed = bytes.clone();
    reheader(&mut changed, |header| {
        header[124..136].copy_from_slice(b"00077777777\0");
    });
    assert_eq!(validate_plugin_wit_v1(&changed), Err(Error::Malformed));
    let mut changed = bytes.clone();
    changed[512 + WORLD.len()] = 1;
    assert_eq!(validate_plugin_wit_v1(&changed), Err(Error::Malformed));
    let mut changed = bytes;
    changed[1536] = 1;
    assert_eq!(validate_plugin_wit_v1(&changed), Err(Error::Malformed));
}

#[test]
fn refuses_invalid_utf8_syntax_and_inconsistent_package_or_world_references() {
    for source in [&[0xff][..], b"not WIT".as_slice()] {
        assert_eq!(
            validate_plugin_wit_v1(&archive(&[("main.wit", source)])),
            Err(Error::Malformed)
        );
    }
    assert_eq!(validate_plugin_wit_v1(&[0; 1024]), Err(Error::Malformed));
    for source in [
        b"package pigloros:plugin@0.1.0;".as_slice(),
        b"package pigloros:plugin@0.2.0; world community-plugin {}".as_slice(),
        b"package pigloros:plugin@0.1.0; world other {}".as_slice(),
        b"package pigloros:plugin@0.1.0; world community-plugin { import missing:dep/api@1.0.0; }"
            .as_slice(),
    ] {
        assert_eq!(
            validate_plugin_wit_v1(&archive(&[("main.wit", source)])),
            Err(Error::ReferenceMismatch)
        );
    }
    assert_eq!(
        validate_plugin_wit_v1(&archive(&[
            ("a.wit", WORLD),
            ("b.wit", b"package different:package; interface api {}")
        ])),
        Err(Error::Malformed)
    );
    let duplicate = b"package pigloros:plugin@0.1.0; interface extra {}";
    assert_eq!(
        validate_plugin_wit_v1(&archive(&[
            ("a/main.wit", WORLD),
            ("b/main.wit", duplicate)
        ])),
        Err(Error::ReferenceMismatch)
    );
}

#[test]
fn keeps_parser_diagnostics_out_of_closed_errors() {
    let error =
        validate_plugin_wit_v1(&archive(&[("private-name.wit", b"private contents")])).err();
    assert_eq!(error, Some(Error::Malformed));
    for error in [
        Error::BoundsExceeded,
        Error::UnsupportedFormat,
        Error::Malformed,
        Error::ReferenceMismatch,
    ] {
        assert!(!format!("{error:?}: {error}").contains("private"));
    }
}

#[test]
fn rejects_malformed_supplied_dependency_before_resolution() {
    let bytes = archive(&[("a/main.wit", WORLD), ("b/bad.wit", b"not WIT")]);
    assert_eq!(validate_plugin_wit_v1(&bytes), Err(Error::Malformed));
}

#[test]
fn preserves_the_pinned_parsers_type_depth_guard() {
    // The pinned grammar permits 100 type nodes: 99 list constructors plus u8.
    for (depth, expected) in [(99, Ok(())), (100, Err(Error::Malformed))] {
        let source = format!(
            "package pigloros:plugin@0.1.0; interface api {{ type nested = {}u8{}; }} world community-plugin {{}}",
            "list<".repeat(depth),
            ">".repeat(depth)
        );
        assert_eq!(
            validate_plugin_wit_v1(&archive(&[("main.wit", source.as_bytes())])),
            expected,
            "type depth {depth}"
        );
    }
}

#[test]
fn validates_ustar_numeric_metadata_and_terminators() -> Result<(), Error> {
    let mut legal = archive(&[("main.wit", WORLD)]);
    reheader(&mut legal, |header| {
        header[100..108].copy_from_slice(b"0000644 ");
        header[136..148].copy_from_slice(b"77777777777\0");
        header[329..337].copy_from_slice(b"0000000\0");
        header[337..345].fill(b' ');
    });
    assert_eq!(validate_plugin_wit_v1(&legal), Ok(()));
    for start in [100, 108, 116, 136, 329, 337] {
        let mut bytes = archive(&[("main.wit", WORLD)]);
        reheader(&mut bytes, |header| header[start] = b'X');
        assert_eq!(
            validate_plugin_wit_v1(&bytes),
            Err(Error::Malformed),
            "field {start}"
        );
    }
    for (start, len) in [
        (100, 8),
        (108, 8),
        (116, 8),
        (124, 12),
        (136, 12),
        (329, 8),
        (337, 8),
    ] {
        let mut bytes = archive(&[("main.wit", WORLD)]);
        reheader(&mut bytes, |header| {
            header[start..start + len].fill(b'0');
            header[start] = 0;
        });
        assert_eq!(
            validate_plugin_wit_v1(&bytes),
            Err(Error::Malformed),
            "NUL in field {start}"
        );
        let mut bytes = archive(&[("main.wit", WORLD)]);
        reheader(&mut bytes, |header| header[start..start + len].fill(b'0'));
        assert_eq!(
            validate_plugin_wit_v1(&bytes),
            Err(Error::Malformed),
            "unterminated field {start}"
        );
    }
    let mut bytes = archive(&[("main.wit", WORLD)]);
    let digits = bytes[148..154].to_vec();
    bytes[148] = 0;
    bytes[149..155].copy_from_slice(&digits);
    assert_eq!(validate_plugin_wit_v1(&bytes), Err(Error::Malformed));
    let mut bytes = archive(&[("main.wit", WORLD)]);
    bytes[148..150].fill(b'0');
    bytes[150..156].copy_from_slice(&digits);
    assert_eq!(validate_plugin_wit_v1(&bytes), Err(Error::Malformed));
    Ok(())
}

fn package_chain(count: usize) -> String {
    let mut source = String::new();
    for index in 0..count {
        let body = if index + 1 == count {
            String::from("type value = u8;")
        } else {
            format!("use local:p{}/api.{{value}};", index + 1)
        };
        assert!(writeln!(
            source,
            "package local:p{index} {{ interface api {{ {body} }} }}"
        )
        .is_ok());
    }
    source
}

#[test]
fn bounds_all_packages_including_inline_declarations_before_resolution() {
    for (nested, expected) in [
        (255, Ok(())),
        (256, Err(Error::BoundsExceeded)),
        (4096, Err(Error::BoundsExceeded)),
    ] {
        let source = format!(
            "package pigloros:plugin@0.1.0; world community-plugin {{ import local:p0/api; }} {}",
            package_chain(nested)
        );
        assert_eq!(
            validate_plugin_wit_v1(&archive(&[("main.wit", source.as_bytes())])),
            expected
        );
    }
    for (nested, expected) in [(254, Ok(())), (255, Err(Error::BoundsExceeded))] {
        let source = format!("package local:other; {}", package_chain(nested));
        assert_eq!(
            validate_plugin_wit_v1(&archive(&[
                ("a/main.wit", WORLD),
                ("b/deps.wit", source.as_bytes())
            ])),
            expected
        );
    }
}

#[test]
fn parses_a_maximum_archive_with_an_actual_large_wit_source() -> Result<(), Error> {
    let mut source = WORLD.to_vec();
    source.extend_from_slice(b"\n/*");
    source.resize(4 * 1024 * 1024 - 1536 - 2, b'x');
    source.extend_from_slice(b"*/");
    let bytes = archive(&[("main.wit", &source)]);
    assert_eq!(bytes.len(), 4 * 1024 * 1024);
    validate_plugin_wit_v1(&bytes)
}

#[test]
fn stops_before_parsing_a_later_group_after_the_package_budget_is_exhausted() {
    let source = format!(
        "package pigloros:plugin@0.1.0; world community-plugin {{ import local:p0/api; }} {}",
        package_chain(255)
    );
    let bytes = archive(&[
        ("a/full.wit", source.as_bytes()),
        ("b/malformed.wit", b"not WIT"),
    ]);
    // Parsing the later group would produce Malformed instead of this bound refusal.
    assert_eq!(validate_plugin_wit_v1(&bytes), Err(Error::BoundsExceeded));
}
