#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CborPreflightError {
    InvalidEncoding,
    FieldOutOfBounds,
}

pub(crate) fn preflight_array_cbor(
    bytes: &[u8],
    maximum_depth: u8,
    maximum_items: u64,
    allow_simple_values: bool,
) -> Result<(), CborPreflightError> {
    fn read_length(
        bytes: &[u8],
        index: &mut usize,
        additional: u8,
    ) -> Result<u64, CborPreflightError> {
        let width = match additional {
            value @ 0..=23 => return Ok(u64::from(value)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(CborPreflightError::InvalidEncoding),
        };
        let end = index.saturating_add(width);
        bytes
            .get(*index..end)
            .ok_or(CborPreflightError::InvalidEncoding)
            .map(|encoded| {
                *index = end;
                let mut value = [0_u8; 8];
                value[8 - width..].copy_from_slice(encoded);
                u64::from_be_bytes(value)
            })
    }

    fn item(
        bytes: &[u8],
        index: &mut usize,
        depth: u8,
        maximum_depth: u8,
        maximum_items: u64,
        allow_simple_values: bool,
    ) -> Result<(), CborPreflightError> {
        if depth > maximum_depth {
            return Err(CborPreflightError::FieldOutOfBounds);
        }
        bytes
            .get(*index)
            .copied()
            .ok_or(CborPreflightError::InvalidEncoding)
            .and_then(|initial| {
                *index = index.saturating_add(1);
                read_length(bytes, index, initial & 0x1f).and_then(|length| match initial >> 5 {
                    0 | 1 => Ok(()),
                    2 | 3 => {
                        let count = usize::try_from(length).unwrap_or(usize::MAX);
                        index
                            .checked_add(count)
                            .ok_or(CborPreflightError::FieldOutOfBounds)
                            .and_then(|end| {
                                bytes
                                    .get(*index..end)
                                    .ok_or(CborPreflightError::InvalidEncoding)
                                    .map(|_| *index = end)
                            })
                    }
                    4 if length > maximum_items => Err(CborPreflightError::FieldOutOfBounds),
                    4 => (0..length).try_for_each(|_| {
                        item(
                            bytes,
                            index,
                            depth.saturating_add(1),
                            maximum_depth,
                            maximum_items,
                            allow_simple_values,
                        )
                    }),
                    7 if allow_simple_values && matches!(initial & 0x1f, 20..=22) => Ok(()),
                    _ => Err(CborPreflightError::InvalidEncoding),
                })
            })
    }

    let mut index = 0;
    item(
        bytes,
        &mut index,
        0,
        maximum_depth,
        maximum_items,
        allow_simple_values,
    )
    .and_then(|()| {
        if index == bytes.len() {
            Ok(())
        } else {
            Err(CborPreflightError::InvalidEncoding)
        }
    })
}

pub(crate) fn identifier(value: &str, maximum_bytes: usize) -> bool {
    let Some(first) = value.bytes().next() else {
        return false;
    };
    value.len() <= maximum_bytes
        && value.is_ascii()
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
}

pub(crate) fn member_path(
    value: &str,
    maximum_bytes: usize,
    maximum_components: usize,
    maximum_component_bytes: usize,
) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.is_ascii()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && (1..=maximum_components).contains(&value.split('/').count())
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.len() <= maximum_component_bytes
        })
}

pub(crate) fn media_type(value: &str, maximum_bytes: usize) -> bool {
    let Some((type_name, subtype)) = value.split_once('/') else {
        return false;
    };
    (3..=maximum_bytes).contains(&value.len())
        && !type_name.is_empty()
        && !subtype.is_empty()
        && !subtype.contains('/')
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'/'
                )
        })
}

pub(crate) fn semantic_version(
    value: &str,
    maximum_bytes: usize,
    maximum_numeric_component_bytes: Option<usize>,
) -> bool {
    if value.is_empty() || value.len() > maximum_bytes || !value.is_ascii() {
        return false;
    }
    let (core_and_prerelease, build) = match value.split_once('+') {
        Some((core, suffix)) if !suffix.is_empty() && !suffix.contains('+') => (core, suffix),
        Some(_) => return false,
        None => (value, ""),
    };
    let (core, prerelease) = match core_and_prerelease.split_once('-') {
        Some((core, suffix)) if !suffix.is_empty() => (core, suffix),
        Some(_) => return false,
        None => (core_and_prerelease, ""),
    };
    let numeric = |component: &str| {
        !component.is_empty()
            && maximum_numeric_component_bytes.is_none_or(|maximum| component.len() <= maximum)
            && (component == "0" || !component.starts_with('0'))
            && component.bytes().all(|byte| byte.is_ascii_digit())
    };
    let identifiers = |suffix: &str, numeric_zero_forbidden: bool| {
        suffix.is_empty()
            || suffix.split('.').all(|component| {
                !component.is_empty()
                    && component
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && (!numeric_zero_forbidden
                        || !component.bytes().all(|byte| byte.is_ascii_digit())
                        || numeric(component))
            })
    };
    core.split('.').count() == 3
        && core.split('.').all(numeric)
        && identifiers(prerelease, true)
        && identifiers(build, false)
}
