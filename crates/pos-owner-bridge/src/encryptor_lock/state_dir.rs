//! Pure resolver for the owner state directory.
//!
//! Implements the ADR-110 E16 base directory (used by E20 LC1 step 3) and the
//! XDG Base Directory Specification `XDG_STATE_HOME` default. The resolver maps
//! two environment values to a path. It reads no environment, touches no
//! filesystem and constructs nothing, so it is not an activation surface
//! (ADR-110 E15). The result is only a path: the `.local` and `state`
//! components are opened separately later (E16).

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// The environment variable that supplied a rejected value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateDirVariable {
    /// `XDG_STATE_HOME`.
    XdgStateHome,
    /// `HOME`.
    Home,
}

impl fmt::Display for StateDirVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::XdgStateHome => "XDG_STATE_HOME",
            Self::Home => "HOME",
        })
    }
}

/// Why no owner state directory could be resolved.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StateDirError {
    /// Neither a non-empty `XDG_STATE_HOME` nor `HOME` is set.
    #[error("neither a non-empty XDG_STATE_HOME nor HOME is set")]
    Unset,
    /// The selected variable is not an absolute path (an empty `HOME` counts).
    #[error("{0} is not an absolute path")]
    NotAbsolute(StateDirVariable),
}

/// Resolve the owner state directory from the two environment values.
///
/// `XDG_STATE_HOME` selects `<value>/pigloros`; otherwise `HOME` selects
/// `<value>/.local/state/pigloros`. A set but empty `XDG_STATE_HOME` counts as
/// unset. A relative one fails closed without falling back (ADR-110 E16,
/// stricter than the XDG rule). The value is joined unchanged, with no
/// canonicalisation.
///
/// # Errors
/// `Unset` when neither a non-empty `XDG_STATE_HOME` nor `HOME` is given;
/// `NotAbsolute` when the selected value is relative or `HOME` is empty.
pub fn owner_state_dir(
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf, StateDirError> {
    let xdg = xdg_state_home.filter(|value| !value.is_empty());
    match (xdg, home) {
        (Some(xdg), _) => {
            let base = absolute(xdg, StateDirVariable::XdgStateHome);
            base.map(|path| path.join("pigloros"))
        }
        (None, Some(home)) => {
            let base = absolute(home, StateDirVariable::Home);
            base.map(|path| path.join(".local/state/pigloros"))
        }
        (None, None) => Err(StateDirError::Unset),
    }
}

fn absolute(value: &OsStr, variable: StateDirVariable) -> Result<&Path, StateDirError> {
    let path = Path::new(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(StateDirError::NotAbsolute(variable))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{owner_state_dir, StateDirError, StateDirVariable};
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    fn os(value: &str) -> &OsStr {
        OsStr::new(value)
    }

    #[test]
    fn xdg_state_home_selects_pigloros_below_it() {
        assert_eq!(
            owner_state_dir(Some(os("/x/state")), None),
            Ok(PathBuf::from("/x/state/pigloros"))
        );
    }

    #[test]
    fn xdg_state_home_wins_over_home() {
        assert_eq!(
            owner_state_dir(Some(os("/x/state")), Some(os("/home/u"))),
            Ok(PathBuf::from("/x/state/pigloros"))
        );
    }

    #[test]
    fn home_selects_the_default_state_location() {
        assert_eq!(
            owner_state_dir(None, Some(os("/home/u"))),
            Ok(PathBuf::from("/home/u/.local/state/pigloros"))
        );
    }

    #[test]
    fn trailing_slash_does_not_double_the_separator() {
        assert_eq!(
            owner_state_dir(Some(os("/x/state/")), None),
            Ok(PathBuf::from("/x/state/pigloros"))
        );
        assert_eq!(
            owner_state_dir(None, Some(os("/home/u/"))),
            Ok(PathBuf::from("/home/u/.local/state/pigloros"))
        );
    }

    #[test]
    fn both_unset_fails_closed() {
        assert_eq!(owner_state_dir(None, None), Err(StateDirError::Unset));
    }

    #[test]
    fn empty_xdg_state_home_counts_as_unset() {
        assert_eq!(
            owner_state_dir(Some(os("")), Some(os("/home/u"))),
            Ok(PathBuf::from("/home/u/.local/state/pigloros"))
        );
        assert_eq!(
            owner_state_dir(Some(os("")), Some(os("home/u"))),
            Err(StateDirError::NotAbsolute(StateDirVariable::Home))
        );
        assert_eq!(
            owner_state_dir(Some(os("")), None),
            Err(StateDirError::Unset)
        );
    }

    #[test]
    fn relative_xdg_state_home_fails_closed_even_with_a_valid_home() {
        let expected = Err(StateDirError::NotAbsolute(StateDirVariable::XdgStateHome));
        assert_eq!(
            owner_state_dir(Some(os("state")), Some(os("/home/u"))),
            expected
        );
        assert_eq!(
            owner_state_dir(Some(os("./state")), Some(os("/home/u"))),
            expected
        );
    }

    #[test]
    fn empty_or_relative_home_fails_closed() {
        let expected = Err(StateDirError::NotAbsolute(StateDirVariable::Home));
        assert_eq!(owner_state_dir(None, Some(os(""))), expected);
        assert_eq!(owner_state_dir(None, Some(os("home/u"))), expected);
    }

    #[test]
    fn non_utf8_absolute_values_are_kept_byte_for_byte() {
        let xdg = OsStr::from_bytes(b"/x/\xff");
        let xdg_want = PathBuf::from(OsStr::from_bytes(b"/x/\xff/pigloros"));
        assert_eq!(owner_state_dir(Some(xdg), None), Ok(xdg_want));
        let home = OsStr::from_bytes(b"/h/\xfe");
        let home_want = PathBuf::from(OsStr::from_bytes(b"/h/\xfe/.local/state/pigloros"));
        assert_eq!(owner_state_dir(None, Some(home)), Ok(home_want));
    }

    #[test]
    fn non_utf8_relative_value_fails_closed() {
        assert_eq!(
            owner_state_dir(Some(OsStr::from_bytes(b"\xff")), None),
            Err(StateDirError::NotAbsolute(StateDirVariable::XdgStateHome))
        );
    }

    #[test]
    fn errors_render_a_message() {
        assert_eq!(
            StateDirError::Unset.to_string(),
            "neither a non-empty XDG_STATE_HOME nor HOME is set"
        );
        assert_eq!(
            StateDirError::NotAbsolute(StateDirVariable::Home).to_string(),
            "HOME is not an absolute path"
        );
        assert_eq!(
            StateDirError::NotAbsolute(StateDirVariable::XdgStateHome).to_string(),
            "XDG_STATE_HOME is not an absolute path"
        );
    }
}
