#![cfg(windows)]
#![forbid(unsafe_code)]

use crate::{BoolProperty, EnvironmentOptions, EnvironmentSnapshot, NativeOperations};
use pos_owner_bridge::{BridgeError, SurfaceError, UnavailableCode};

pub(super) const OPTIONS: EnvironmentOptions = EnvironmentOptions {
    extensions: false,
    custom_crash_reporting: true,
    exclusive_folder: true,
};

const SETTINGS: [(BoolProperty, bool); 16] = [
    (BoolProperty::Script, true),
    (BoolProperty::WebMessage, false),
    (BoolProperty::ScriptDialogs, false),
    (BoolProperty::StatusBar, false),
    (BoolProperty::DevTools, false),
    (BoolProperty::ContextMenus, false),
    (BoolProperty::HostObjects, false),
    (BoolProperty::Zoom, false),
    (BoolProperty::BuiltInErrorPage, false),
    (BoolProperty::BrowserAccelerators, false),
    (BoolProperty::PasswordAutosave, false),
    (BoolProperty::Autofill, false),
    (BoolProperty::PinchZoom, false),
    (BoolProperty::SwipeNavigation, false),
    (BoolProperty::ReputationChecking, false),
    (BoolProperty::ExternalDrop, false),
];

pub(super) fn verify_options(snapshot: &EnvironmentSnapshot) -> Result<(), SurfaceError> {
    if !snapshot.arguments.as_str().is_empty()
        || snapshot.options.extensions != OPTIONS.extensions
        || snapshot.options.custom_crash_reporting != OPTIONS.custom_crash_reporting
        || snapshot.options.exclusive_folder != OPTIONS.exclusive_folder
    {
        return Err(unavailable());
    }
    Ok(())
}

pub(super) fn apply(native: &dyn NativeOperations) -> Result<(), SurfaceError> {
    for (property, expected) in SETTINGS {
        native
            .set_bool(property, expected)
            .map_err(|_| unavailable())?;
        let observed = native.get_bool(property).map_err(|_| unavailable())?;
        if observed != expected {
            return Err(unavailable());
        }
    }
    Ok(())
}

const fn unavailable() -> SurfaceError {
    SurfaceError::new(BridgeError::Unavailable(
        UnavailableCode::InterfaceUnavailable,
    ))
}
