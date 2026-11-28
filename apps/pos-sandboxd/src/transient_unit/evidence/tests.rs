use std::error::Error;

use pos_reference::sandbox_provider_protocol::{
    DbusValue, RequestedConfigurationStatus, SandboxProviderProtocolError,
};

use super::{unverified_requested_configuration, verified_requested_configuration};
use crate::{
    RequestedConfigurationProperty, RequestedConfigurationValue, SystemdHardeningReadbackValue,
    SystemdManagerReadback, SystemdManagerReadbackOnlyProperty, SystemdTransientUnitReadback,
    SystemdTransientUnitReadbackValue,
};

type TestResult = Result<(), Box<dyn Error>>;

fn requested() -> [RequestedConfigurationProperty; 1] {
    [RequestedConfigurationProperty {
        name: "SuccessExitStatus",
        value: RequestedConfigurationValue::Typed(SystemdTransientUnitReadbackValue::Static(
            SystemdHardeningReadbackValue::ExitStatuses(vec![1, 2], vec![15]),
        )),
    }]
}

fn readback(statuses: Vec<i32>, signals: Vec<i32>) -> [SystemdTransientUnitReadback; 1] {
    [SystemdTransientUnitReadback::new(
        "SuccessExitStatus",
        SystemdTransientUnitReadbackValue::Static(SystemdHardeningReadbackValue::ExitStatuses(
            statuses, signals,
        )),
    )]
}

/// A read-back that differs from the request is a mismatch, and its exit statuses and signals are
/// recorded as they were read.
#[test]
fn an_exit_status_readback_in_range_is_recorded_as_read() -> TestResult {
    let readback = readback(vec![1, 255], vec![0, 64]);
    let evidence =
        unverified_requested_configuration([1; 16], [2; 32], &requested(), Some(&readback))?;
    let fields = evidence.fields();
    assert_eq!(fields.status, RequestedConfigurationStatus::Mismatch);
    let recorded = fields.readback.as_ref().ok_or("no readback")?;
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].value,
        DbusValue::ExitStatusSet(vec![1, 255], vec![0, 64])
    );
    Ok(())
}

/// A status or signal outside `0..=255` cannot be written into RQE1, and is not recorded as a
/// read-back that looks like the request: the read-back is unobtainable, status 3.
#[test]
fn an_out_of_range_exit_status_readback_is_reported_as_unobtainable() -> TestResult {
    for (statuses, signals) in [
        (vec![300], vec![]),
        (vec![-1], vec![]),
        (vec![256], vec![]),
        (vec![1], vec![300]),
        (vec![1], vec![-1]),
        (vec![1, 256], vec![15]),
    ] {
        let readback = readback(statuses.clone(), signals.clone());
        let evidence =
            unverified_requested_configuration([1; 16], [2; 32], &requested(), Some(&readback))?;
        let fields = evidence.fields();
        assert_eq!(
            fields.status,
            RequestedConfigurationStatus::ReadbackUnavailable,
            "{statuses:?} {signals:?}"
        );
        assert!(fields.readback.is_none());
        assert!(fields.requested.is_some());
    }
    Ok(())
}

/// A verified start has the exact list, so an out-of-range one is a refusal, not a record.
#[test]
fn an_out_of_range_exit_status_readback_cannot_be_a_verified_record() {
    let manager =
        SystemdManagerReadback::new(SystemdManagerReadbackOnlyProperty::RootImagePolicy, "");
    let refused = verified_requested_configuration(
        [1; 16],
        [2; 32],
        &requested(),
        &readback(vec![300], vec![15]),
        &manager,
    );
    assert!(matches!(
        refused,
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    ));
}
