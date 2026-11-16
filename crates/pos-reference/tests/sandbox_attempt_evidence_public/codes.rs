//! Every closed R9 code converts to and from exactly its R9 number.

use std::fmt::Debug;
use std::ops::RangeInclusive;

use pos_reference::sandbox_provider_protocol::{
    AttemptProgressCode, BarrierFailure, CancelSource, CgroupEmptyBasis, CleanupResult,
    Contradiction, EndingCode, LaunchFailure, LocalNetworkTerminationCode, MainExitCode,
    RequestedConfigurationStatus, SandboxProviderProtocolError as ProtocolError, ServiceResultCode,
    StartJobResult, TerminalCode,
};

fn closed<T>(range: RangeInclusive<u8>)
where
    T: TryFrom<u8, Error = ProtocolError> + Into<u8> + Copy + Debug,
{
    for number in 0..=u8::MAX {
        match T::try_from(number) {
            Ok(code) => {
                assert!(range.contains(&number), "{number} is not an R9 code");
                assert_eq!(code.into(), number);
            }
            Err(error) => {
                assert!(!range.contains(&number), "R9 code {number} was rejected");
                assert_eq!(error, ProtocolError::FieldOutOfBounds);
            }
        }
    }
}

#[test]
fn every_closed_code_is_its_r9_number() {
    closed::<AttemptProgressCode>(0..=2);
    closed::<LaunchFailure>(0..=2);
    closed::<StartJobResult>(0..=5);
    closed::<Contradiction>(0..=2);
    closed::<ServiceResultCode>(0..=10);
    closed::<MainExitCode>(0..=3);
    closed::<EndingCode>(0..=7);
    closed::<BarrierFailure>(0..=12);
    closed::<LocalNetworkTerminationCode>(0..=4);
    closed::<CancelSource>(0..=1);
    closed::<CleanupResult>(0..=2);
    closed::<RequestedConfigurationStatus>(0..=3);
    closed::<TerminalCode>(1..=10);
    closed::<CgroupEmptyBasis>(0..=1);
    assert_eq!(TerminalCode::try_from(6).map(TerminalCode::code), Ok(6));
    assert_eq!(u8::from(CgroupEmptyBasis::Deleted), 1);
}
