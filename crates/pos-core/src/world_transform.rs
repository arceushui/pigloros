#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> WorldGeographicEvidenceCapabilityV1 {
        WorldGeographicEvidenceCapabilityV1::for_trusted_core()
    }

    fn origin(
        capability: &WorldGeographicEvidenceCapabilityV1,
        max_radius_metres: f64,
    ) -> WorldOriginV1 {
        WorldOriginV1::new(
            capability,
            [1; 16],
            [2; 16],
            1,
            Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("fixture origin is valid"),
            [3; 32],
            max_radius_metres,
        )
        .expect("fixture origin is valid")
    }

    #[test]
    fn position_normalizes_longitude_and_rejects_poles() {
        let position =
            Wgs84PositionV1::new(10.0, 540.0, -20.0).expect("finite longitude normalizes");
        assert_eq!(position.latitude_degrees(), 10.0);
        assert_eq!(position.longitude_degrees(), -180.0);
        assert_eq!(position.ellipsoidal_height_metres(), -20.0);
        assert!(matches!(
            Wgs84PositionV1::new(90.0, 0.0, 0.0),
            Err(WorldTransformError::PoleUnsupported)
        ));
        assert!(matches!(
            Wgs84PositionV1::new(f64::NAN, 0.0, 0.0),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
        assert!(matches!(
            Wgs84PositionV1::new(91.0, 0.0, 0.0),
            Err(WorldTransformError::LatitudeOutOfRange)
        ));
    }

    #[test]
    fn forward_origin_is_zero_and_repeated_forward_is_deterministic() {
        let capability = capability();
        let origin = origin(&capability, 10_000.0);
        let transform =
            WorldTransformV1::new(&capability, origin.clone()).expect("origin is transformable");
        let coordinate = transform
            .forward(
                &capability,
                Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("same origin is valid"),
            )
            .expect("origin maps to local zero");
        assert_eq!(coordinate.east_metres(), 0.0);
        assert_eq!(coordinate.north_metres(), 0.0);
        assert_eq!(coordinate.up_metres(), 0.0);
        assert_eq!(
            coordinate,
            transform
                .forward(
                    &capability,
                    Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("same origin is valid"),
                )
                .expect("same input is deterministic")
        );
        assert_eq!(origin.max_radius_metres(), 10_000.0);
    }

    #[test]
    fn forward_covers_hemispheres_height_antimeridian_and_radius() {
        let capability = capability();
        let equator = WorldOriginV1::new(
            &capability,
            [4; 16],
            [5; 16],
            1,
            Wgs84PositionV1::new(0.0, 179.999, 0.0).expect("valid antimeridian origin"),
            [6; 32],
            10_000.0,
        )
        .expect("origin is valid");
        let transform =
            WorldTransformV1::new(&capability, equator).expect("origin is transformable");
        let east = transform
            .forward(
                &capability,
                Wgs84PositionV1::new(0.0, -179.999, 25.0).expect("valid antimeridian neighbor"),
            )
            .expect("ECEF handles longitude wrap");
        assert!(east.east_metres().is_finite());
        assert!(east.north_metres().is_finite());
        assert!(east.up_metres().is_finite());

        let southern = transform
            .forward(
                &capability,
                Wgs84PositionV1::new(-0.01, 179.999, -25.0).expect("valid southern point"),
            )
            .expect("southern point is in range");
        assert!(southern.north_metres() < 0.0);
        assert!(southern.up_metres() < 0.0);

        let one_metre = WorldOriginV1::new(
            &capability,
            [7; 16],
            [8; 16],
            1,
            Wgs84PositionV1::new(0.0, 0.0, 0.0).expect("valid equator origin"),
            [9; 32],
            1.0,
        )
        .expect("one metre radius is valid");
        let one_metre_transform =
            WorldTransformV1::new(&capability, one_metre).expect("origin is transformable");
        assert!(one_metre_transform
            .forward(
                &capability,
                Wgs84PositionV1::new(0.0, 0.0, 1.0).expect("boundary height is valid"),
            )
            .is_ok());
        assert!(matches!(
            one_metre_transform.forward(
                &capability,
                Wgs84PositionV1::new(0.0, 0.0, 1.1).expect("out-of-radius height is valid"),
            ),
            Err(WorldTransformError::OutOfRadius)
        ));
    }

    #[test]
    fn inverse_round_trip_and_near_pole_policy_are_deterministic() {
        let capability = capability();
        let transform = WorldTransformV1::new(&capability, origin(&capability, 10_000.0))
            .expect("origin is transformable");
        let source =
            Wgs84PositionV1::new(35.001, -119.999, 120.0).expect("round-trip source is valid");
        let coordinate = transform
            .forward(&capability, source)
            .expect("source is in local radius");
        let recovered = transform
            .inverse(&capability, coordinate)
            .expect("forward result is invertible");
        assert!((recovered.latitude_degrees() - source.latitude_degrees()).abs() < 1e-10);
        assert!((recovered.longitude_degrees() - source.longitude_degrees()).abs() < 1e-10);
        assert!(
            (recovered.ellipsoidal_height_metres() - source.ellipsoidal_height_metres()).abs()
                < 1e-4
        );
        assert!(matches!(
            Wgs84PositionV1::new(89.999, -120.0, 0.0),
            Ok(_)
        ));
    }

    #[test]
    fn origin_registry_rejects_duplicates_and_restores_atomically() {
        let capability = capability();
        let first = origin(&capability, 10_000.0);
        let reference = first.reference();
        let mut registry = WorldOriginRegistryV1::new();
        registry
            .register(&capability, first.clone())
            .expect("first origin registers");
        assert!(registry.resolve(&capability, &reference).is_ok());
        assert!(matches!(
            registry.register(&capability, first.clone()),
            Err(WorldTransformError::DuplicateOrigin)
        ));
        registry
            .retire(&capability, &reference)
            .expect("retirement is authorized");
        assert!(matches!(
            registry.resolve(&capability, &reference),
            Err(WorldTransformError::OriginRetired)
        ));

        let second = WorldOriginV1::new(
            &capability,
            [10; 16],
            [11; 16],
            1,
            Wgs84PositionV1::new(-20.0, 30.0, 0.0).expect("second origin is valid"),
            [12; 32],
            500.0,
        )
        .expect("second origin is valid");
        assert!(matches!(
            registry.restore(&capability, vec![second.clone(), first]),
            Err(WorldTransformError::OriginRetired)
        ));
        assert!(matches!(
            registry.resolve(&capability, &reference),
            Err(WorldTransformError::OriginRetired)
        ));
        registry
            .restore(&capability, vec![second.clone()])
            .expect("valid restore replaces the registry");
        assert!(registry.resolve(&capability, &second.reference()).is_ok());
    }
}
