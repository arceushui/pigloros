//! Fixed World session profiles selected by the installed host.

/// An opaque host-selected World profile. Callers cannot change its fields.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HostWorldProfileV1 {
    timestep_micros: u32,
    coord_convention: u8,
    gravity_x: f32,
    gravity_y: f32,
    gravity_z: f32,
    action_schema_version: u32,
    observation_schema_version: u32,
    sensor_min_resolution_mm: u16,
    actuator_catalogue_version: u32,
}

impl HostWorldProfileV1 {
    /// The fixed first World profile for the built-in backend.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            timestep_micros: 16_667,
            coord_convention: 0,
            gravity_x: 0.0,
            gravity_y: -9.81,
            gravity_z: 0.0,
            action_schema_version: 1,
            observation_schema_version: 1,
            sensor_min_resolution_mm: 100,
            actuator_catalogue_version: 1,
        }
    }

    /// The fixed one-second, zero-gravity proof profile.
    #[must_use]
    pub const fn moat_proof() -> Self {
        Self {
            timestep_micros: 1_000_000,
            coord_convention: 0,
            gravity_x: 0.0,
            gravity_y: 0.0,
            gravity_z: 0.0,
            action_schema_version: 1,
            observation_schema_version: 1,
            sensor_min_resolution_mm: 100,
            actuator_catalogue_version: 1,
        }
    }

    #[must_use]
    pub const fn timestep_micros(self) -> u32 {
        self.timestep_micros
    }

    #[must_use]
    pub const fn coord_convention(self) -> u8 {
        self.coord_convention
    }

    #[must_use]
    pub const fn gravity(self) -> [f32; 3] {
        [self.gravity_x, self.gravity_y, self.gravity_z]
    }

    #[must_use]
    pub const fn action_schema_version(self) -> u32 {
        self.action_schema_version
    }

    #[must_use]
    pub const fn observation_schema_version(self) -> u32 {
        self.observation_schema_version
    }

    #[must_use]
    pub const fn sensor_min_resolution_mm(self) -> u16 {
        self.sensor_min_resolution_mm
    }

    #[must_use]
    pub const fn actuator_catalogue_version(self) -> u32 {
        self.actuator_catalogue_version
    }
}
