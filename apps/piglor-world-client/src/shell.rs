use bevy::{
    input::{keyboard::KeyCode, mouse::AccumulatedMouseMotion, ButtonInput},
    prelude::*,
    window::{CursorGrabMode, CursorOptions, Window, WindowPlugin},
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{decode_fixture, fixture_bytes, project_fixture, ClientError, ProjectionDigest};

const CAMERA_SPEED: f32 = 4.0;
const MOUSE_SENSITIVITY: f32 = 0.002;
const PITCH_LIMIT: f32 = std::f32::consts::FRAC_PI_2 - 0.01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorState {
    Released,
    Locked,
}

#[derive(Component)]
struct FirstPersonCamera {
    yaw: f32,
    pitch: f32,
}

#[derive(Resource)]
struct ShellProjection(ProjectionDigest);

#[must_use]
pub fn movement_vector(keys: &ButtonInput<KeyCode>) -> Vec3 {
    let mut movement = Vec3::ZERO;
    if keys.pressed(KeyCode::KeyW) {
        movement.z -= 1.0;
    }
    if keys.pressed(KeyCode::KeyS) {
        movement.z += 1.0;
    }
    if keys.pressed(KeyCode::KeyA) {
        movement.x -= 1.0;
    }
    if keys.pressed(KeyCode::KeyD) {
        movement.x += 1.0;
    }
    if movement == Vec3::ZERO {
        movement
    } else {
        movement.normalize()
    }
}

#[must_use]
pub fn clamp_pitch(pitch: f32) -> f32 {
    pitch.clamp(-PITCH_LIMIT, PITCH_LIMIT)
}

#[must_use]
pub fn mouse_look(current: Vec2, delta: Vec2, sensitivity: f32) -> Vec2 {
    Vec2::new(
        current.x + delta.x * sensitivity,
        clamp_pitch(current.y + delta.y * sensitivity),
    )
}

#[must_use]
pub fn cursor_state(current: CursorState, left_click: bool, escape: bool) -> CursorState {
    if escape {
        CursorState::Released
    } else if left_click {
        CursorState::Locked
    } else {
        current
    }
}

/// Build the native or WebGL2 Bevy application around a pure projection.
pub fn build_app(digest: ProjectionDigest) -> App {
    let mut app = App::new();
    app.insert_resource(ShellProjection(digest))
        .add_plugins(DefaultPlugins.set(WindowPlugin {
            primary_window: Some(Window {
                canvas: Some("#piglor-world".to_owned()),
                fit_canvas_to_parent: true,
                ..default()
            }),
            ..default()
        }))
        .add_systems(Startup, setup_scene)
        .add_systems(Update, (move_camera, look_camera, update_cursor).chain());
    app
}

/// Run the fixture-backed client on a native target.
///
/// # Errors
///
/// Returns [`ClientError`] when the embedded fixture cannot be decoded or
/// projected into a [`ProjectionDigest`].
pub fn run_native() -> Result<(), ClientError> {
    let digest = fixture_digest()?;
    build_app(digest).run();
    Ok(())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn start_wasm() -> Result<(), wasm_bindgen::JsValue> {
    run_native().map_err(|error| wasm_bindgen::JsValue::from_str(&error.to_string()))
}

fn fixture_digest() -> Result<ProjectionDigest, ClientError> {
    decode_fixture(&fixture_bytes()).and_then(|export| project_fixture(&export))
}

// Bevy ECS system extractors require owned `Res<T>` parameters here.
#[allow(clippy::needless_pass_by_value)]
fn setup_scene(
    mut commands: Commands,
    projection: Res<ShellProjection>,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    commands.spawn((
        Camera3d::default(),
        FirstPersonCamera {
            yaw: 0.0,
            pitch: 0.0,
        },
        Transform::from_xyz(0.0, 1.5, 6.0),
    ));

    commands.spawn((
        Mesh3d(meshes.add(Plane3d::default().mesh().size(20.0, 20.0))),
        MeshMaterial3d(materials.add(Color::srgb(0.08, 0.1, 0.14))),
    ));

    commands.spawn((
        Mesh3d(meshes.add(Cuboid::new(1.0, 2.0, 1.0))),
        MeshMaterial3d(materials.add(Color::srgb(0.15, 0.65, 0.9))),
        Transform::from_xyz(projection.0.landmark_x(), 1.0, -3.0),
    ));

    commands.spawn((
        DirectionalLight {
            illuminance: 10_000.0,
            shadow_maps_enabled: true,
            ..default()
        },
        Transform::from_rotation(Quat::from_euler(
            EulerRot::XYZ,
            -std::f32::consts::FRAC_PI_4,
            -std::f32::consts::FRAC_PI_4,
            0.0,
        )),
    ));
}

// Bevy ECS system extractors require owned `Res<T>` parameters here.
#[allow(clippy::needless_pass_by_value)]
fn move_camera(
    time: Res<Time>,
    keys: Res<ButtonInput<KeyCode>>,
    mut cameras: Query<(&mut Transform, &FirstPersonCamera)>,
) {
    let movement = movement_vector(&keys);
    if movement == Vec3::ZERO {
        return;
    }
    for (mut transform, camera) in &mut cameras {
        let direction = Quat::from_rotation_y(camera.yaw) * movement;
        transform.translation += direction * CAMERA_SPEED * time.delta_secs();
        transform.translation.y = 1.5;
    }
}

// Bevy ECS system extractors require owned `Res<T>` parameters here.
#[allow(clippy::needless_pass_by_value)]
fn look_camera(
    mouse_motion: Res<AccumulatedMouseMotion>,
    mut cameras: Query<(&mut Transform, &mut FirstPersonCamera)>,
) {
    if mouse_motion.delta == Vec2::ZERO {
        return;
    }
    for (mut transform, mut camera) in &mut cameras {
        let angles = mouse_look(
            Vec2::new(camera.yaw, camera.pitch),
            mouse_motion.delta,
            MOUSE_SENSITIVITY,
        );
        camera.yaw = angles.x;
        camera.pitch = angles.y;
        transform.rotation = Quat::from_euler(EulerRot::YXZ, camera.yaw, camera.pitch, 0.0);
    }
}

// Bevy ECS system extractors require owned `Res<T>` parameters here.
#[allow(clippy::needless_pass_by_value)]
fn update_cursor(
    mut cursor: Single<&mut CursorOptions>,
    mouse: Res<ButtonInput<MouseButton>>,
    keys: Res<ButtonInput<KeyCode>>,
) {
    let current = match cursor.grab_mode {
        CursorGrabMode::Locked | CursorGrabMode::Confined => CursorState::Locked,
        CursorGrabMode::None => CursorState::Released,
    };
    match cursor_state(
        current,
        mouse.just_pressed(MouseButton::Left),
        keys.just_pressed(KeyCode::Escape),
    ) {
        CursorState::Locked => {
            cursor.visible = false;
            cursor.grab_mode = CursorGrabMode::Locked;
        }
        CursorState::Released => {
            cursor.visible = true;
            cursor.grab_mode = CursorGrabMode::None;
        }
    }
}

#[cfg(test)]
mod tests {
    use bevy::input::keyboard::KeyCode;
    use bevy::input::ButtonInput;
    use bevy::math::{Vec2, Vec3};

    use super::{clamp_pitch, cursor_state, mouse_look, movement_vector, CursorState};

    #[test]
    fn movement_vectors_follow_wasd_axes_and_normalize_diagonals() {
        let mut keys = ButtonInput::default();
        keys.press(KeyCode::KeyW);
        keys.press(KeyCode::KeyD);

        assert_eq!(
            movement_vector(&keys),
            Vec3::new(1.0, 0.0, -1.0).normalize()
        );
    }

    #[test]
    fn zero_input_produces_zero_movement() {
        let keys = ButtonInput::default();

        assert_eq!(movement_vector(&keys), Vec3::ZERO);
    }

    #[test]
    fn pitch_is_clamped_to_just_under_half_turn() {
        assert_eq!(
            clamp_pitch(10.0).to_bits(),
            (std::f32::consts::FRAC_PI_2 - 0.01).to_bits()
        );
        assert_eq!(
            clamp_pitch(-10.0).to_bits(),
            (-std::f32::consts::FRAC_PI_2 + 0.01).to_bits()
        );
    }

    #[test]
    fn mouse_delta_updates_yaw_and_pitch_with_clamp() {
        assert_eq!(
            mouse_look(Vec2::new(1.0, 0.0), Vec2::new(2.0, 3.0), 0.5),
            Vec2::new(2.0, clamp_pitch(1.5))
        );
    }

    #[test]
    fn left_click_requests_locked_cursor() {
        assert_eq!(
            cursor_state(CursorState::Released, true, false),
            CursorState::Locked
        );
    }

    #[test]
    fn escape_requests_released_cursor() {
        assert_eq!(
            cursor_state(CursorState::Locked, false, true),
            CursorState::Released
        );
    }
}
