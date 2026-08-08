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
enum CursorState {
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
fn movement_vector(keys: &ButtonInput<KeyCode>) -> Vec3 {
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
fn clamp_pitch(pitch: f32) -> f32 {
    pitch.clamp(-PITCH_LIMIT, PITCH_LIMIT)
}

#[must_use]
fn mouse_look(current: Vec2, delta: Vec2, sensitivity: f32) -> Vec2 {
    Vec2::new(
        current.x + delta.x * sensitivity,
        clamp_pitch(current.y + delta.y * sensitivity),
    )
}

#[must_use]
fn cursor_state(current: CursorState, left_click: bool, escape: bool) -> CursorState {
    if escape {
        CursorState::Released
    } else if left_click {
        CursorState::Locked
    } else {
        current
    }
}

/// Build the native or WebGL2 Bevy application around a pure projection.
#[rustfmt::skip]
pub fn build_app(digest: ProjectionDigest) -> App {
    let mut app = App::new();
    add_default_plugins(&mut app);
    install_shell(&mut app, digest);
    app
}

#[rustfmt::skip]
fn add_default_plugins(app: &mut App) {
    let plugins = DefaultPlugins.set(window_plugin());
    #[cfg(test)]
    let plugins = plugins.disable::<bevy::winit::WinitPlugin>();
    app.add_plugins(plugins);
    #[cfg(test)]
    app.set_runner(|_| bevy::app::AppExit::Success);
}

fn window_plugin() -> WindowPlugin {
    WindowPlugin {
        primary_window: Some(Window {
            canvas: Some("#piglor-world".to_owned()),
            fit_canvas_to_parent: true,
            ..default()
        }),
        ..default()
    }
}

fn install_shell(app: &mut App, digest: ProjectionDigest) {
    app.insert_resource(ShellProjection(digest))
        .add_systems(Startup, setup_scene)
        .add_systems(Update, (move_camera, look_camera, update_cursor).chain());
}

/// Run the fixture-backed client on a native target.
///
/// # Errors
///
/// Returns [`ClientError`] when the embedded fixture cannot be decoded or
/// projected into a [`ProjectionDigest`].
#[rustfmt::skip]
pub fn run_native() -> Result<(), ClientError> {
    let digest = fixture_digest()?;
    run_app(build_app(digest));
    Ok(())
}

fn run_app(mut app: App) {
    app.run();
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn start_wasm() -> Result<(), wasm_bindgen::JsValue> {
    run_native().map_err(|error| wasm_bindgen::JsValue::from_str(&error.to_string()))
}

fn fixture_digest() -> Result<ProjectionDigest, ClientError> {
    decode_fixture(&fixture_bytes()).and_then(|export| project_fixture(&export))
}

fn setup_scene(
    mut commands: Commands,
    projection: Res<ShellProjection>,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    let projection = projection.into_inner();

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

fn move_camera(
    time: Res<Time>,
    keys: Res<ButtonInput<KeyCode>>,
    mut cameras: Query<(&mut Transform, &FirstPersonCamera)>,
) {
    let time = time.into_inner();
    let keys = keys.into_inner();
    let movement = movement_vector(keys);
    if movement == Vec3::ZERO {
        return;
    }
    for (mut transform, camera) in &mut cameras {
        let direction = Quat::from_rotation_y(camera.yaw) * movement;
        transform.translation += direction * CAMERA_SPEED * time.delta_secs();
        transform.translation.y = 1.5;
    }
}

fn look_camera(
    mouse_motion: Res<AccumulatedMouseMotion>,
    mut cameras: Query<(&mut Transform, &mut FirstPersonCamera)>,
) {
    let mouse_motion = mouse_motion.into_inner();
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

fn update_cursor(
    mut cursor: Single<&mut CursorOptions>,
    mouse: Res<ButtonInput<MouseButton>>,
    keys: Res<ButtonInput<KeyCode>>,
) {
    let mouse = mouse.into_inner();
    let keys = keys.into_inner();
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
    use std::time::Duration;

    use bevy::{
        app::{App, Startup, Update},
        asset::Assets,
        ecs::schedule::IntoScheduleConfigs,
        input::{
            keyboard::KeyCode,
            mouse::{AccumulatedMouseMotion, MouseButton},
            ButtonInput,
        },
        math::{Vec2, Vec3},
        prelude::{Camera3d, Mesh, StandardMaterial, Time, Transform},
        window::{CursorGrabMode, CursorOptions},
    };

    use super::{
        build_app, clamp_pitch, cursor_state, fixture_digest, install_shell, look_camera,
        mouse_look, move_camera, movement_vector, run_native, setup_scene, update_cursor,
        window_plugin, CursorState, FirstPersonCamera, ShellProjection, MOUSE_SENSITIVITY,
    };

    #[test]
    fn install_shell_registers_fixture_shell_resources_and_systems() {
        let digest = fixture_digest().expect("embedded fixture should project");
        let mut app = App::new();
        install_shell(&mut app, digest);

        assert_eq!(app.world().resource::<ShellProjection>().0, digest);
    }

    #[test]
    fn public_builder_installs_default_plugins_and_fixture_shell() {
        let digest = fixture_digest().expect("embedded fixture should project");
        let app = build_app(digest);

        assert_eq!(app.world().resource::<ShellProjection>().0, digest);
    }

    #[test]
    fn window_plugin_targets_the_world_canvas() {
        let plugin = window_plugin();
        let window = plugin
            .primary_window
            .expect("world client should configure a primary window");

        assert_eq!(window.canvas.as_deref(), Some("#piglor-world"));
        assert!(window.fit_canvas_to_parent);
    }

    #[test]
    fn public_native_runner_projects_and_starts_the_app() {
        run_native().expect("embedded fixture should project");
    }

    #[test]
    fn setup_scene_builds_fixture_backed_camera_and_landmark() {
        let digest = fixture_digest().expect("embedded fixture should project");
        let mut app = App::new();
        app.insert_resource(ShellProjection(digest))
            .init_resource::<Assets<Mesh>>()
            .init_resource::<Assets<StandardMaterial>>()
            .add_systems(Startup, setup_scene);

        app.update();

        let mut cameras = app.world_mut().query::<&Camera3d>();
        assert_eq!(cameras.iter(app.world()).count(), 1);
        let mut transforms = app.world_mut().query::<&Transform>();
        assert!(transforms
            .iter(app.world())
            .any(|transform| transform.translation == Vec3::new(digest.landmark_x(), 1.0, -3.0)));
    }

    #[test]
    fn camera_systems_apply_movement_and_mouse_look() {
        let mut app = App::new();
        let camera = app
            .world_mut()
            .spawn((
                Transform::default(),
                FirstPersonCamera {
                    yaw: 0.0,
                    pitch: 0.0,
                },
            ))
            .id();
        app.insert_resource(Time::<()>::default())
            .insert_resource(ButtonInput::<KeyCode>::default())
            .insert_resource(AccumulatedMouseMotion::default())
            .add_systems(Update, (move_camera, look_camera).chain());
        app.world_mut()
            .resource_mut::<ButtonInput<KeyCode>>()
            .press(KeyCode::KeyW);
        app.world_mut()
            .resource_mut::<AccumulatedMouseMotion>()
            .delta = Vec2::new(1.0, 2.0);
        app.world_mut()
            .resource_mut::<Time>()
            .advance_by(Duration::from_secs(1));

        app.update();

        let mut cameras = app.world_mut().query::<(&Transform, &FirstPersonCamera)>();
        let (transform, camera_state) = cameras
            .get(app.world(), camera)
            .expect("camera should remain in the world");
        assert_eq!(transform.translation.y.to_bits(), 1.5f32.to_bits());
        assert!(transform.translation.z < 0.0);
        assert_eq!(camera_state.yaw.to_bits(), MOUSE_SENSITIVITY.to_bits());
        assert_eq!(
            camera_state.pitch.to_bits(),
            (2.0 * MOUSE_SENSITIVITY).to_bits()
        );
    }

    #[test]
    fn camera_systems_ignore_idle_input() {
        let mut app = App::new();
        let camera = app
            .world_mut()
            .spawn((
                Transform::default(),
                FirstPersonCamera {
                    yaw: 0.0,
                    pitch: 0.0,
                },
            ))
            .id();
        app.insert_resource(Time::<()>::default())
            .insert_resource(ButtonInput::<KeyCode>::default())
            .insert_resource(AccumulatedMouseMotion::default())
            .add_systems(Update, (move_camera, look_camera).chain());

        app.update();

        let mut cameras = app.world_mut().query::<(&Transform, &FirstPersonCamera)>();
        let (transform, camera_state) = cameras
            .get(app.world(), camera)
            .expect("camera should remain in the world");
        assert_eq!(transform.translation, Vec3::ZERO);
        assert_eq!(camera_state.yaw.to_bits(), 0.0f32.to_bits());
        assert_eq!(camera_state.pitch.to_bits(), 0.0f32.to_bits());
    }

    #[test]
    fn cursor_system_locks_on_click_and_releases_on_escape() {
        let mut app = App::new();
        let cursor_entity = app.world_mut().spawn(CursorOptions::default()).id();
        app.insert_resource(ButtonInput::<MouseButton>::default())
            .insert_resource(ButtonInput::<KeyCode>::default())
            .add_systems(Update, update_cursor);

        app.update();
        let mut cursors = app.world_mut().query::<&CursorOptions>();
        assert_eq!(
            cursors.single(app.world()).unwrap().grab_mode,
            CursorGrabMode::None
        );
        app.world_mut()
            .get_mut::<CursorOptions>(cursor_entity)
            .unwrap()
            .grab_mode = CursorGrabMode::Confined;
        app.world_mut()
            .resource_mut::<ButtonInput<MouseButton>>()
            .press(MouseButton::Left);
        app.update();
        let cursor = cursors.single(app.world()).unwrap();
        assert!(!cursor.visible);
        assert_eq!(cursor.grab_mode, CursorGrabMode::Locked);

        app.world_mut()
            .resource_mut::<ButtonInput<MouseButton>>()
            .clear();
        app.world_mut()
            .resource_mut::<ButtonInput<KeyCode>>()
            .press(KeyCode::Escape);
        app.update();
        let cursor = cursors.single(app.world()).unwrap();
        assert!(cursor.visible);
        assert_eq!(cursor.grab_mode, CursorGrabMode::None);
    }

    #[test]
    fn movement_vectors_follow_wasd_axes_and_normalize_diagonals() {
        let mut keys = ButtonInput::default();
        keys.press(KeyCode::KeyW);
        keys.press(KeyCode::KeyD);

        assert_eq!(
            movement_vector(&keys),
            Vec3::new(1.0, 0.0, -1.0).normalize()
        );

        keys.press(KeyCode::KeyS);
        keys.press(KeyCode::KeyA);
        assert_eq!(movement_vector(&keys), Vec3::ZERO);
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
        assert_eq!(
            cursor_state(CursorState::Released, false, false),
            CursorState::Released
        );
        assert_eq!(
            cursor_state(CursorState::Released, true, true),
            CursorState::Released
        );
    }
}
