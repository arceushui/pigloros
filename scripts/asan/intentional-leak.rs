fn main() {
    let leaked = Box::leak(Box::new([0_u8; 1_234]));
    std::hint::black_box(leaked);
}
