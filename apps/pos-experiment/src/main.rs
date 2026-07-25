#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]
fn main() {
    println!("pos-experiment: use as a library via pos_experiment crate");
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn main_is_callable() {
        // Exercises the binary entry point for coverage.
        super::main();
    }
}
