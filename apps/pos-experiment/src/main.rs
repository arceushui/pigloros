fn main() {
    println!("pos-experiment: use as a library via pos_experiment crate");
}

#[cfg(test)]
mod tests {
    #[test]
    fn main_is_callable() {
        // Exercises the binary entry point for coverage.
        super::main();
    }
}
