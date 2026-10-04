fn main() {
    if let Err(error) = outbound_witness_proxy::run_from_env() {
        eprintln!("outbound-witness-proxy: {error}");
        std::process::exit(2);
    }
}
