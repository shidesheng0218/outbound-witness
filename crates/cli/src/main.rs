fn main() {
    match outbound_witness::run(std::env::args().collect()) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("错误: {error}");
            std::process::exit(2);
        }
    }
}
