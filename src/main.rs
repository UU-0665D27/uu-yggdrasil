#[tokio::main]
async fn main() {
    let need_tun = false;
    if need_tun {
        let config = tun::configure();
        let _device = tun::create(&config).expect("tun");
    }
    println!("Hello, world!");
}
