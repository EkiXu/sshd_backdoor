use std::time::Duration;

use plain::Plain;
use libbpf_rs::{PerfBufferBuilder, Error};
use time::macros::format_description;
use time::OffsetDateTime;


mod demo {
    include!(concat!(env!("OUT_DIR"), "/demo.skel.rs"));
}

use demo::*;

unsafe impl Plain for demo_bss_types::event {}

fn handle_event(_cpu: i32, data: &[u8]) {
    // let mut event = runqslower_bss_types::event::default();
    let mut event = demo_bss_types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    let comm = std::str::from_utf8(&event.comm).unwrap();

    println!(
        "{:8} {:16} {:<7} ",
        now,
        comm.trim_end_matches(char::from(0)),
        event.pid,
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<(),Error>  {
    println!("Hello, world!");

    let mut skel_builder = DemoSkelBuilder::default();

    skel_builder.obj_builder.debug(true);


    let mut open_skel = skel_builder.open()?;


    // Begin tracing
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
    .sample_cb(handle_event)
    .lost_cb(handle_lost_events)
    .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }

}

