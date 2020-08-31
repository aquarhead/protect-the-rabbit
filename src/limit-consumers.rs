#![no_std]
#![no_main]
use core::mem::size_of;
use memoffset::offset_of;
use redbpf_macros::map;
use redbpf_probes::tc::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[derive(Clone, Debug)]
#[repr(C)]
struct Source {
  addr: u32,
  port: u32, // should be u16, but need padding (?)
}

#[map("counts")]
static mut counts: HashMap<Source, u8> = HashMap::with_max_entries(10240);

#[tc_action]
fn limit(skb: SkBuff) -> TcActionResult {
  let eth_proto: u16 = skb.load(offset_of!(ethhdr, h_proto))?;
  //Only look at IPv4 TCP packets
  if eth_proto as u32 != ETH_P_IP {
    return Ok(TcAction::Ok);
  }

  let ip_start = size_of::<ethhdr>();
  let ip_proto: u8 = skb.load(ip_start + offset_of!(iphdr, protocol))?;
  let ip_len = ((skb.load::<u8>(ip_start)? & 0x0F) << 2) as usize;
  // Only look at TCP packets
  if ip_proto as u32 != IPPROTO_TCP {
    return Ok(TcAction::Ok);
  }

  let tcp_start = ip_start + ip_len;
  let dest_port: u16 = skb.load(tcp_start + offset_of!(tcphdr, dest))?;
  // Only look at RabbitMQ traffic
  if dest_port != 5672 {
    return Ok(TcAction::Ok);
  }

  let data_offset = (skb.load::<u8>(tcp_start + 12)? >> 4) << 2;
  let data_start = tcp_start + data_offset as usize;

  let src_addr: u32 = skb.load(ip_start + offset_of!(iphdr, saddr))?;
  let src_port: u16 = skb.load(tcp_start + offset_of!(tcphdr, source))?;
  let src = Source {
    addr: src_addr,
    port: src_port as u32,
  };

  let amqp_type: u8 = skb.load(data_start)?;
  let amqp_class: u16 = skb.load(data_start + 7)?;

  // "METHOD" type and "Basic" class
  if amqp_type == 1 && amqp_class == 60 {
    let amqp_method: u16 = skb.load(data_start + 9)?;

    let cnt = unsafe { counts.get_mut(&src) };

    if amqp_method == 20 {
      // "consume" method
      match cnt {
        // trick to avoid relocation error, not using &1
        None => unsafe { counts.set(&src, &amqp_type) },
        Some(n) if *n >= 10 => {
          return Ok(TcAction::Shot);
        }
        Some(n) => *n += 1,
      }
    } else if amqp_method == 30 {
      // "cancel" method
      match cnt {
        Some(1) => unsafe { counts.delete(&src) },
        Some(n) => *n -= 1,
        None => {}
      }
    }
  }

  Ok(TcAction::Ok)
}
