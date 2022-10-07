/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

struct metadata { }


const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Registers for checking our l2_cache
register<bit>(256) l2_cache_valid;
register<bit<32>>(256) l2_cache_vals;

// Ethernet II header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// IPv4 header
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// UDP header 
header udp_t {
    bit<16> source_port;
    bit<16> dest_port;
    bit<16> udp_length;
    bit<16> checksum;
}

// Request header
header req_t{
    bit<8> key;
}

// Response header
header res_t{
    bit<8> key;
    bit<8> is_valid;
    bit<32> value;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    req_t req;
    res_t res;
 }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    // Begin by parsing the ethernet header
    state start {
        transition parse_ethernet;
    }

    /** 
        Extract the ethernet header.
        If the next header is ipv4, then parse ipv4.
        Else, reject the packet.
    **/
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
        }
    }

    /**
        Extract the IPv4 Header.
        If the next header is UDP, then parse UDP.
        Otherwise, reject the packet.
    */
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            0x11: parse_udp;
        }
    }

    /**
        Extract the UDP header.
        If the dest_port is 1234,
        parse the request header.
        Otherwise, parse the response header or 
        nothing.
    */
    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dest_port){
            1234: parse_req;

            default: parse_res_or_regular_traffic;
        }
    }
    
    /**
        Parse the request header and accept.
    */
    state parse_req{
        packet.extract(hdr.req);
        transition accept;
    }

    /**
        Parse the response header and accept.
    */
    state parse_res_or_regular_traffic{
        transition select(hdr.udp.source_port){
            1234: parse_res;
            default: accept;
        }
    }

    state parse_res{
        packet.extract(hdr.res);
        transition accept;
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Action to return a response to the client when there is a a cache hit.
    action reply() {
        // Swap the port to go back to the ingress port
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        
        // Swap the ethernet MAC addresses
        macAddr_t tmpDstMac = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmpDstMac;

        // Swap the IPv4 addresses
        ip4Addr_t tmpDstIp = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = tmpDstIp;

        // Swap the UDP ports
        bit<16> tmpDstPort = hdr.udp.dest_port;
        hdr.udp.dest_port = hdr.udp.source_port;
        hdr.udp.source_port = tmpDstPort;

        // Make the checksum 0 so that it is not checked
        hdr.udp.checksum = 0;
    }

    // ipv4_forward forwards the 
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
            standard_metadata.egress_spec = port;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = dstAddr;
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // IPv4 forwarding table
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // Update the headers of the packet for replying using the cache.
    action update(bit<32> value){
        hdr.res = {hdr.req.key, 1, value};
        hdr.req.setInvalid();
        hdr.res.setValid();
        hdr.udp.udp_length = hdr.udp.udp_length + 5;
        hdr.udp.checksum = 0;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 5;
        standard_metadata.packet_length = standard_metadata.packet_length + 5;
    }

    // Cache table
    table cache {
        key = {
            hdr.req.key: exact;
        }

        actions = {
            update;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    
    apply {
        // If the destination port is the server and it is a request
        if(hdr.udp.dest_port == 1234 && hdr.req.isValid()){
            // Apply the cache
            cache.apply();
            // If there was a cache hit, respond using the result.
            if (hdr.res.isValid() && (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0)) {    
                reply();
            } else {
                // Check if the value is in the register cache.
                bit in_reg;
                l2_cache_valid.read(in_reg, (bit<32>)hdr.req.key);
                // If the value is in the register cache update,
                // update the packet with the response header and reply.
                if(in_reg == 1){
                    bit<32> cached_val;
                    l2_cache_vals.read(cached_val, (bit<32>)hdr.req.key);
                    update(cached_val);
                    reply();
                } else{
                    // Otherwise forward as usual.
                    ipv4_lpm.apply();
                }
            }
        } else {
            // Otherwise if it is from the server and a valid result, update the registers.
            if(hdr.udp.source_port == 1234 && hdr.res.isValid() && hdr.res.is_valid == 1){
                l2_cache_valid.write((bit<32>)hdr.res.key, 1);
                l2_cache_vals.write((bit<32>)hdr.res.key, hdr.res.value);
            }
            // If the ipv4 header is valid, forward as usual.
            if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
                ipv4_lpm.apply();
            }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.res);
        packet.emit(hdr.req);
    }
    
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
