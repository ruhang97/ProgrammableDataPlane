/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// NOTE: new type added here
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> tcpPort_t;
typedef bit<2>  anon_t;
#define H2_IP_ADDRESS 0x0A000202 // 10.0.2.2
#define H1_IP_ADDRESS 0x0A000101 // 10.0.1.1

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// TODO: Update the parser to parse the anonForward header as well
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, anon_t anon) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        if (anon == 1 && hdr.tcp.isValid()) {
            if (hdr.tcp.srcPort == 5000) {
              hdr.ipv4.srcAddr = H2_IP_ADDRESS;    // change ipv4 src to h2
            }
        } else if (anon == 2 && hdr.tcp.isValid()) {
            if (hdr.tcp.dstPort == 5000) {
              standard_metadata.egress_spec = 1;
              hdr.ethernet.dstAddr = 0x080000000100;
              hdr.ipv4.dstAddr = H1_IP_ADDRESS;
            }
        }
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // Change the srcAddr of h1
    /*
    action anonForward_set_src(macAddr_t mac_dstAddr, ip4Addr_t ipv4_srcAddr, tcpPort_t tcp_srcPort, egressSpec_t port) {
       standard_metadata.egress_spec = port;
       hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
       hdr.ethernet.dstAddr = mac_dstAddr;
       hdr.ipv4.srcAddr = ipv4_srcAddr;    // change ipv4 dst address here
       hdr.tcp.srcPort = tcp_srcPort;      // change tcp dst address here
       hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    action anonForward_set_src(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table anonForward_s1 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            anonForward_set_src;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    } */

    // switch 2
    /*action anonForward_forward(macAddr_t mac_dstAddr, ip4Addr_t ipv4_dstAddr, tcpPort_t tcp_dstPort, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = mac_dstAddr;
        hdr.ipv4.dstAddr = ipv4_dstAddr;    // change ipv4 dst address here
        hdr.tcp.dstPort = tcp_dstPort;      // change tcp dst address here
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    // TODO: declare a new table: anonForward_exact
    table anonForward_exact_s2 {
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            anonForward_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }*/


    apply {
        // TODO: Update control flow: done
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            // anonForward_s1.apply();
        }
        if (hdr.tcp.isValid()) {
            // anonForward_exact_s1.apply();
            //anonForward_exact_s2.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        // TODO: emit anonForward header as well: done
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
