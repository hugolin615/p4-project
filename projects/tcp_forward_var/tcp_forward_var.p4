/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

#extern void log_msg(string msg);
#extern void log_msg<T>(string msg, in T data);

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header tcp_t {
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

// including padding size
header tcp_options_h {
    varbit<320>     options;
}

header my_payload {
   bit<8>          payload_val;          
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;
    tcp_options_h   tcp_opt;
    my_payload      my_payload_val;
}

struct fwd_metadata_t {
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadOptionLength,
    TcpBadSackOptionLength
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    bit<7> tcp_hdr_bytes_left;
    bit<16> tcp_payload_size;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        log_msg("HLDebug parse ipv4 packet");
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        verify(hdr.tcp.dataOffset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (hdr.tcp.dataOffset - 5);
        log_msg("HLDebug: TCP packet from {} to {} dataoffset {} {}", {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.dataOffset, tcp_hdr_bytes_left});
        transition select(tcp_hdr_bytes_left) {
            0 : accept; 
            default : parse_tcp_option; 
        }
    }
    
    state parse_tcp_option {
        tcp_payload_size = hdr.ipv4.totalLen - 4 * (bit<16>)hdr.ipv4.ihl - 4 * (bit<16>)hdr.tcp.dataOffset;
        log_msg("HLDebug: TCP option parsing {} {}", {(bit<32>)tcp_hdr_bytes_left, tcp_payload_size});
        packet.extract(hdr.tcp_opt, 8 * (bit<32>)tcp_hdr_bytes_left);
        //packet.extract(hdr.tcp_opt, 96);
        log_msg("HLDebug: TCP option parsing success");
        transition select(tcp_payload_size){
            0 : accept;
            default: parse_payload;
        }
        //transition accept;
    }

    state parse_payload {
        packet.extract(hdr.my_payload_val);
        //packet.extract(hdr.my_payload_val, (bit<32>)tcp_payload_size);
        log_msg("HLDebug: TCP payload: {} from {} to {} ", {hdr.my_payload_val.payload_val, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
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

    apply {
        // log_msg("HLDebug: entering MyIngress");
        if (hdr.ipv4.dstAddr == 32w167772417) {  /* 167772417 : 10.0.1.1 */
            standard_metadata.egress_spec = 1;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = 48w8796093022481;
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        } 
        if (hdr.ipv4.dstAddr == 32w167772674) {  /* for 10.0.2.2 */
            standard_metadata.egress_spec = 2;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = 48w8796093022754;
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_opt);
        packet.emit(hdr.my_payload_val);
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
