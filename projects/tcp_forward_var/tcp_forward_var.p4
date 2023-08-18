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
    //bit<3>  res;
    //bit<3>  ecn;
    //bit<6>  ctrl;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ecn;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
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
    //varbit<32>	   payload_val;
}

header my_payload2 {
    bit<8>          payload_val;
}

header_union app {
    my_payload   app1;
    my_payload2  app2;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;
    tcp_options_h   tcp_opt;
    //my_payload      my_payload_val;
    app             app_val;
}

struct fwd_metadata_t {
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    bit<16> tcpLength;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadOptionLength,
    TcpBadSackOptionLength,
    TCPPayload
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
        meta.tcpLength = hdr.ipv4.totalLen - 4 * (bit<16>)(hdr.ipv4.ihl);
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
        packet.extract(hdr.app_val.app1);
        log_msg("HLDebug: TCP payload: {} from {} to {} ", {hdr.app_val.app1.payload_val, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});

        //packet.extract(hdr.my_payload_val);
        //log_msg("HLDebug: TCP payload: {} from {} to {} ", {hdr.my_payload_val.payload_val, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
        
        //packet.extract(hdr.my_payload_val, 8 * (bit<32>)tcp_payload_size);
        //log_msg("HLDebug: TCP payload: {} from {} to {} ", {tcp_payload_size, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});

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
    register<bit<32>>(1024) syn_val;
    bit<10> flow_id;
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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

    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid()) {
                hash(flow_id, HashAlgorithm.crc32,
                     10w0,
                     { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort },
                     10w1023);
                syn_val.write( (bit<32>)flow_id, hdr.tcp.seqNo );
            }
            ipv4_lpm.apply();
        }
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  
        // Testing using union to change application layer payload
        //log_msg("HLDebug: MyEgress: Entering");
        
        if (hdr.app_val.app1.isValid()) {
            log_msg("HLDebug: MyEgress: app1 {}", {hdr.app_val.app1.payload_val});
            hdr.app_val.app2 = { hdr.app_val.app1.payload_val + 8w1 };
            //hdr.app_val.app2 = {8w97 };
            hdr.app_val.app1.setInvalid();
            //hdr.app_val.app2.setValid(); //// Do not call setValid directly here; as this function will re-initialize app2
        }
        if (hdr.app_val.app2.isValid()) {
            log_msg("HLDebug: MyEgress: app2 {}", {hdr.app_val.app2.payload_val});
        }
    }
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
        
        update_checksum_with_payload(( hdr.tcp.isValid() && hdr.app_val.app2.isValid() ),
        {   hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            8w0,
            hdr.ipv4.protocol,
            meta.tcpLength, //I changed this name, so change it back to yours
            hdr.tcp.srcPort,
            hdr.tcp.dstPort,
            hdr.tcp.seqNo,
            hdr.tcp.ackNo,
            hdr.tcp.dataOffset,
            hdr.tcp.res,
            hdr.tcp.cwr,
            hdr.tcp.ecn,
            hdr.tcp.urg,
            hdr.tcp.ack,
            hdr.tcp.psh,
            hdr.tcp.rst,
            hdr.tcp.syn,
            hdr.tcp.fin,
            hdr.tcp.window,
            16w0,
            hdr.tcp.urgentPtr,
            hdr.tcp_opt.options,
            hdr.app_val.app2.payload_val},
        hdr.tcp.checksum, HashAlgorithm.csum16);

        update_checksum_with_payload(( hdr.tcp.isValid() && hdr.app_val.app1.isValid() ),
        {   hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            8w0,
            hdr.ipv4.protocol,
            meta.tcpLength, //I changed this name, so change it back to yours
            hdr.tcp.srcPort,
            hdr.tcp.dstPort,
            hdr.tcp.seqNo,
            hdr.tcp.ackNo,
            hdr.tcp.dataOffset,
            hdr.tcp.res,
            hdr.tcp.cwr,
            hdr.tcp.ecn,
            hdr.tcp.urg,
            hdr.tcp.ack,
            hdr.tcp.psh,
            hdr.tcp.rst,
            hdr.tcp.syn,
            hdr.tcp.fin,
            hdr.tcp.window,
            16w0,
            hdr.tcp.urgentPtr,
            hdr.tcp_opt.options,
            hdr.app_val.app1.payload_val},
        hdr.tcp.checksum, HashAlgorithm.csum16);

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
        packet.emit(hdr.app_val);
        //packet.emit(hdr.my_payload_val);
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
