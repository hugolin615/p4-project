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

header Tcp_option_end_h {
    bit<8> kind;
}
header Tcp_option_nop_h {
    bit<8> kind;
}
header Tcp_option_mss_h {
    bit<8>  kind; // should be value 2
    bit<8>  length; 
    bit<16> mss;
}
header Tcp_option_window_h {
    bit<8>  kind; // should be value 3
    bit<8>  length; 
    bit<8>  sc; // shift count
}
header Tcp_option_sack_h {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}
header Tcp_option_sackpermit_h {
    bit<8>  kind;
    bit<8>  length;
}
header Tcp_option_timestamp_h {
    bit<8>  kind;
    bit<8>  length;
    bit<32> send_time;
    bit<32> recv_time;
}

header_union Tcp_option_h {
    Tcp_option_end_h  end; // 0
    Tcp_option_nop_h  nop; // 1
    Tcp_option_mss_h   mss; // 2
    Tcp_option_window_h    window;    //3
    Tcp_option_sackpermit_h sackpermit;  // 4
    Tcp_option_sack_h sack;              // 5   
    Tcp_option_timestamp_h timestamp;    // 8
}

// Defines a stack of 10 tcp options
typedef Tcp_option_h[10] Tcp_option_stack;

header Tcp_option_padding_h {
    varbit<256> padding;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t            tcp;
    Tcp_option_stack tcp_options_vec;
    Tcp_option_padding_h tcp_options_padding;
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

struct Tcp_option_sack_top
{
    bit<8> kind;
    bit<8> length;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         out Tcp_option_stack vec,
                         out Tcp_option_padding_h padding)
{
    bit<7> tcp_hdr_bytes_left;
    
    state start {
        // RFC 793 - the Data Offset field is the length of the TCP
        // header in units of 32-bit words.  It must be at least 5 for
        // the minimum length TCP header, and since it is 4 bits in
        // size, can be at most 15, for a maximum TCP header length of
        // 15*4 = 60 bytes.
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        // always true here: 0 <= tcp_hdr_bytes_left <= 40
        transition next_option;
    }
    state next_option {
        transition select(tcp_hdr_bytes_left) {
            0 : accept;  // no TCP header bytes left
            default : next_option_part2;
        }
    }
    state next_option_part2 {
        // precondition: tcp_hdr_bytes_left >= 1
        transition select(b.lookahead<bit<8>>()) {
            0: parse_tcp_option_end;
            1: parse_tcp_option_nop;
            2: parse_tcp_option_mss;
            3: parse_tcp_option_window;
            4: parse_tcp_option_sackpermit;
            5: parse_tcp_option_sack;
            8: parse_tcp_option_timestamp;
        }
    }
    state parse_tcp_option_end {
        b.extract(vec.next.end);
        // TBD: This code is an example demonstrating why it would be
        // useful to have sizeof(vec.next.end) instead of having to
        // put in a hard-coded length for each TCP option.
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition consume_remaining_tcp_hdr_and_accept;
    }
    state consume_remaining_tcp_hdr_and_accept {
        // A more picky sub-parser implementation would verify that
        // all of the remaining bytes are 0, as specified in RFC 793,
        // setting an error and rejecting if not.  This one skips past
        // the rest of the TCP header without checking this.

        // tcp_hdr_bytes_left might be as large as 40, so multiplying
        // it by 8 it may be up to 320, which requires 9 bits to avoid
        // losing any information.
        b.extract(padding, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }
    state parse_tcp_option_nop {
        b.extract(vec.next.nop);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        log_msg("HLDebug: TCP option NOP {} {} {}", {vec.size, vec.lastIndex, tcp_hdr_bytes_left});
        transition next_option;
    }
    state parse_tcp_option_mss {
        //verify(tcp_hdr_bytes_left >= 4, error.TcpOptionTooLongForHeader);
        bit<8> option_len = b.lookahead<Tcp_option_sack_top>().length;
        //bit<32> cur_index = vec.lastIndex;
        verify(option_len == 4, error.TcpBadOptionLength);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 4;
        b.extract(vec.next.mss);
        //b.extract(vec[Tcp_option_stack.nextIndex].mss);
        //vec[vec.lastIndex].mss.setValid();
        //bit<8> temp = vec[vec.lastIndex].mss.kind;
        // Hui Lin: I still cannot figure out how to extract option values; but not needed at this moment
        log_msg("HLDebug: TCP option MSS {} {} {}", {vec.size, vec.lastIndex, tcp_hdr_bytes_left});
        transition next_option;
    }
    state parse_tcp_option_window {
        bit<8> option_len = b.lookahead<Tcp_option_sack_top>().length;
        // verify(tcp_hdr_bytes_left >= 4, error.TcpOptionTooLongForHeader);
        verify(option_len == 3, error.TcpBadOptionLength);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 3;
        b.extract(vec.next.window);
        log_msg("HLDebug: TCP option WINDOW {} {} {}", {vec.size, vec.lastIndex, tcp_hdr_bytes_left});
        transition next_option;
    }
    state parse_tcp_option_sackpermit {
        bit<8> option_len = b.lookahead<Tcp_option_sack_top>().length;
        verify(option_len == 2, error.TcpBadOptionLength);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 2;
        b.extract(vec.next.sackpermit);
        log_msg("HLDebug: TCP option SACK PERMIT {} {} {}", {vec.size, vec.lastIndex, tcp_hdr_bytes_left});
        transition next_option;
    }
    state parse_tcp_option_sack {
        bit<8> n_sack_bytes = b.lookahead<Tcp_option_sack_top>().length;
        // I do not have global knowledge of all TCP SACK
        // implementations, but from reading the RFC, it appears that
        // the only SACK option lengths that are legal are 2+8*n for
        // n=1, 2, 3, or 4, so set an error if anything else is seen.
        verify(n_sack_bytes == 10 || n_sack_bytes == 18 ||
               n_sack_bytes == 26 || n_sack_bytes == 34,
               error.TcpBadSackOptionLength);
        verify(tcp_hdr_bytes_left >= (bit<7>) n_sack_bytes,
               error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - (bit<7>) n_sack_bytes;
        b.extract(vec.next.sack, (bit<32>) (8 * n_sack_bytes - 16));
        transition next_option;
    }
    state parse_tcp_option_timestamp {
        bit<8> option_len = b.lookahead<Tcp_option_sack_top>().length;
        verify(option_len == 10, error.TcpBadOptionLength);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 10;
        b.extract(vec.next.timestamp);
        log_msg("HLDebug: TCP option TIMESTAMP {} {} {}", {vec.size, vec.lastIndex, tcp_hdr_bytes_left});
        transition next_option;
    }
}

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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        log_msg("HLDebug: TCP packet fromi {} to {} ", {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
        Tcp_option_parser.apply(packet, hdr.tcp.dataOffset,
                                hdr.tcp_options_vec, hdr.tcp_options_padding);
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
        packet.emit(hdr.tcp_options_vec);
        packet.emit(hdr.tcp_options_padding);
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
