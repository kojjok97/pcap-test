#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct Ethernet_Header{
    u_int8_t ethernet_destination[6];
    u_int8_t ethernet_source[6];
    u_int16_t ethernet_type;

}Ehternet_Header;

typedef struct IP_Header{

    u_int8_t version_header_length;
    u_int8_t TOS;
    u_int16_t total_length;
    u_int16_t identification;
    u_int16_t fragment_offset;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t header_checksum;
    u_int8_t source_address[4];
    u_int8_t destination_address[4];

}IP_Header;

typedef struct TCP_Header{

    u_int16_t source_port;
    u_int16_t destination_port;
    u_int32_t sequence_number;
    u_int32_t acknowledgement_number;
    u_int8_t offset_reserved;
    u_int8_t tcp_flags;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;

}TCP_Header;

typedef struct Payload{

    u_int8_t data[10];

}Payload;

void read_payload(u_char* packet,u_int8_t ip_header_length, u_int8_t tcp_header_length){

    packet += 14+ip_header_length+tcp_header_length;
    struct Payload* payload = (struct Payload*)packet;
    printf("=======================payload========================\n");
    printf("payload : ");
    for(int i = 0; i < 10; i++){
        printf("%02x ",payload->data[i]);
    }
    printf("\n\n\n\n");

}


u_int8_t read_TCP_header(u_char* packet, u_int8_t ip_length){

    struct TCP_Header* tcp_header;
    packet += 14+ip_length;
    tcp_header = (struct TCP_Header*)packet;
    u_int8_t offset = ((tcp_header->offset_reserved & 0xf0) >> 4)*4;


    printf("======================TCP Header======================\n");
    printf("Source Port : %d\n", ntohs(tcp_header->source_port));
    printf("Destination Port : %d\n", ntohs(tcp_header->destination_port));
    return offset;

//    u_int8_t reserved = (tcp_header->offset_reserved & 0x0f);
//    printf("%x\n", ntohl(tcp_header->sequence_number));
//    printf("%x\n", ntohl(tcp_header->acknowledgement_number));
//    printf("%d\n", offset);
//    printf("%d\n", reserved);
//    printf("%d\n", tcp_header->tcp_flags);
//    printf("%d\n", ntohs(tcp_header->window));
//    printf("%d\n", ntohs(tcp_header->checksum));
//    printf("%d\n", ntohs(tcp_header->urgent_pointer));


}

u_int8_t read_IP_header(u_char* packet){
    struct IP_Header* ip_header;
    packet += 14;
    ip_header = (struct IP_Header*)packet;

    u_int8_t header_length = (ip_header->version_header_length & 0x0f) * 4;
    printf("=======================IP Header======================\n");
    printf("Source IP Address : %d.%d.%d.%d\n",ip_header->source_address[0],ip_header->source_address[1],
                           ip_header->source_address[2],ip_header->source_address[3]);

    printf("Destination IP Address : %d.%d.%d.%d\n",ip_header->destination_address[0],ip_header->destination_address[1],
                           ip_header->destination_address[2],ip_header->destination_address[3]);

    return header_length;


//    u_int8_t version = (ip_header->version_header_length & 0xf0) >> 4;
//    u_int16_t ip_flag = (ntohs(ip_header->fragment_offset) & 0xE000) >> 8;
//    u_int16_t fragment_offset = (ntohs(ip_header->fragment_offset) & 0x1fff);
//    printf("%d\n",version);
//    printf("%d\n", header_length);
//    printf("%d\n", ip_header->TOS);
//    printf("%d\n", ntohs(ip_header->total_length));
//    printf("%d\n", ntohs(ip_header->identification));
//    printf("%d\n", ip_flag);
//    printf("%d\n", fragment_offset);
//    printf("%d\n", ip_header->ttl);
//    printf("%d\n", ip_header->protocol);
//    printf("%x\n", ntohs(ip_header->header_checksum));



}

void read_Ethernet_header(u_char* packet){
    struct Ethernet_Header * ethernet_header;
    ethernet_header = (struct Ethernet_Header*)packet;
    printf("====================Ethernet Header===================\n");
    printf("Destination Ethernet Address : %02x:%02x:%02x:%02x:%02x:%02x \n" ,ethernet_header->ethernet_destination[0],ethernet_header->ethernet_destination[1],
                                               ethernet_header->ethernet_destination[2],ethernet_header->ethernet_destination[3],
                                               ethernet_header->ethernet_destination[4],ethernet_header->ethernet_destination[5]);
    printf("Source Ehternet Address : %02x:%02x:%02x:%02x:%02x:%02x \n" ,ethernet_header->ethernet_source[0],ethernet_header->ethernet_source[1],ethernet_header->ethernet_source[2],
                                               ethernet_header->ethernet_source[3],ethernet_header->ethernet_source[4],ethernet_header->ethernet_source[5]);

    return;

}

u_int8_t check_packet_header(u_char* packet){

    struct Ethernet_Header * ethernet_header;
    struct IP_Header * ip_header;
    ethernet_header = (struct Ethernet_Header*)packet;
    packet += 14;
    ip_header = (struct IP_Header*)packet;

    if (ntohs(ethernet_header->ethernet_type) == 0x0800){
       if(ip_header->protocol == 6){
           return 1;
       }else{
           return 0;
       }


    }else{
        return 0;
    }


}


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}



        if(check_packet_header(packet) == 1){
            u_int8_t ip_length;
            u_int8_t tcp_length;
            printf("======================Packet size=====================\n");
            printf("%u bytes captured\n", header->caplen);
            read_Ethernet_header(packet);
            ip_length = read_IP_header(packet);
            tcp_length = read_TCP_header(packet,ip_length);
            read_payload(packet,ip_length,tcp_length);
        }
	}

	pcap_close(pcap);
}
