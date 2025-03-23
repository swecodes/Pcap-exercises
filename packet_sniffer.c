#include<pcap.h>
#include<stdio.h>
#include<arpa/inet.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>

// callback function for packet processing
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
printf("Packet captured: length = %d \n", header ->len);

//ethernet header

struct ether_header *eth_header = (struct ether_header *)packet;
printf("Ethernet type: 0x%04x\n", ntohs(eth_header->ether_type));

//check if it is an IP packet
if (ntohs(eth_header->ether_type)==ETHERTYPE_IP){
struct ip *ip_header = (struct ip*)(packet+sizeof(struct ether_header));
char src_ip [INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRELEN];
inet_ntop(AF_INET,&(ip_header->ip_src),src_ip,INET_ADDRSTRLEN);
inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
printf('IP packet: %s -> %s \n', src_ip,dst_ip);
}
}
int main() {
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;

// find a device to sniff on
char *device = pcap_lookupdev(errbuf);
if(!device)
{ fprintf(stderr,"could not find default device: %s \n",errbuf);
return 1;}

printf("Sniffing on device : %s \n", device);

//open the device for capturing

handle = pcap_open_live(device,BUFSIZ,1,1000,errbuf);
if(!handle){
fprintf(stderr,"could not open device %s: %s \n", device,errbuf);
return 1;
}

//start packet capture (10 packets)
pcap_loop(handle, 10, packet_handler,NULL);

// close the handle
pcap_close(handle);

return 0;
}




