#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>

// callback function to process packets

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
printf("Packet captured: \n");
printf("Timestamp: %s",ctime((const time_t*)&header->ts.tv_sec));
printf("Packet Length: %d bytes \n", header->len);
printf("--------------------------------\n");
}

int main(){

char errbuf[PCAP_ERRBUF_SIZE]; // buffer for error messages
char *device; //device to sniff on

// find the default device

device = pcap_lookupdev(errbuf);
if(device ==NULL){
fprintf(stderr,"Error finding device: %s \n",errbuf);
return 1;
}
printf("Using device %s \n",device);

//open the device for live capture
pcap_t *handle = pcap_open_live(device,BUFSIZ,1,1000,errbuf);

if(handle == NULL){
fprintf(stderr,"Could not open device %s: \n",device,errbuf);
return 1;
}
printf("Listening on %s.....\n",device);

//start capturing packets
pcap_loop(handle, 10, packet_handler, NULL);

//close the handle

pcap_close(handle);

return 0;
}
