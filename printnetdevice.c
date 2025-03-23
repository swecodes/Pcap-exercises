#include<pcap.h>
#include<stdio.h>

int main(){
char errbuf[PCAP_ERRBUF_SIZE]; //ERROR BUFFER TO STORE ERROR MESSAGES

//find a default network device

char *device = pcap_lookupdev(errbuf);

if(device == NULL){
fprintf(stderr, "error finding device: %s \n", errbuf);
return 1;
}

printf("Default network device: %s\n",device);

return 0;
}
