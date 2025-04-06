#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"


//mac 주소 출력
void print_mac(u_char *mac){
  for (int i=0; i<6; i++) {
    printf("%02x", mac[i]);
    if (i<5) {
        printf(":");
    }
  }
}

 
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  printf("Ehternet_src_mac : ");
  print_mac(eth->ether_shost); 
  printf("\n");

  printf("Ehternet_dst_mac : ");
  print_mac(eth->ether_dhost); 
  printf("\n");

  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader * ip = (struct ipheader *)
                            (packet + sizeof(struct ethheader)); 

    printf("IP_src_ip : %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("IP_dst_ip : %s\n", inet_ntoa(ip->iph_destip));    


    switch(ip->iph_protocol) {
                                 
      case IPPROTO_TCP:

        struct tcpheader* tcp = (struct tcpheader *)
                                  (packet + sizeof(struct ethheader) + sizeof(struct ipheader)); 
        
        printf("TCP_src_port : %d\n", tcp->tcp_sport);
        printf("TCP_dst_port : %d\n", tcp->tcp_dport);

        printf("**** Message ****\n");
        char* msg = (char*)(tcp+sizeof(struct tcpheader));
        for(int i=0;i<16;i++){
          printf("%02x", msg[i]);
        }
        printf("\n");
        printf("--------------------Protocol - TCP--------------------n\n");
        return;


      case IPPROTO_UDP:
        printf("--------------------Protocol - UDP--------------------n\n");
        return;

      case IPPROTO_ICMP:
        printf("--------------------Protocol - ICMP--------------------n\n");
        return;
      
      default:
        printf("--------------------Protocol - others--------------------n\n");
        return;
    } 
  }
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  //enp0s3가 아니라 eth0가 잡혀서 수정
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);  
  return 0;
}