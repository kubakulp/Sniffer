#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>      /* socket                  */
#include <unistd.h>          /* close                   */
#include <signal.h>          /* SIGINT                  */
#include <arpa/inet.h>       /* htons,htonl,ntohl,ntohs */
#include <string.h>          /* memset                  */
#include <netinet/tcp.h>     /* tcphdr struct           */
#include <netinet/udp.h>     /* udphdr struct           */
#include <netinet/ip_icmp.h> /* icmphdr, iphdr struct   */
#include <net/if_arp.h>      /* arphdr struct           */
#include <net/ethernet.h>    /* ethhdr struct           */
#include <net/if.h>          /* ifreq struct            */
#include<sys/ioctl.h>        /* ioctl                   */

unsigned char *buffor;
int sockfd;

/* Obsluga sygnalu SIGINT oraz poprawne zamkniecie programu*/
void sgnhandle(int signal) 
{
    printf("\n");
    /* zwalniam wczesniej przydzielona pamiec do buffora */
    free(buffor);
    /* zamykam gniazdo */
    close(sockfd);
	exit(1);
}

/* Obsluga bledow */
void exit_with_perror(char *msg)
{
    perror(msg);
    exit(0);
}

/* Wczytywanie danych do odpowiednich struktur oraz wyswietlanie informacji dla wybranych protokołow */
/* Warstwa aplikacji */

void ECHO_PROTOCOL()
{
    printf("Application layer protocol name:\n");
    printf("ECHO PROTOCOL\n\n");
}

void TIME_PROTOCOL()
{
    printf("Application layer protocol name:\n");
    printf("ECHO PROTOCOL\n\n");
}

void DHCP_SERVER()
{
    printf("Application layer protocol name:\n");
    printf("DHCP server\n\n");
}

void DHCP_CLIENT()
{
    printf("Application layer protocol name:\n");
    printf("DHCP client\n\n");
}

void HTTP()
{
    printf("Application layer protocol name:\n");
    printf("HTTP\n\n");
}

void HTTPS()
{
    printf("Application layer protocol name:\n");
    printf("HTTPS\n\n");
}

/* Warstwa transportowa */
void TCP(const u_char * buffor, int length)
{
    /* Rzutowanie na odpowiednia strukture */
    struct tcphdr *tcp;	
	tcp=(struct tcphdr*) (buffor + length + sizeof(struct ethhdr));

    if( ((ntohs(tcp->source))==7) || ((ntohs(tcp->dest))==7) )
    {
        ECHO_PROTOCOL();
    }
    else
    if( ((ntohs(tcp->source))==37) || ((ntohs(tcp->dest))==37) )
    {
        TIME_PROTOCOL();
    }
    else
    if( ((ntohs(tcp->source))==67) || ((ntohs(tcp->dest))==67) )
    {
        DHCP_SERVER();
    }
    else
    if( ((ntohs(tcp->source))==68) || ((ntohs(tcp->dest))==68) )
    {
        DHCP_CLIENT();
    }
    else
    if( ((ntohs(tcp->source))==80) || ((ntohs(tcp->dest))==80) )
    {
        HTTP();
    }
    else
    if( ((ntohs(tcp->source))==443) || ((ntohs(tcp->dest))==443) )
    {
        HTTPS();
    }
    /* Wypisywanie informacji */
    printf("TCP:\n");
	printf("Source port address: %u\n",      ntohs(tcp->source));
	printf("Destination port address: %u\n", ntohs(tcp->dest));
	printf("Sequence number: %u\n",          ntohl(tcp->seq));
	printf("Acknowledgment number: %u\n",    ntohl(tcp->ack_seq));
	printf("Window size: %u\n",              ntohs(tcp->window));
	printf("Checksum: %u\n",                 ntohs(tcp->check));
	printf("Urgent pointer: %d\n\n",         ntohs(tcp->urg_ptr));
}

void UDP(const u_char * buffor, int length)
{
    /* Rzutowanie na odpowiednia strukture */
    struct udphdr *udp;	
	udp=(struct udphdr*) (buffor + length + sizeof(struct ethhdr));

    if( ((ntohs(udp->source))==7) || ((ntohs(udp->dest))==7) )
    {
        ECHO_PROTOCOL();
    }
    else
    if( ((ntohs(udp->source))==37) || ((ntohs(udp->dest))==37) )
    {
        TIME_PROTOCOL();
    }
    else
    if( ((ntohs(udp->source))==67) || ((ntohs(udp->dest))==67) )
    {
        DHCP_SERVER();
    }
    else
    if( ((ntohs(udp->source))==68) || ((ntohs(udp->dest))==68) )
    {
        DHCP_CLIENT();
    }
    else
    if( ((ntohs(udp->source))==80) || ((ntohs(udp->dest))==80) )
    {
        HTTP();
    }
    else
    if( ((ntohs(udp->source))==443) || ((ntohs(udp->dest))==443) )
    {
        HTTPS();
    }

    /* Wypisywanie informacji */
	printf("UDP:\n");
	printf("Source port: %d\n",         ntohs(udp->source));
	printf("Destination port: %d\n",    ntohs(udp->dest));
	printf("UDP length: %d\n",          ntohs(udp->len));
	printf("UDP checksum: %u\n\n",      ntohs(udp->check));	
}

/* Warstwa internetu */
void ICMP(const u_char * buffor, int length)
{	
    /* Rzutowanie na odpowiednia strukture */
	struct icmphdr *icmp;
	icmp=(struct icmphdr*) (buffor + length + sizeof(struct ethhdr));
	
	printf("ICMP\n");
	printf("Message type: %u\n",    icmp->type);
	printf("Type sub-code: %u\n",   icmp->code);
	printf("Checksum: %u\n",        ntohs(icmp->checksum));
	printf("Gateway address: %u\n", ntohl(icmp->un.gateway));	
	printf("Id: %u\n",              ntohs(icmp->un.echo.id));	
	printf("Sequence: %u\n\n",      ntohs(icmp->un.echo.sequence));	
}

void IP4(const u_char * buffor)
{		
	char source[16];
	char destination[16];
	int prot=0;
	
    /* Rzutowanie na odpowiednia strukture */
	struct iphdr *ip;
	ip=(struct iphdr*) (buffor + sizeof(struct ethhdr));	
	
	prot=ip->protocol;
	int length=ip->ihl*4;

	if(prot==1)
	{		
		ICMP(buffor,length);
	}

	if(prot==6)
	{		
        TCP(buffor,length);
	}
	if(prot==17)
	{
        UDP(buffor,length);
	}
	
    /* Wypisywanie informacji */
	printf("IPv4:\n");			
    printf("Header length with options: %u\n",  ip->ihl);
	printf("Version: %u\n",                     ip->version);
	printf("Type of service(TOS): %u\n",        ip->tos);
	printf("Full length of packet: %u\n",       ntohs(ip->tot_len));
	printf("Identification: %u\n",              ntohs(ip->id));
	printf("Fragment offset: %u\n",             ntohs(ip->frag_off));
	printf("Time to live(TTL): %u\n",           ip->ttl);
    printf("Protocol: %u\n",                    ip->protocol);
	printf("Header checksum: %u\n",             ntohs(ip->check));
	inet_ntop(AF_INET,&ip->saddr,source,16);
	printf("Source IP address: %s\n",source);
	inet_ntop(AF_INET,&ip->daddr,destination,16);
	printf("Destination IP address: %s\n\n",destination);	
}

/* Warstwa dostępu do sieci */
void ARP(const u_char * buffor)
{
    /* Rzutowanie na odpowiednia strukture */
	struct arphdr *arp;	
	arp = (struct arphdr*) (buffor + sizeof(struct ethhdr *));

    /* Wypisywanie informacji */
	printf("ARP:\n");
	printf("Format of hardware address: %u\n" ,     arp->ar_hrd);
	printf("Format of protocol address: %u\n" ,     arp->ar_pro);
	printf("Length of hardware address: %u\n" ,     arp->ar_hln);
	printf("Length of protocol address: %u\n" ,     arp->ar_pln);
	printf("ARP opcode (command):       %u\n\n" ,   arp->ar_op);
}

void ETH(const u_char * buffor)
{
    /* Rzutowanie na odpowiednia strukture */
	struct ethhdr *eth;
	eth = (struct ethhdr *)(buffor);
	
    /* Wypisywanie informacji */
	printf("ETHERNET:\n");
	printf("Source MAC address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n" , eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
	printf("Destination MAC Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n" , eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

int main(int argc, char **argv)
{
	signal(SIGINT, sgnhandle);
    int etherType;
    int saddr_size;
	struct sockaddr saddr;
	struct ethhdr *eth;	
	struct ifreq  ifr;    

    /* Przestawienie karty w tryb promisc */
	if(argc==2)
	{
		strncpy((char*)ifr.ifr_name, argv[1], IF_NAMESIZE);
		ifr.ifr_flags |= IFF_PROMISC;	
		if(ioctl(sockfd, SIOCSIFFLAGS, &ifr) != 0)
		{ 
			perror("Blad ioctl: ");
			exit(1);
		}
	}
    
    if(argc>2)
    {
        printf("Uruchom sniffera z jednym parametrem bedacym nazwa interfejsu karty lub bez parametru");
        exit(1);
    }

    /* odpowiedni socket dla sniffera */
    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        exit_with_perror("Blad socket");
    }

    while(8)
    {
        buffor = (unsigned char*)malloc(65536);
        memset(buffor,0,65536);   /* czyszczenie bufora */
        saddr_size = sizeof saddr;

        /* Czytam naglowek ethernet, wczytuje je do struktury sockaddr */
        if((recvfrom(sockfd, buffor, 65536, 0, &saddr, (socklen_t *)&saddr_size))<0)
        {
            exit_with_perror("Blad recvfrom");
        }
        
        /* a nastepnie rzutuje na strukture naglowka dla ethernet */
		eth = (struct ethhdr *)(buffor);
        
        /* Czytam etherType aby okreslic protokol warstwy wyzszej */
		etherType=ntohs(eth->h_proto);

        /* Wczytuje dane do odpowiednich struktur oraz wyswietlam informacje */
		if(etherType==2054)
		{	
			ARP(buffor);
            ETH(buffor);			
		}
		else 
        if(etherType==2048)
		{
			IP4(buffor);
            ETH(buffor);			
		}
        /* zwalniam wczesniej przydzielona pamiec do buffora */
        free(buffor);
    }
    /* zamykam gniazdo */
    close(sockfd);
}

