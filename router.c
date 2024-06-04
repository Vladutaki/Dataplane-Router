#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

// Arbore trie pentru tabela de rutare
typedef struct Trie{
	struct route_table_entry *val;
	struct Trie *child[2];
}Trie;

// Functie pentru compunerea unui pachet ICMP
void icmp(int length, int interface, uint8_t type, uint8_t code, void* oldPacket) {
    // Aloca memorie pentru un nou pachet ICMP
    void *newPacket = malloc(70);
    if (newPacket == NULL) {
        perror("Failed to allocate memory for new packet");
        return;
    }

    // Copieaza header-ul Ethernet din pachetul vechi in cel nou
    memcpy(newPacket, oldPacket, sizeof(struct ether_header));

    // Setam tipul pachetului Ethernet ca fiind IP
    struct ether_header *ether_head = (struct ether_header *) newPacket;
    ether_head->ether_type = htons(ETHERTYPE_IP);

    // Setați header-ul IP al noului pachet
    struct iphdr *old_ip_head = (struct iphdr*) (oldPacket + sizeof(struct ether_header));
    struct iphdr *ip_head = (struct iphdr*) (newPacket + sizeof(struct ether_header));
    memset(ip_head, 0, sizeof(struct iphdr)); // Clearing the header
    ip_head->version = 4;
    ip_head->ihl = 5;
    ip_head->ttl = 64;
    ip_head->protocol = IPPROTO_ICMP;
    ip_head->id = htons(1);
    ip_head->tot_len = htons(70 - sizeof(struct ether_header));
    ip_head->saddr = inet_addr(get_interface_ip(interface));
    ip_head->daddr = old_ip_head->saddr;
    ip_head->check = htons(checksum((uint16_t *) ip_head, sizeof(struct iphdr)));

    // Setam header-ul ICMP al noului pachet
    struct icmphdr *icmp_head = (struct icmphdr *) (newPacket + sizeof(struct ether_header) + sizeof(struct iphdr));
    memset(icmp_head, 0, sizeof(struct icmphdr)); // Golim header-ul
    icmp_head->type = type;
    icmp_head->code = code;

    // Copiem datele de eroare din pachetul vechi in cel nou
    void *error_data = newPacket + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    memcpy(error_data, old_ip_head, sizeof(struct iphdr) + 8);

    // Recalculam checksum-ul pachetului ICMP
    icmp_head->checksum = htons(checksum((uint16_t *) icmp_head, sizeof(struct icmphdr) + 8));

    // Trimitem pachetul
    send_to_link(interface, newPacket, 70);

    // Eliberam memoria alocata
    free(newPacket);
}

void simple_icmp(int interface, struct iphdr *ip_hdr){
	struct icmphdr *newPacket = (struct icmphdr *)((uint8_t *)ip_hdr + (sizeof (struct iphdr)));
	// Schimbarea tipului pachetului ICMP in echo reply
	newPacket->type = 0;

	// Recalcularea checksum-ului pachetului
	newPacket->checksum = 0;
	newPacket->checksum = checksum((uint16_t *)newPacket, sizeof(struct icmphdr));

	// Schimbarea adresei IP destinatie cu adresa IP sursa
	ip_hdr->daddr = ip_hdr->saddr;

	// Schimbarea adresei IP sursa cu adresa IP a interfetei
	inet_pton(AF_INET, get_interface_ip(interface), &ip_hdr->saddr);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Parsarea tabelei de rutare
	struct route_table_entry *route_table = malloc(sizeof(struct route_table_entry) * 80000);
	int route_table_len = read_rtable(argv[1], route_table);

	// Parsarea tabelei ARP
	struct arp_table_entry *mac_table = malloc(sizeof(struct arp_table_entry) * 10000);
	int mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	// Alocarea si initializarea arborelui trie pentru tabela de rutare
	Trie *route_table_trie = malloc(sizeof(Trie));
	route_table_trie->val = NULL;
	route_table_trie->child[0] = NULL;
	route_table_trie->child[1] = NULL;
	
	// Initializarea arborelui trie cu datele din tabela de rutare
	for(int i = 0; i < route_table_len; i++){
		// Prefixul in binar al entry-ului i
		uint8_t binary[32];
		//printf("Prefixul in binar al entry-ului %d: ", i);
		uint32_t prefix = ntohl(route_table[i].prefix);
		for(int j = 31; j >= 0; j--){
			binary[j] = prefix % 2;
			//printf("%d", binary[j]);
			prefix /= 2;
		}
		//printf("\n");

		// Lungimea prefixului + masca entry-ului i
		int len = 32;
		int mask = ntohl(route_table[i].mask);
		while(mask % 2 == 0){
			len--;
			mask /= 2;
		}
		//printf("Maskul entry-ului %d: %d\nPrefix + mask:", i, len);
		for(int j = 0; j < len; j++){
			//printf("%d", binary[j]);
		}
		//printf("\n");

		// Adaugarea entry-ului i in arborele trie
		Trie *current_node = route_table_trie;
		for(int j = 0; j < len; j++){
			if(current_node->child[binary[j]] == NULL){
				Trie* new_trie_entry = malloc(sizeof(struct Trie));
				new_trie_entry->val = NULL;
				new_trie_entry->child[0] = NULL;
				new_trie_entry->child[1] = NULL;
				current_node->child[binary[j]] = new_trie_entry;
				//printf("+%d", binary[j]);
			}
			else{
				//printf("%d", binary[j]);
			}
			current_node = current_node->child[binary[j]];
		}
		//printf("\n\n");
		current_node->val = &route_table[i];
	}

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		uint16_t eth_type = ntohs(eth_hdr->ether_type);
		printf("Received packet with ethertype: %d\n", eth_type);

		if(eth_type == ETHERTYPE_IP){
			// Initializarea header-ului IP
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			printf("Received packet with destination IP: %d\n", ip_hdr->daddr);

			// Verificarea destinatiei pachetului
			uint32_t interface_ip;
			inet_pton(AF_INET, get_interface_ip(interface), &interface_ip);
			printf("Interface IP: %d\n", interface_ip);
			
			// Routerul este destinatia pachetului
			if(ip_hdr->daddr == interface_ip){
				simple_icmp(interface, ip_hdr);
			}

			// Verificarea checksum-ului pachetului
			u_int16_t ip_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			if(checksum((u_int16_t*)ip_hdr, sizeof(struct iphdr)) != ntohs(ip_checksum)){
				printf("Checksum error\n");
				continue;
			}

			// Decrementarea TTL-ului pachetului
			if(ip_hdr->ttl == 0 || ip_hdr->ttl == 1){
				//TTL-ul a expirat
				icmp(len, interface, 11, 0, buf);
				printf("Time exceeded\n");
				continue;
			}
			else{
				ip_hdr->ttl--;
			}

			// Cautarea celei mai bune rute pentru pachet
			struct route_table_entry *best_route = NULL;
			Trie *current_node = route_table_trie;
			uint32_t ip_dest = ntohl(ip_hdr->daddr);
			uint8_t binary[32];
			for(int j = 31; j >= 0; j--){
				binary[j] = ip_dest % 2;
				ip_dest /= 2;
			}
			int i = 0;
			while(current_node != 0){
				if(current_node->val != 0)
					best_route = current_node->val;
				current_node = current_node->child[binary[i]];
				i++;
			}

			if(best_route == NULL){
				// Nu s-a gasit nicio ruta
				icmp(len, interface, 3, 0, buf);
				printf("Destination unreachable\n");
				continue;
			}

			// Recalcularea checksum-ului pachetului
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// Primeste si seteaza MAC-ul destinatie
			struct arp_table_entry *mac_dest = NULL;
			for (int i = 0; i < mac_table_len; i++) {
				if (ip_hdr->daddr == mac_table[i].ip) {
					mac_dest = &(mac_table[i]);
				}
			}
			memcpy(eth_hdr->ether_dhost, mac_dest->mac, 6);

			// Primeste si seteaza MAC-ul sursa
			uint8_t mac[6] = {0};
			get_interface_mac(best_route->interface, mac);
			memcpy((char*)eth_hdr->ether_shost, (char*)mac, 6);

			send_to_link(best_route->interface, buf, len);
		}
	}

	free(route_table);
	free(route_table_trie);
	free(mac_table);
}