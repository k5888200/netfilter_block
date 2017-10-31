#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <bits/stdc++.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

struct TRIE{
	bool is_end;
	TRIE *next[256];
};

TRIE trie;

const vector<const char *> HTTP_method({"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"});


void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

bool block_check(unsigned char* data, int size){
	iphdr* iph = (iphdr *)data;

	//dump(data, size);
	//dump(data, size);
	if(iph->protocol != IPPROTO_TCP) return 0;
	tcphdr* tcph = (tcphdr *)(data + (iph->ihl << 2));
	const unsigned char* payload = data + (iph->ihl << 2) + (tcph->doff << 2);
	int payload_size = htons(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
	int flag = 0;

	for(auto &http_method: HTTP_method){
		if(payload_size >= strlen(http_method) && !memcmp(payload, http_method, strlen(http_method))){
			flag = 1;
			break;
		}
	}
	if(!flag) return 0;
	unsigned char *str_host = (unsigned char *)payload;
	for(int i = -1;*str_host;str_host++){
		if(*str_host != "Host"[++i]) i = -1;
		if(i == 3) break;
	}
	str_host += 3;

	TRIE *S = &trie;
	flag = 1;
	for(char *s = (char*)str_host; *s != '\r'; s++){
		if(!(S->next[*s])){
			flag = 0;
			break;
		}
		S = S->next[*s];
	}

	//puts("");
	for(;*str_host != '\r'; str_host++) printf("%c",*str_host);
	if(flag && S->is_end){
		printf(" ----- block");
		flag = 1;
	}
	if(!S->is_end) flag = 0;
	puts("");


	return flag;
}

/* returns packet id */
static pair<u_int32_t, int> print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret, state;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		/*
		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
		*/
	}
	/*
	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
	*/
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		//printf("payload_len=%d ", ret);
		//dump(data, ret);
		unsigned char *ip_payload = (unsigned char *)malloc( (ret + 1) * sizeof(unsigned char) );
		memcpy(ip_payload, data, ret);
		state = !block_check(ip_payload, ret);
	}

	//fputc('\n', stdout);

	return make_pair(id, state);
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id;
	int state;
	tie(id, state) = print_pkt(nfa);
	//printf("entering callback\n");
	return nfq_set_verdict(qh, id, state?NF_ACCEPT:NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	FILE * in = fopen(argv[1], "r");
	char block_host[300];
	int cnt = 0;
	while(fgets(block_host, 300, in) != NULL){
		TRIE *S = &trie;
		int flag = 0;
		for(char *s = block_host; *s && *s != '\n'; s++){
			if(!flag && *s == ','){ flag = 1;continue;}
			if(!flag) {continue;}
			if(!(S->next[*s])) S->next[*s] = (TRIE *)malloc(sizeof(TRIE)), printf("%d\n",++cnt);
			S = S->next[*s];
		}
		S->is_end = true;
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);


	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
