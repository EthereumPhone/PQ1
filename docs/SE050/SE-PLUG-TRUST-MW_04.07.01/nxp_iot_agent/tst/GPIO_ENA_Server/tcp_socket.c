/*
 * Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
#include "tcp_socket.h"
#include "gpio_ena_controller.h"

#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/err.h"

#define PORT 25001

enum connection_state { CONN_ACCEPTED = 0, CONN_WAITING= 1, CONN_CLOSING=2 };

enum connection_state connection_state_ = CONN_WAITING;
static struct tcp_pcb* tcp_pcb;

void close_connection(struct tcp_pcb* tpcb) {
	PRINTF("INFO: Close connection\n\r");
	tcp_close(tpcb);
}

static err_t tcp_sent_callback(void *arg, struct tcp_pcb *tpcb, u16_t len) {
	LWIP_UNUSED_ARG(len);

	PRINTF("INFO: Packet has been sent\n\r");
	if(connection_state_ == CONN_CLOSING) {
		close_connection(tpcb);
	}

	return ERR_OK;
}

static err_t tcp_recv_callback(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
	err_enum_t ret_err = ERR_ABRT;
	if(p != NULL) {
		if(connection_state_ == CONN_ACCEPTED) {
			//Expected: uint32_t and character
			char port_to_enable = *((char*) p->payload);
			uint8_t pin_to_enable = atoi(((char*) p->payload + 1));
			PRINTF("INFO: Received: %d %c\n\r", pin_to_enable, port_to_enable);

			enum return_state ret = enable_pin(pin_to_enable, port_to_enable);
			PRINTF("INFO: enable_pin returns %d\n\r", (int) ret);
			if(tcp_write(tpcb, &ret, sizeof(ret), 1) == ERR_OK) {
				ret_err = tcp_output(tpcb);
				if(ret_err != ERR_OK) {
					PRINTF("ERROR: error in tcp_output: %d\n\r", (int) ret_err);
				}
				else {
					PRINTF("INFO: free pbuf\n\r");
					pbuf_free(p);
				}
			}
			else
				PRINTF("ERROR: Failed tcp_write\n\r");


			connection_state_ = CONN_CLOSING;
		}
		else {
			ret_err = ERR_ABRT;
			PRINTF("ERROR: Received packet without accepting connection.\n\r");
		}
	}
	else {
		close_connection(tpcb);
		//PRINTF("INFO: Would have closed connection\n\r");
		ret_err = ERR_OK;
	}

	return ret_err;
}

static err_t tcp_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err) {
	PRINTF("INFO: Accpeted connection\n\r");
	connection_state_ = CONN_ACCEPTED;

	tcp_recv(newpcb, tcp_recv_callback);
	tcp_sent(newpcb, tcp_sent_callback);
	return ERR_OK;
}

void init_tcp_socket() {
	tcp_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
	if (tcp_pcb != NULL) {
		err_t err;

		err = tcp_bind(tcp_pcb, IP_ANY_TYPE, PORT);
		if (err == ERR_OK) {
			tcp_pcb = tcp_listen(tcp_pcb);
			tcp_accept(tcp_pcb, tcp_accept_callback);
		} else {
			PRINTF("ERROR: binding tcp pcb to port %d\n\r", PORT);
		}
	} else {
		PRINTF("ERROR: creating tcp pcb\n\r", PORT);
	}
}

