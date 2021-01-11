/* 
 * This file is part of the HDDP Switch distribution (https://github.com/gistnetserv-uah/HDDP).
 * Copyright (c) 2020.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include "datapath.h"
#include "dp_buffers.h"
#include "dp_actions.h"
#include "packet.h"
#include "packets.h"
#include "action_set.h"
#include "ofpbuf.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-print.h"
#include "util.h"


struct packet *
packet_create(struct datapath *dp, uint32_t in_port,
    struct ofpbuf *buf, bool packet_out) {
    struct packet *pkt;

    pkt = xmalloc(sizeof(struct packet));

    pkt->dp         = dp;
    pkt->buffer     = buf;
    pkt->in_port    = in_port;
    pkt->action_set = action_set_create(dp->exp);

    pkt->packet_out       = packet_out;
    pkt->out_group        = OFPG_ANY;
    pkt->out_port         = OFPP_ANY;
    pkt->out_port_max_len = 0;
    pkt->out_queue        = 0;
    pkt->buffer_id        = NO_BUFFER;
    pkt->table_id         = 0;

    pkt->handle_std = packet_handle_std_create(pkt);
    return pkt;
}

struct packet *
packet_clone(struct packet *pkt) {
    struct packet *clone;

    clone = xmalloc(sizeof(struct packet));
    clone->dp         = pkt->dp;
    clone->buffer     = ofpbuf_clone(pkt->buffer);
    clone->in_port    = pkt->in_port;
    /* There is no case we need to keep the action-set, but if it's needed
     * we could add a parameter to the function... Jean II
     * clone->action_set = action_set_clone(pkt->action_set);
     */
    clone->action_set = action_set_create(pkt->dp->exp);


    clone->packet_out       = pkt->packet_out;
    clone->out_group        = OFPG_ANY;
    clone->out_port         = OFPP_ANY;
    clone->out_port_max_len = 0;
    clone->out_queue        = 0;
    clone->buffer_id        = NO_BUFFER; // the original is saved in buffer,
                                         // but this buffer is a copy of that,
                                         // and might be altered later
    clone->table_id         = pkt->table_id;

    clone->handle_std = packet_handle_std_clone(clone, pkt->handle_std);

    return clone;
}

void
packet_destroy(struct packet *pkt) {
    /* If packet is saved in a buffer, do not destroy it,
     * if buffer is still valid */
     
    if (pkt->buffer_id != NO_BUFFER) {
        if (dp_buffers_is_alive(pkt->dp->buffers, pkt->buffer_id)) {
            return;
        } else {
            dp_buffers_discard(pkt->dp->buffers, pkt->buffer_id, false);
        }
    }

    action_set_destroy(pkt->action_set);
    ofpbuf_delete(pkt->buffer);
    packet_handle_std_destroy(pkt->handle_std);
    free(pkt);
}

char *
packet_to_string(struct packet *pkt) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    fprintf(stream, "pkt{in=\"");
    ofl_port_print(stream, pkt->in_port);
    fprintf(stream, "\", actset=");
    action_set_print(stream, pkt->action_set);
    fprintf(stream, ", pktout=\"%u\", ogrp=\"", pkt->packet_out);
    ofl_group_print(stream, pkt->out_group);
    fprintf(stream, "\", oprt=\"");
    ofl_port_print(stream, pkt->out_port);
    fprintf(stream, "\", buffer=\"");
    ofl_buffer_print(stream, pkt->buffer_id);
    fprintf(stream, "\", std=");
    packet_handle_std_print(stream, pkt->handle_std);
    fprintf(stream, "}");

    fclose(stream);
    return str;
}

/*Modificacion UAH Discovery hybrid topologies, JAH-*/

/* Paquetes HELLO para descubrir sensores virtuales */
void packet_hello_send(void)
{
    dp_actions_output_port(pkt_hello, OFPP_FLOOD, pkt_hello->out_queue, pkt_hello->out_port_max_len, 0xffffffffffffffff);
}

struct packet * packet_hello_create(struct datapath *dp, uint32_t in_port, bool packet_out)
{
        struct packet *pkt = NULL;
        struct ofpbuf *buf = NULL;
        uint8_t Total[44] = {0}, Mac[ETH_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF} , 
            type_array[2] = {0x76, 0x98};
        uint16_t eth_type = 0x9876, type_device = htons(type_sensor);

        //Creamos el buffer del paquete
        buf = ofpbuf_new(46); //sizeof(struct eth_header));
        //lo rellenamos con la broadcast
        ofpbuf_put(buf, Mac, ETH_ADDR_LEN);
        //lo rellenamos con la mac switch       
        ofpbuf_put(buf, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN);
        //le metemos el eth Type
        ofpbuf_put(buf, type_array, 2);
        //indicamos el tipo de sensor
        ofpbuf_put(buf, &type_device, sizeof(type_device));
        //rellenamos
        ofpbuf_put(buf, Total, 44);
        //Creamos el buffer del paquete
        pkt = packet_create(dp, in_port, buf, packet_out);

        //creamos la cabecera eth y le metemos los valores que queremos
        pkt->handle_std->proto->eth = xmalloc(sizeof(struct eth_header));
        memcpy(pkt->handle_std->proto->eth->eth_dst, Mac, ETH_ADDR_LEN);
        memcpy(pkt->handle_std->proto->eth->eth_src, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN);
        pkt->handle_std->proto->eth->eth_type = eth_type;

        pkt->handle_std->valid = false;
        packet_handle_std_validate(pkt->handle_std);

    return pkt;
}

/*Modificacion UAH Discovery hybrid topologies, JAH-*/
struct packet * create_dht_reply_packet(struct datapath *dp, uint8_t * mac_dst,
    uint32_t in_port, uint32_t out_port, uint16_t type_device, uint64_t mac_device_64, uint16_t num_devices)
{
    /*                                 Estructura del paquete
     * ----------------------------------------------------------------------------------
     * | ETH HEADER | OPCODE 2B | NUM DEVICE 2B |
     * | struct 1 = [TYPE DEVICE 4B |MAC DEVICE X 8B | IN_PORT X 4B | OUT_PORT X 4B] |
     * | struct 2 ... struct 30 | 
     * | struct 31 = [TYPE DEVICE 4B | MAC DEVICE X 8B | IN_PORT X 4B | OUT_PORT X 4B] | 
     * ---------------------------------------------------------------------------------- 
    */

    struct packet *pkt = NULL;
    struct ofpbuf *buffer2;
    
    uint16_t opcode = bigtolittle16(0x0002), etherType = bigtolittle16(ETH_TYPE_DHT), 
        type_devices[DHT_MAX_ELEMENTS] = {0};
    uint64_t mac[DHT_MAX_ELEMENTS]={0};
    uint32_t out_ports[DHT_MAX_ELEMENTS] = {0}, in_ports[DHT_MAX_ELEMENTS] = {0};
   
    //Dejamos los datos prepados para insertar
    //si solo transmitimos la informacion del nodo
    if (num_devices == 0x0001){
        //Solo información del nodo
        num_devices = htons(num_devices);
        type_devices[0] = htons(type_device);
        mac[0] = bigtolittle64(mac_device_64);
        in_ports[0] = htonl(in_port);
        out_ports[0] = htonl(out_port);         
    } else {
        //modificamos el valor de num_devices
        num_devices = htons(num_devices);
        //primero información del sensor
        type_devices[0] = htons(type_device);
        mac[0] = bigtolittle64(mac_device_64);
        in_ports[0] = htonl(1);
        out_ports[0] = htonl(1); 
        //segundo información del nodo
        type_devices[1] = htons(NODO_NO_SDN);
        mac[1] = bigtolittle64(mac2int(dp->ports[1].conf->hw_addr)); 
        in_ports[1] = htonl(in_port);
        out_ports[1] = htonl(out_port);
    }

    //Now, create the packet and add the Ethernet header
    buffer2= ofpbuf_new( sizeof(struct eth_header) + sizeof(struct dht_header));
    ofpbuf_put(buffer2, mac_dst, ETH_ADDR_LEN); 
    ofpbuf_put(buffer2, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN);
    ofpbuf_put(buffer2, &etherType, sizeof(uint16_t));
    
    //Now, create the HDP header
    ofpbuf_put(buffer2,&opcode, sizeof(uint16_t));
    ofpbuf_put(buffer2,&num_devices, sizeof(uint16_t));
    ofpbuf_put(buffer2,type_devices, sizeof(uint16_t)*DHT_MAX_ELEMENTS);
    ofpbuf_put(buffer2,mac, sizeof(uint64_t)*DHT_MAX_ELEMENTS);
    ofpbuf_put(buffer2,in_ports, sizeof(uint32_t)*DHT_MAX_ELEMENTS);
    ofpbuf_put(buffer2,out_ports, sizeof(uint32_t)*DHT_MAX_ELEMENTS);

    //Creamos la estructura del paquete
    pkt = packet_create(dp, in_port, buffer2, false);

    //Creamos la cabecera ethernet
    pkt->handle_std->proto->eth = xmalloc(sizeof(struct eth_header));
    memcpy(pkt->handle_std->proto->eth->eth_dst, mac_dst, ETH_ADDR_LEN);
    memcpy(pkt->handle_std->proto->eth->eth_src, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN);
    //Insertamos el eth al reves por tema de little endian
    pkt->handle_std->proto->eth->eth_type=ETH_TYPE_DHT_INV;

    //creamos la cabecera de nuestro protocolo
    pkt->handle_std->proto->dht=xmalloc(sizeof(struct dht_header));
    pkt->handle_std->proto->dht->opcode = opcode;
    pkt->handle_std->proto->dht->num_devices = num_devices;
    memcpy(&pkt->handle_std->proto->dht->type_devices,type_devices,sizeof(uint16_t)*DHT_MAX_ELEMENTS);
    memcpy(&pkt->handle_std->proto->dht->macs,mac,sizeof(uint64_t)*DHT_MAX_ELEMENTS);
    memcpy(&pkt->handle_std->proto->dht->in_ports, in_ports,sizeof(uint32_t)*DHT_MAX_ELEMENTS);
    memcpy(&pkt->handle_std->proto->dht->out_ports, out_ports,sizeof(uint32_t)*DHT_MAX_ELEMENTS);

    //validamos el paquete
    packet_handle_std_validate(pkt->handle_std);
    return pkt;
}

void update_data_request(struct packet * pkt){
    //actualizo el numero de saltos para control de posibles enlaces perdidos
    uint64_t num_elements=pkt->handle_std->proto->dht->num_devices;
    
    pkt->handle_std->proto->dht->num_devices = htons(bigtolittle16(num_elements)+1);
    pkt->packet_out=false;
    pkt->handle_std->valid = false;
    packet_handle_std_validate(pkt->handle_std);
}

uint16_t update_data_reply(struct packet * pkt, uint32_t out_port, uint16_t type_device){

    //Mod the last element of the packet (sw|out_port)
    uint16_t num_elements=bigtolittle16(pkt->handle_std->proto->dht->num_devices) + 1;

    if (num_elements > DHT_MAX_ELEMENTS)
        return num_elements;

    //Puerto de entrada sentido SRC->DST
    pkt->handle_std->proto->dht->num_devices = htons(num_elements);
    pkt->handle_std->proto->dht->type_devices[num_elements-1]=htons(type_device);
    pkt->handle_std->proto->dht->macs[num_elements-1]=bigtolittle64(mac2int(pkt->dp->ports[1].conf->hw_addr));
    pkt->handle_std->proto->dht->in_ports[num_elements-1]=htonl(pkt->in_port);
    pkt->handle_std->proto->dht->out_ports[num_elements-1]=htonl(out_port);

    pkt->packet_out=false;
    pkt->handle_std->valid = false;
    packet_handle_std_validate(pkt->handle_std);
    return 0;
}

/*Fin Modificacion UAH Discovery hybrid topologies, JAH-*/
