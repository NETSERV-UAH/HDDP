/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, CPqD, Brazil  
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef PIPELINE_H
#define PIPELINE_H 1


#include "datapath.h"
#include "packet.h"
#include "flow_table.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"


struct sender;

/****************************************************************************
 * A pipeline implementation. Processes messages through flow tables,
 * including the execution of instructions.
 ****************************************************************************/

/*Modificacion UAH Discovery hybrid topologies, JAH-*/
//vecinos globales para asi poder pasar y seleccionar envios

extern struct mac_to_port neighbor_table, bt_table;
//tiempo de vida del sensor 1.5 segundos]
#define TIME_HELLO_SENSOR 1.5 
//tiempo de vida del controlador en la tabla de controladores debe ser mas 
//pequeño que el tiempo entre refresco del controlador
#define BT_TIME 20

//Tipos de dispositivos 
#define NODO_SDN 1
#define NODO_NO_SDN 2
#define NODO_SENSOR 3

/*Fin Modificacion UAH Discovery hybrid topologies, JAH-*/

/* A pipeline structure */
struct pipeline {
    struct datapath    *dp;
    struct flow_table  *tables[PIPELINE_TABLES];
};


/* Creates a pipeline. */
struct pipeline *
pipeline_create(struct datapath *dp);

/* Processes a packet in the pipeline. */
void
pipeline_process_packet(struct pipeline *pl, struct packet *pkt);

/* Handles a flow_mod message. */
ofl_err
pipeline_handle_flow_mod(struct pipeline *pl, struct ofl_msg_flow_mod *msg,
                         const struct sender *sender);

/* Handles a table_mod message. */
ofl_err
pipeline_handle_table_mod(struct pipeline *pl,
                          struct ofl_msg_table_mod *msg,
                          const struct sender *sender);

/* Handles a flow stats request. */
ofl_err
pipeline_handle_stats_request_flow(struct pipeline *pl,
                                   struct ofl_msg_multipart_request_flow *msg,
                                   const struct sender *sender);

/* Handles a table stats request. */
ofl_err
pipeline_handle_stats_request_table(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg,
                                    const struct sender *sender);

/* Handles a table feature  request. */
ofl_err
pipeline_handle_stats_request_table_features_request(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg,
                                    const struct sender *sender);

/* Handles an aggregate stats request. */
ofl_err
pipeline_handle_stats_request_aggregate(struct pipeline *pl,
                                  struct ofl_msg_multipart_request_flow *msg,
                                  const struct sender *sender);


/* Commands pipeline to check if any flow in any table is timed out. */
void
pipeline_timeout(struct pipeline *pl);

/* Detroys the pipeline. */
void
pipeline_destroy(struct pipeline *pl);

/*Modificacion UAH Discovery hybrid topologies, JAH-*/
//tratamiento de los paquetes hellos recibidos
int8_t handle_hello_packets(struct packet *pkt);
//selector de paquetes especificos del protocolo
uint8_t selecto_HDT_packets(struct packet *pkt);
//manejador de paquetes request del protocolo
uint8_t handle_hdt_request_packets(struct packet *pkt);
//manejador de paquetes replay del protocolo
uint8_t handle_hdt_reply_packets(struct packet *pkt);

//Generador de todos los paquetes que debemos enviar
void creator_dht_reply_packets(struct packet *pkt);
/*Fin Modificacion UAH Discovery hybrid topologies, JAH-*/

#endif /* PIPELINE_H */
