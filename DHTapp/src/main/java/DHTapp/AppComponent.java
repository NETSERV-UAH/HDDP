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
package DHTapp;

import org.apache.felix.scr.annotations.*;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.config.*;
import org.onosproject.net.device.*;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostProvider;
import org.onosproject.net.host.HostProviderService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.*;
import org.onosproject.net.packet.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/** Modificar la topologia en ONOS */
    import org.onosproject.net.PortNumber;

    /** Librerias para enlaces */
import org.onosproject.net.provider.ProviderId;
import org.onosproject.net.LinkKey;

    /** Librerias para devices */

/** Librerias para Host */
    import org.onosproject.net.host.HostProviderRegistry;
import sun.net.PortConfig;

/** Librerias para recursos */
    import static com.google.common.base.Preconditions.checkNotNull;
import static org.onosproject.net.PortNumber.portNumber;

/**
 * @brief Logica del protocolo de descubrimiento de topologias hibridas UAH
 * @author Joaquin Alvarez Horcajo
 *
 * Skeletal ONOS application component.
 */

@Component(immediate = true)
public class AppComponent{
    /** Tiempo de eliminacion de dispositivos */
    private final long TIME_DELETE_DEVICE = 15; //(s)
    /** Tiempo de refresco */
    private final long TIME_REFRESH = 3000l, TIME_DELETE = 3000l;
    private long Time_delete = 0;
    /** MAC Propia del protocolo */
    private final String MAC_GENERIC = "AA:BB:CC:DD:EE:FF";
    /** Opction code del protocolo */
    private final short OPCODE_DHT_REQUEST = 1, OPCODE_DHT_REPLY = 2;

    /** @brieg Servicio de Log*/
    private final Logger log = LoggerFactory.getLogger(getClass());

    /** @brief Servicio para interactuar con el inventario de enlaces */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private LinkService linkService;

    /** @brief Servicio para iterceptar paquetes recibidos y emitir paquetes de salida */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private PacketService packetService;

    /** @brief Servicio para interactuar con el nucleo del sistema del controlador */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private CoreService coreService;

    /** @brief Servicio para interactuar con el inventario de dispositivos */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private DeviceService deviceService;

    /** @brief Servicio para interactuar con el inventario de dispositivos */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private HostService hostService;

    /** @brief Direccion MAC broadcast */
    private final String ETHERNET_BROADCAST_ADDRESS = "FF:FF:FF:FF:FF:FF";

    /** @brief Procesador de paquetes recibidos */
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigRegistry netCfgService;

    /** @brief Identificador de la aplicacion en Onos*/
    private ApplicationId appId;

    /** @brief Servicio de planificacion de tareas*/
    ScheduledExecutorService scheduledExecutorService = null;

    /** Topologia */
    /** register de los elementos de la red*/
    public static ProviderId PID;
    private LinkProvider linkProvider = new StubLinkProvider();
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected LinkProviderRegistry linkProviderRegistry;

    private DeviceProvider deviceProvider = new StubDeviceProvider();
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceProviderRegistry deviceProviderRegistry;

    private HostProvider hostProvider = new StubHostProvider();
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostProviderRegistry hostProviderRegistry ;


    /** @brief Lista de enlaces de la topologia*/
    protected Set<LinkKey> configuredLinks = new HashSet<>();

    /** Provider de servercios para elementos de red */
    private LinkProviderService linkProviderService;
    private DeviceProviderService deviceProviderService;
    private HostProviderService hostProviderService;

    /**Clase para manejar los enlaces */
    private DHTproviderlink DHTlink = new DHTproviderlink(PID);
    /**Clase para manejar los devices */
    private DHTproviderdevices DHTdevices = new DHTproviderdevices(PID);
    /**Clase para manejar los host */
    private DHTproviderhost DHThost = new DHTproviderhost(PID);

    private String[] TYPE_SENSORS  = new String[] {
            "TEMPERATURE", "WIND", "PRESSURE", "LIGHT", "ACCELEROMETER",
            "VIBRATION", "GIROSCOPE", "PROXIMITY", "DISTANCE", "MOVEMENT", "SMOKE",
            "MAGNETISM", "HUMIDITY"};

    /**Modo de funcionamiento */
    /** Modo 0 = no se permite que los sensores se interconecten entre ellos
    Modo 1 = Se permite la conexion entre sensores */
    private short modeDHT = 1;

    /**Enlaces guardados entre elementos SDN*/
    Map<String, Integer> link_sdn_nodes = new HashMap<String, Integer>();

    /** Estadisticos */
    Integer Num_packet_out = 0, Num_packet_in = 0, Num_packet_data = 0;

    /** @brief Funcion de activacion de la aplicacion. Punto de entrada al programa  */
    @Activate
    protected void activate() {
        try{
            log.info("COMENZAMOS CON LA APLICACION");

            appId = coreService.registerApplication("DHT.NetServ.UAH");

            PID = new ProviderId("cfg", "DHT.NetServ.UAH", true);

            packetService.addProcessor(processor, PacketProcessor.advisor(2)); //.director(2));

            scheduledExecutorService = Executors.newScheduledThreadPool(1);

            /**Registramos el servicio */
            linkProviderService = linkProviderRegistry.register(linkProvider);
            deviceProviderService = deviceProviderRegistry.register(deviceProvider);
            hostProviderService = hostProviderRegistry.register(hostProvider);

            /** Comprobacion de los registros, no deben ser nulos */
            ConfigProvider(deviceProviderRegistry, linkProviderRegistry, hostProviderRegistry);

            ScheduledFuture scheduledFuture =
                    scheduledExecutorService.schedule(() -> {
                        log.debug("Application started");
                        /** Cargamos la lista de enlaces*/
                        DHTlink.createLinks(netCfgService,configuredLinks);
                        log.debug("Lista de enlaces cargados");

                        /** Activo la selección de paquetes para mi protocolo **/
                        requestIntercepts();
                        log.debug("Activado el capturador de paquetes del protocolo");

                        /** Comenzamos el proceso de exploración*/
                        log.debug("Iniciamos el protocolo");
                        startDHTProcess();

                        log.debug(configuredLinks.toString());
                    },  0,  TimeUnit.SECONDS);
        }catch (Exception e){
            log.error("ERROR DHT !! -----> ALGO HA IDO MAL AL ARRANCAR: "+e.getMessage());
        }

    }

    @Deactivate
    protected void deactivate() {

        linkProviderRegistry.unregister(linkProvider);
        deviceProviderRegistry.unregister(deviceProvider);
        hostProviderRegistry.unregister(hostProvider);

        withdrawIntercepts();
        scheduledExecutorService.shutdownNow();

        log.info("Stopped");
    }

    /** Clases y Funciones auxiliares para realizar el proceso de descubrimiento */

    /** @brief Función que inicia el proceso de exploración del protocolo */
    private void startDHTProcess() {
        while (true){
            /** Se Genera un array de dispositivos descubierto por SDN*/
            Iterable<Device> devices = deviceService.getAvailableDevices(Device.Type.SWITCH);
            /** Reiniciamos los Estadisticos */
            Num_packet_out = 0;
            Num_packet_in = 0;
            Num_packet_data = 0;

            /** Se Recorreo ese array*/
            for(Device device : devices) {
                /**Aumentamos el estadistico*/
                Num_packet_out++;
                /** Solo se los mandamos a los OF*/
                if (device.id().toString().contains("of:")){
                   log.debug("Device select: "+  device.id());
                    /** redescubrimos los enlaces */
                    /** Creamos el paquete inicial para enviar al device seleccionado*/
                    log.debug("Creamos paquete DHT Request");
                    Ethernet packet =  CreatePacketDHT(device.id(), OPCODE_DHT_REQUEST, 255, null);
                    log.debug("Paquete creado correctamente");
                    /** Enviamos el paquete creado */
                    sendpacketwithDevice(device,packet);
                    log.debug("OK->Paquete enviado correctamente!!!");
                    /** Para depurar esperamos un poco entre lanzamientos */
                    log.debug("Discovery with device id " + device.id() + " DONE");
                }
            }
            try {
                Thread.sleep(TIME_REFRESH);
                log.info("##########################################################");
                log.info("packet out {}",Num_packet_out);
                log.info("packet in {}",Num_packet_in);
                log.info("packet data {}",Num_packet_data);
                log.info("##########################################################");

                /** Limpiamos los enlaces antigos de este dispositivo */
                if (Time_delete < System.currentTimeMillis()){
                    for (Device device: deviceService.getDevices()){
                        //Si es un sensor borramos todos sus enlaces y puertos
                        if (!device.id().toString().contains("sw") && !device.id().toString().contains("of")){
                            for (Port port: deviceService.getPorts(device.id())){
                                deviceProviderService.deletePort(device.id(),DefaultPortDescription.builder().
                                        withPortNumer(port.number()).isEnabled(true).
                                        portSpeed(1000).type(Port.Type.COPPER).build()
                                );
                            }
                        }
                        else{ //si es un nodo solo borramos los enlaces
                            for (Link link: linkService.getDeviceLinks(device.id())){
                                DHTlink.linkVanished(link.src().toString(), link.dst().toString(), linkProviderService);
                            }
                        }

                    }
                    Time_delete = System.currentTimeMillis() + TIME_DELETE;
                }
            } catch (InterruptedException e) {
                log.error("DHTAPP ERROR :Interrupted exception");
                log.error(e.getMessage());
            }
        }
    }

    /** @brief Clase interna utilizada procesar las notificaciones de paquetes de descubrimiento y confirmacion recibidos **/
    private class ReactivePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {

            /** Obtenemos el paquete In **/
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            /** Comprobamos si es de nuestro protocolo */
            if (ethPkt == null) {
                log.info("Null ethernet packet");
                return;
            }

            if(ethPkt.getEtherType() == DHTpacket.DHT_ETHERNET_TYPE) {
                byte[] raw = context.inPacket().parsed().getPayload().serialize();
                try {
                    DHTpacket Packet_in_dht = DHTpacket.deserializer().deserialize(raw, 0, raw.length);

                    /** Aumentamos el Estadistico */
                    Num_packet_in ++;

                    /** Si llega un request y es un enlace directo entre dos SDN*/
                    if (Packet_in_dht.getOpcode() == OPCODE_DHT_REQUEST && Packet_in_dht.getNumDevices() == 1) {
                        /**Si recibimos un Request, debemos contar 1 paquete mas ya que el ultimo enlace no le contariamos*/
                        Num_packet_data ++;

                        /** Comprobamos si existe en enlace contrario en la lista */
                        Integer port_link = link_sdn_nodes.get("of:"+ DHTlink.parser_idpacket_to_iddevice(Packet_in_dht.getidmacdevices()[0])
                                +" "+context.inPacket().receivedFrom().deviceId().toString());
                        /** Si no existe el enlace todavia lo guardamos y a otra cosa */
                        if (port_link == null){
                            link_sdn_nodes.put(context.inPacket().receivedFrom().deviceId().toString()+" "+
                                    "of:"+DHTlink.parser_idpacket_to_iddevice(Packet_in_dht.getidmacdevices()[0]),
                                    (int)context.inPacket().receivedFrom().port().toLong());
                        }
                        else{
                            DHTlink.linkbewteendevices(deviceService, linkProviderService, configuredLinks,
                                    context.inPacket().receivedFrom().deviceId().toString(),
                                    (int)context.inPacket().receivedFrom().port().toLong(),
                                    "of:"+ DHTlink.parser_idpacket_to_iddevice(Packet_in_dht.getidmacdevices()[0]),
                                    port_link, modeDHT);
                        }
                    }
                    /** Si llega un request y NO es un enlace directo entre dos SDN*/
                    else if (Packet_in_dht.getOpcode() == OPCODE_DHT_REQUEST && Packet_in_dht.getNumDevices() > 1){
                        /**Si recibimos un Request, debemos contar 1 paquete mas ya que el ultimo enlace no le contariamos*/
                        Num_packet_data ++;

                        /**Sabemos que por cada uno de los enlaces va un dato */
                        log.debug("####################################################");
                        log.debug("Request Recibido: WARNING!!, Detectado Request");
                        log.debug("Creamos paquete Reply para comprobar la rama");
                        Ethernet Reply_packet = CreatePacketDHT(context.inPacket().receivedFrom().deviceId(),
                                OPCODE_DHT_REPLY,(int)context.inPacket().receivedFrom().port().toLong(),
                                deviceService.getPort(context.inPacket().receivedFrom().deviceId(),
                                        PortNumber.portNumber(1))
                        );
                        log.debug("Enviamos paquete reply");
                        /**Aumentamos el estadistico de packet out */
                        Num_packet_out++;
                        /** Enviamos el paquete creado utilizando la id del switch */
                        sendPacketwithID(context.inPacket().receivedFrom().deviceId(),
                                context.inPacket().receivedFrom().port(),
                                Reply_packet);
                        log.debug("Paquete REPLY enviado correctamnente");
                        log.debug("DEVICE ID DST packet out{}",context.inPacket().receivedFrom().deviceId().toString());
                        log.debug("Puerto DST packet out:{}",context.inPacket().receivedFrom().port().toString());
                        log.debug("####################################################");
                    }
                    /** Si llega un reply */
                    else{

                        /**Sabemos que por cada device que salta un paquete es un paquete por la red*/
                        Num_packet_data = Num_packet_data + Packet_in_dht.getNumDevices();

                        /** Toca modificar la topologia con los datos obtenidos */
                        log.debug("ATENCION REPLY Recibido: Pasamos a modificar la topologia con los datos");
                        /** Si el numero de saltos es 1 Toca modificar la topologia */
                        if (Packet_in_dht.getNumDevices() == 1 &&
                                Packet_in_dht.getTypedevices()[0] == DHTdevices.TYPE_SDN){
                            log.debug("ATENCION REPLY Recibido: Dectectado enlace entre dos SDN DEVICES!");
                            /** SOLUCION PARA EL PUERTO DE SALIDA!!!*/
                            DHTlink.linkbewteendevices(deviceService, linkProviderService, configuredLinks,
                                context.inPacket().receivedFrom().deviceId().toString(),
                                (int)context.inPacket().receivedFrom().port().toLong(),
                                "of:"+ DHTlink.parser_idpacket_to_iddevice(Packet_in_dht.getidmacdevices()[0]),
                                Packet_in_dht.getoutports()[0], modeDHT);
                        }else{
                            /** Existen nodos entre ellos */
                            log.debug("ATENCION REPLY Recibido: Dectectado enlace entre varios DEVICES!");
                            /** Comprobamos que todos los dispositivos del paquete estan en la topologia
                             * sino se han de crear */
                            if (!DHTdevices.checkdevices(deviceProviderService, deviceService,
                                    Packet_in_dht, modeDHT, TYPE_SENSORS)){
                                log.error("ALGO FUE MAL EN LA CREACION Y COMPROBACIÖN DE DISPOSITIVOS");
                                context.block();
                                return;
                            }
                            log.debug("DEVICES DEL PAQUETE OK!");
                            /** Comprobamos que todos los puertos de los dispositivos del paquete estan
                             * sino se han de crear */
                            if (!DHTdevices.checkportperdevices(deviceProviderService, deviceService,
                                    Packet_in_dht, modeDHT, TYPE_SENSORS)){
                                log.error("ALGO FUE MAL EN LA CREACION Y COMPROBACIÖN DE LOS PUERTOS DE DISPOSITIVOS");
                                context.block();
                                return;
                            }
                            /** Comprobamos que todos los host existen y sino los refrescamos */
                            if (!DHThost.checkhost(hostService, hostProviderService, Packet_in_dht, modeDHT, TYPE_SENSORS)){
                                log.error("ALGO FUE MAL EN LA CREACION Y COMPROBACIÖN DE LOS PUERTOS DE DISPOSITIVOS");
                                context.block();
                                return;
                            }
                            log.debug("PUERTOS DEL PAQUETE OK!");
                            /** Toca hacer los enlaces entre dispostivos */
                            DHTlink.linkstopology(configuredLinks, context.inPacket().receivedFrom().deviceId().toString(),
                                    (int)context.inPacket().receivedFrom().port().toLong(),
                                    Packet_in_dht, deviceService, linkProviderService, modeDHT, TYPE_SENSORS);
                         }
                    }
                } catch(DeserializationException e) {
                    log.error("Exception cached while deserializing discovery packet");
                    e.printStackTrace();
                    context.block();
                }

                /** Indicamos que el paquete ha sido manejado correctamente
                 * para que el resto de aplicaciones no lo traten */
                context.block();
            }
        }

    }

    /**
     * @brief Funcion encarga de crear el paquete de exploración REQUEST
     *
     * @param deviceId Id del dispositivo
     * @param Opcode código de opcion para los paquetes del protocolo
     * @param port puerto (representa el puerto de salida)
     * @param mac_port class port para obtener la mac del puerto de salida
     */
    private Ethernet CreatePacketDHT(DeviceId deviceId, short Opcode, int port, Port mac_port) {
        Ethernet packet = new Ethernet();
        short Num_devices = 1, Type_devices[] = new short[DHTpacket.DHT_MAX_ELEMENT];
        int  outports[] = new int[DHTpacket.DHT_MAX_ELEMENT],
                inports[] = new int[DHTpacket.DHT_MAX_ELEMENT];
        long id_mac_devices[] = new long[DHTpacket.DHT_MAX_ELEMENT];

        /**Completamos los arrays con los datos del switch elegido */
        /*Nodo SDN*/
        Type_devices[0] = 1;
        /* Id del dispositivo */
        id_mac_devices[0] = Long.parseLong(deviceId.toString().replace("of:",""),16);
        outports[0] = port;
        inports[0] = port;

        log.debug("Packet Request Process Create: Type: "+  Type_devices[0] +
                "Id Device: "+id_mac_devices[0]);

        DHTpacket RequestPacket = new DHTpacket(Opcode, Num_devices, Type_devices,
                outports, inports, id_mac_devices);

        /** Creamos paquete y completamos los datos como pay load*/
        RequestPacket.setParent(packet);

        if (Opcode == 1)
            packet.setSourceMACAddress(MAC_GENERIC)
                .setDestinationMACAddress(ETHERNET_BROADCAST_ADDRESS)
                .setEtherType(RequestPacket.DHT_ETHERNET_TYPE)
                .setPad(true)
                .setPayload(RequestPacket);
        else
            packet.setSourceMACAddress(mac_port.annotations().value("portMac"))
                .setDestinationMACAddress(MAC_GENERIC)
                .setEtherType(RequestPacket.DHT_ETHERNET_TYPE)
                .setPad(true)
                .setPayload(RequestPacket);

        log.debug("Packet Request Create OK!!!");

        return packet;
    }

    /**
     * @brief Imprime informacion del contexto del packet-in recibido.
     *
     * @param context Contexto del packet-in recibido por el controlador
     * @param Packet_in_dht paquete propio del protocolo
     */
    private void printPacketContextInfo(PacketContext context, DHTpacket Packet_in_dht) {
        Ethernet inEthPacket = context.inPacket().parsed();
        if(inEthPacket.getEtherType() != DHTpacket.DHT_ETHERNET_TYPE)
        {
            log.debug("Unknown");
            return;
        }

        log.debug("DHT packet received. Device: " + context.inPacket().receivedFrom().deviceId()
                + " rcv port: " + context.inPacket().receivedFrom().port()
                + " src MAC: " + inEthPacket.getSourceMAC()
                + " dst MAC: " + inEthPacket.getDestinationMAC()
                + " Packet: " + Packet_in_dht.toString());
    }

    /**
     * @brief Envia paquete de descubrimiento
     *
     * @param device Nodo que envia el paquete
     * @param packet trama Ethernet que encapsula el paquete de descubrimiento
     */
    private void sendpacketwithDevice(Device device, Ethernet packet) {

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.FLOOD)
                .build();

        byte[] buffer = packet.serialize();
        OutboundPacket outboundPacket = new DefaultOutboundPacket(device.id(),
                treatment, ByteBuffer.wrap(buffer));

        packetService.emit(outboundPacket);
    }

    /**
     * @brief Enviar Paquete usando el puerto de salida y la id del dispisitivo
     *
     * @param sourceDeviceId Nodo que envia el paquete
     * @param outPort Puerto por donde se reenvia el paquete
     * @param packet trama Ethernet que encapsula el paquete de confirmacion
     */
    private void sendPacketwithID(DeviceId sourceDeviceId, PortNumber outPort, Ethernet packet) {

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(outPort)
                .build();

        byte[] buffer = packet.serialize();
        OutboundPacket outboundPacket = new DefaultOutboundPacket(sourceDeviceId,
                treatment, ByteBuffer.wrap(buffer));

        packetService.emit(outboundPacket);
    }


    /**
     * @brief Activa la notificacion de paquetes de descubrimiento y confirmacion recibidos
     */
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

        selector.matchEthType(DHTpacket.DHT_ETHERNET_TYPE);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * @brief Desactiva la notificacion de paquetes de descubrimiento y confirmacion recibidos
     */
    private void withdrawIntercepts() {
        packetService.removeProcessor(processor);
    }

    /**
     * Creates a new configuration provider.
     *
     * @param deviceProviderRegistry device provider registry
     * @param linkProviderRegistry   link provider registry
     * @param hostProviderRegistry   host provider registry
     */
    private void ConfigProvider(
                   DeviceProviderRegistry deviceProviderRegistry,
                   LinkProviderRegistry linkProviderRegistry,
                   HostProviderRegistry hostProviderRegistry) {
        this.deviceProviderRegistry = checkNotNull(deviceProviderRegistry, "Device provider registry cannot be null");
        this.linkProviderRegistry = checkNotNull(linkProviderRegistry, "Link provider registry cannot be null");
        this.hostProviderRegistry = checkNotNull(hostProviderRegistry, "Host provider registry cannot be null");
    }


    private static boolean isremoveable(String unixTime, long Time_delete_device) {
        String time ;

        time = unixTime.replace("connected ","");
        time = time.replace("disconnected ","");
        time = time.replace("ago","");

        // si ya dias u horas o minutos se elimina directamente
        if ( time.contains("d") || unixTime.contains("h") || unixTime.contains("m")){
            return true;
        }
        else if (time.contains("2")){
            if (Long.getLong(time.split("2")[0]) > Time_delete_device)
                return true;
        }
        return false;
    }

    // Stub provider used to get LinkProviderService
    private static final class StubLinkProvider implements LinkProvider {
        @Override
        public ProviderId id() {
            return PID;
        }
    }

    private static final class StubDeviceProvider implements DeviceProvider {
        @Override
        public ProviderId id() {
            return PID;
        }

        @Override
        public void triggerProbe(DeviceId deviceId) {

        }

        @Override
        public void roleChanged(DeviceId deviceId, MastershipRole mastershipRole) {

        }

        @Override
        public boolean isReachable(DeviceId deviceId) {
            return false;
        }

        @Override
        public void changePortState(DeviceId deviceId, PortNumber portNumber, boolean b) {

        }
    }

    private static final class StubHostProvider implements HostProvider{

        @Override
        public void triggerProbe(Host host) {

        }

        @Override
        public ProviderId id() {
            return PID;
        }
    }
}
