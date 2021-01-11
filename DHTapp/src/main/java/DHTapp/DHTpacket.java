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

import org.onlab.packet.BasePacket;
import java.util.Arrays;
import org.onlab.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.nio.ByteBuffer;
import static com.google.common.base.MoreObjects.toStringHelper;
import static org.onlab.packet.PacketUtils.checkInput;

/**
 * @brief Paquete propio para el descubrimiento de topologias hibridas
 * @author Joaquin Alvarez Horcajo
 */


public class DHTpacket extends BasePacket {

    /** Atributos de la clase */

        /** @brief Servicio de log de la aplicacion */
        private final Logger log = LoggerFactory.getLogger(getClass());

        /** @brief Campo EtherType para un paquete de confirmacion */
        static public final short DHT_ETHERNET_TYPE = (short)65450; /** 43775 **/
        /** @brief Numero máximo de elementos posibles en un paquete */
        static public final short DHT_MAX_ELEMENT = (short)31;
        /** @brief Tamaño maximo de un paquete (ojo que me lo devuelve en bit) */
        static public final short DHT_PACKET_SIZE =
                ((2*Short.SIZE) + ((Short.SIZE + (2*Integer.SIZE) + Long.SIZE) * DHT_MAX_ELEMENT))/8;

        /** @brief Campos del paquete */
        private short Opcode;
        private short Num_devices, Type_devices[];
        private int outports[], inports[];
        private long id_mac_devices[];

    /** Metodos de la clase */

    /** @brief Constructor por defecto */
    public DHTpacket() {

    }

    /**
     * @brief Constructor con parametros
     *
     * @param Opcode: Codigo de opcion => 1 = Request; 2 = Reply
     * @param Num_devices:  Numero de dispositivos
     * @param Type_devices: Array con el tipo de dispositivos
     * @param outports: Array con los puertos de salida
     * @param inports: Array con los puertos de entrada
     * @param id_mac_devices: Array con los ID de los dispositivos por los que pasa
     * @return objeto de la clase DHTpacket
     */
    public DHTpacket(short Opcode, short Num_devices, short Type_devices[],
                     int outports[], int inports[], long id_mac_devices[]) {
        this.Opcode = Opcode;
        this.Num_devices = Num_devices;
        this.Type_devices = Type_devices;
        this.id_mac_devices = id_mac_devices;
        this.inports = inports;
        this.outports = outports;
    }
    /**
     * @brief Obtiene el Option code del paquete
     *
     * @return short Opcode
     */
    public short getOpcode() {
        return Opcode;
    }

    /**
     * @brief Obtiene El numero de dispositivos por los que ha pasado el paquete
     *
     * @return short Num_devices
     */
    public short getNumDevices() {
        return Num_devices;
    }

    /**
     * @brief Obtiene un array con todos los tipos de dispositivos que lleva el paquete
     *
     * @return int [] Type_devices
     */
    public short [] getTypedevices() {
        return Type_devices;
    }

    /**
     * @brief Obtiene un array con todos los puertos de salida que lleva el paquete
     *
     * @return short [] outports
     */
    public int [] getoutports() {
        return outports;
    }

    /**
     * @brief Obtiene un array con todos los puertos de entrada que lleva el paquete
     *
     * @return short [] inports
     */
    public int [] getinports() {
        return inports;
    }

    /**
     * @brief Obtiene un array con todas las IDs de los switches que lleva el paquete
     *
     * @return long [] id_mac_devices
     */
    public long [] getidmacdevices() {
        return id_mac_devices;
    }
    /**
     * @brief Indica si un objeto es "igual que" este objeto, comparando todos sus elementos
     *
     * @return true si el objeto es igual, false en caso contrario
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (!(obj instanceof DHTpacket)) {
            return false;
        }
        final DHTpacket other = (DHTpacket) obj;
        if (this.Opcode != other.Opcode) {
            return false;
        }
        if (this.Num_devices != other.Num_devices) {
            return false;
        }
        if (this.Type_devices != other.Type_devices) {
            return false;
        }
        if (this.outports != other.outports) {
            return false;
        }
        if (this.inports != other.inports) {
            return false;
        }
        if (this.id_mac_devices != other.id_mac_devices) {
            return false;
        }
        return true;
    }

    /**
     * @brief Serializa el objeto especificado.
     *
     * @return array de bytes
     */
    @Override
    public byte[] serialize() {
        int length = DHT_PACKET_SIZE;

        /** Creamos buffer para serializar */
        final byte[] data = new byte[length];

        /** Envolvemos el buffer para que sea mas facil serializar */
        final ByteBuffer bb = ByteBuffer.wrap(data);

        /** Serializamos campo source device id */
        bb.putShort(this.Opcode);

        /** Serializamos campo Num Devices device id */
        bb.putShort(this.Num_devices);

        /** Serializamos el array de datos Tipo, Id, In_port, Out_port */
        set_array_buffer(bb, Type_devices, this.Num_devices);
        set_array_buffer(bb, id_mac_devices, this.Num_devices);
        set_array_buffer(bb, inports, this.Num_devices);
        set_array_buffer(bb, outports, this.Num_devices);

        /** Devolvemos los datos serializados */
        return data;
    }

    /**
     * @brief Deserializa un paquete a partir de un array de bytes
     *
     * @param data Array de bytes recibidos
     * @param offset índice de comienzo del array de bytes
     * @param size longitud del paquete
     * @return objeto Ipacket del paquete deserializado
     */
    public IPacket deserialize(byte[] data, int offset, int size) {

        final ByteBuffer bb = ByteBuffer.wrap(data, offset, size);

        /** sacamos el campo Opcode */
        this.Opcode = bb.getShort();
        /** Sacamos el campo Num_devices */
        this.Num_devices = bb.getShort();
        /** Sacamos los datos pertenecientes a los diferentes arrays */
        this.Type_devices = get_array_buffer_short(bb);
        this.id_mac_devices = get_array_buffer_long(bb);
        this.inports = get_array_buffer_int(bb);
        this.outports = get_array_buffer_int(bb);

        return this;
    }

    /**
     * @brief Deserializer function for Confirmation packet.
     *
     * @return deserializer function
     */

    public static Deserializer<DHTpacket> deserializer() {
        return (data, offset, length) -> {

            checkInput(data, offset, length, DHT_PACKET_SIZE);
            final ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
            /** Creamos la clase para ser rellenada */
            DHTpacket packet = new DHTpacket();
            /** sacamos el campo Opcode */
            packet.Opcode = bb.getShort();
            /** Sacamos el campo Num_devices */
            packet.Num_devices = bb.getShort();
            /** Sacamos los datos pertenecientes a los diferentes arrays */
            packet.Type_devices = get_array_buffer_short(bb);
            packet.id_mac_devices = get_array_buffer_long(bb);
            packet.inports = get_array_buffer_int(bb);
            packet.outports = get_array_buffer_int(bb);

            return packet;
        };
    }

    @Override
    public String toString() {
        return toStringHelper(getClass())
                .add("OpCode", String.valueOf(this.Opcode))
                .add("Num Devices",  String.valueOf(this.Num_devices))
                .add("Type Devices", Arrays.toString(Type_devices))
                .add("Id Mac Devices", Arrays.toString(id_mac_devices))
                .add("In Ports", Arrays.toString(inports))
                .add("Out Ports", Arrays.toString(outports))
                .toString();
    }

    /** @brief introduce los datos en el buffer
     *
     * @param bb buffer
     * @param data datos
     * @param num_element numero de elementos a introducir en el buffer
     */
    public void set_array_buffer (ByteBuffer bb, short data [], int num_element) {
        for(int pos = 0; pos < DHT_MAX_ELEMENT; pos ++) {
            if (pos < num_element){
                /** Introducimos los datos en el paquete */
                bb.putShort(data[pos]);
            }
            else{
                /** Si ya hemos metido todos los elementos relleno con 0 */
                bb.putShort((short)0);
            }
        }
    }

    /** @brief introduce los datos en el buffer
     *
     * @param bb buffer
     * @param data datos
     * @param num_element numero de elementos a introducir en el buffer
     */
    public void set_array_buffer (ByteBuffer bb, int data [], int num_element) {
        for(int pos = 0; pos < DHT_MAX_ELEMENT; pos ++) {
            if (pos < num_element){
                /** Introducimos los datos en el paquete */
                bb.putInt(data[pos]);
            }
            else{
                /** Si ya hemos metido todos los elementos relleno con 0 */
                bb.putInt(0);
            }
        }
    }

    /** @brief introduce los datos en el buffer
     *
     * @param bb buffer
     * @param data datos
     * @param num_element numero de elementos a introducir en el buffer
     */
    public void set_array_buffer(ByteBuffer bb, long data [], int num_element) {
        for(int pos = 0; pos < DHT_MAX_ELEMENT; pos ++) {
            if (pos < num_element){
                /** Introducimos los datos en el paquete */
                bb.putLong(data[pos]);
            }
            else{
                /** Si ya hemos metido todos los elementos relleno con 0 */
                bb.putLong(0);
            }
        }
    }

    /** @brief obtiene los datos del buffer
     *
     * @param bb buffer
     * @return devuelve un array de datos tipo int
     */
    public static int [] get_array_buffer_int(ByteBuffer bb) {
        int data_recovery [] = new int[DHT_MAX_ELEMENT];

        for(int pos = 0; pos < DHT_MAX_ELEMENT; pos ++) {
            data_recovery[pos] = bb.getInt();
        }
        return data_recovery;
    }

    /** @brief obtiene los datos del buffer
     *
     * @param bb buffer
     * @return devuelve un array de datos tipo long
     */
    public static long [] get_array_buffer_long(ByteBuffer bb) {
        long data_recovery [] = new long[DHT_MAX_ELEMENT];

        for(int pos = 0; pos < DHT_MAX_ELEMENT; pos ++) {
            data_recovery[pos] = bb.getLong();
        }
        return data_recovery;
    }

    /** @brief obtiene los datos del buffer
     *
     * @param bb buffer
     * @return devuelve un array de datos tipo short
     */
    public static short[] get_array_buffer_short(ByteBuffer bb){
        short data_recovery [] = new short[DHT_MAX_ELEMENT];

        for(int pos = 0; pos < DHT_MAX_ELEMENT; pos ++) {
            data_recovery[pos] = bb.getShort();
        }
        return data_recovery;
    }

    /** @brief permite generar una mac valida a partir de un long
     *
     * @param address identificador numero de la mac
     * @return string con una direccion mac valida
     */

    public String LongToMacString(long address)
    {
        int[] addressInBytes = new int[] {
                (int)((address >> 40) & 0xff),
                (int)((address >> 32) & 0xff),
                (int)((address >> 24) & 0xff),
                (int)((address >> 16) & 0xff),
                (int)((address >> 8 ) & 0xff),
                (int)((address >> 0) & 0xff)
        };

        return addressInBytes.toString();
    }
}
