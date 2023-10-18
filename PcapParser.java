import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;

import javax.swing.plaf.synth.SynthStyle;

public class PcapParser {
    public static void main(String[] args) {
        String pcapFilePath = "arp.pcap";

        try (FileInputStream fis = new FileInputStream(pcapFilePath);
             DataInputStream dis = new DataInputStream(fis)) {

            // Parse the Global Header
            parseGlobalHeader(dis);

            int packetNumber = 0;

            while (dis.available() > 0) {
                // Parse each packet
                parsePacket(dis, packetNumber);
                packetNumber++;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void parseGlobalHeader(DataInputStream dis) throws IOException {
        // Read and parse the Global Header
        byte[] globalheader = new byte[24];
        dis.readFully(globalheader);
        /*
        int magicNumber = dis.readInt();
        short majorVersion = dis.readShort();
        short minorVersion = dis.readShort();
        int timeZoneOffset = dis.readInt();
        int timestampAccuracy = dis.readInt();
        int maxLengthCaptured = dis.readInt();
        
        // Print Global Header information
        System.out.println("PCAP Global Header:");
        System.out.println("Magic Number: 0x" + Integer.toHexString(magicNumber));
        System.out.println("Major Version: " + Integer.toHexString(majorVersion));
        System.out.println("Minor Version: " + Integer.toHexString(minorVersion));
        System.out.println("Time Zone Offset: " + Integer.toHexString(timeZoneOffset));
        System.out.println("Timestamp Accuracy: " + Integer.toHexString(timestampAccuracy));
        System.out.println("Max Length Captured: " + Integer.toHexString(maxLengthCaptured));
        System.out.println();
        */
    }

    private static void parsePacket(DataInputStream dis, int packetNumber) throws IOException {
        // Parse each packet
        
        int timestampSeconds = dis.readInt();
        int timestampMicroseconds = dis.readInt();
        int capturedPacketLength = dis.readInt();
        int originalPacketLength = dis.readInt();
        
        
        System.out.println("Packet " + packetNumber + ":");
        System.out.println("Timestamp (seconds): " + Integer.toHexString(timestampSeconds));
        
        System.out.println("Captured Packet Length: " + (Integer.reverseBytes(capturedPacketLength)));
        System.out.println("Original Packet Length: " + originalPacketLength);

        
        byte[] ethernetFrame = new byte[Integer.reverseBytes(capturedPacketLength)];
        
        System.out.println(dis.available());
        dis.readFully(ethernetFrame);
        
       
        byte[] sourceMAC = new byte[6];
        byte[] destMAC = new byte[6];
        byte[] typeIp = new byte[2];
        System.arraycopy(ethernetFrame, 0, destMAC, 0, 6);
        System.arraycopy(ethernetFrame, 6, sourceMAC, 0, 6);
        System.arraycopy(ethernetFrame, 12, typeIp, 0, 2);

        System.out.println("Source MAC Address: " + macAddressToString(sourceMAC));
        System.out.println("Destination MAC Address: " + macAddressToString(destMAC));
        System.out.println("Type of IP: " + macAddressToString(typeIp));
       
        if (macAddressToString(typeIp).equals("08:00")){
            byte[] ipsource=new byte[4];
            byte[] ipdest=new byte[4];
            byte[] protocol = new byte[1];

            System.arraycopy(ethernetFrame, 30, ipdest, 0, 4);
            System.arraycopy(ethernetFrame, 26, ipsource, 0, 4);
            System.arraycopy(ethernetFrame, 23, protocol, 0, 1);
            System.out.println("IP source : " + hexIPToIPAddress(macAddressToString(ipsource)) );
            System.out.println("IP destination : " + hexIPToIPAddress(macAddressToString(ipdest)) );
            System.out.println("Protocol : " + macAddressToString(protocol));   
            
            if (macAddressToString(protocol).equals("06")){
                 byte[] sourceport=new byte[2];
                byte[] destport=new byte[2];

                System.arraycopy(ethernetFrame, 34, sourceport, 0, 2);
                System.arraycopy(ethernetFrame, 36, destport, 0, 2);

                System.out.println("Source port : " + hexToDecimal(macAddressToString(sourceport)));
                System.out.println("Destination port : " + hexToDecimal(macAddressToString(destport)) );
        

                System.out.println();
            }
            else if (macAddressToString(protocol).equals("01")){
                byte[] typeicmp = new byte[1];

                System.arraycopy(ethernetFrame, 34, typeicmp, 0, 1);

                System.out.println("ICMP de type " + macAddressToString(typeicmp));
            }
            else if(macAddressToString(protocol).equals("11")){
                byte[] sourceport=new byte[2];
                byte[] destport=new byte[2];

                System.arraycopy(ethernetFrame, 34, sourceport, 0, 2);
                System.arraycopy(ethernetFrame, 36, destport, 0, 2);
                String sport=Integer.toString(hexToDecimal(macAddressToString(sourceport)));
                String dport=Integer.toString(hexToDecimal(macAddressToString(destport)));
                System.out.println("Source port : " + sport );
                System.out.println("Destination port : " + dport );
                System.out.println("UDP");

                if(sport.equals("53") || dport.equals("53")){
                    
                }

                
            }
            
           
        }

        else if(macAddressToString(typeIp).equals("08:06")){
            byte[] typearp=new byte[2];
            byte[] macsource=new byte[6];
            byte[] macdest=new byte[6];
            byte[] ipsource=new byte[4];
            byte[] ipdest=new byte[4];
 
            System.arraycopy(ethernetFrame, 20, typearp,0, 2);
            System.arraycopy(ethernetFrame, 22, macsource,0, 6);
            System.arraycopy(ethernetFrame, 28, ipsource,0, 4);
            System.arraycopy(ethernetFrame, 32, macdest,0, 6);
            System.arraycopy(ethernetFrame, 38, ipdest,0, 4);

            System.out.println("ARP de type " + macAddressToString(typearp));
            System.out.println("MAC source : " + macAddressToString(macsource));
            System.out.println("MAC dest : " + macAddressToString(macdest));
            System.out.println("IP source : " + hexIPToIPAddress(macAddressToString(ipsource)));
            System.out.println("IP dest : " + hexIPToIPAddress(macAddressToString(ipdest)));
        }
        

        

        

    }

    public static InetAddress bytesToIpAddress(byte[] ipAddressBytes) {
        try {
            if (ipAddressBytes.length == 4) {
                return InetAddress.getByAddress(ipAddressBytes);
            } else {
                throw new IllegalArgumentException("Le tableau de bytes doit contenir exactement 4 éléments pour une adresse IP.");
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String macAddressToString(byte[] macAddress) {
        StringBuilder sb = new StringBuilder();
        for (byte b : macAddress) {
            sb.append(String.format("%02X:", b));
        }
        return sb.substring(0, sb.length() - 1); // Remove the trailing ':'
    }
    public static int hexToDecimal(String hex) {
        try {
            return Integer.parseInt(hex.replace(":", ""), 16);
        } catch (NumberFormatException e) {
            e.printStackTrace();
            return -1; // Remplacer par une valeur de gestion d'erreur appropriée
        }
    }
    public static InetAddress hexIPToIPAddress(String hexIP) {
        // Nettoyez la chaîne hexadécimale pour éliminer les délimiteurs, le cas échéant
        hexIP = hexIP.replaceAll(":", "");

        if (hexIP.length() != 8) {
            System.err.println("La chaîne hexadécimale doit contenir exactement 8 caractères.");
            return null;
        }

        try {
            // Convertissez chaque paire de caractères hexadécimaux en un octet
            byte[] ipAddressBytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                String byteHex = hexIP.substring(i * 2, i * 2 + 2);
                ipAddressBytes[i] = (byte) Integer.parseInt(byteHex, 16);
            }

            return InetAddress.getByAddress(ipAddressBytes);
        } catch (UnknownHostException | NumberFormatException e) {
            e.printStackTrace();
            return null;
        }
    }
    

}
