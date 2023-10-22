import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;


public class PcapParser {

    public static ArrayList<TcpSegment> tcpsegments=new ArrayList<>();
    public static void main(String[] args) {
        String pcapFilePath = "http.pcap";
        
        
        try (FileInputStream fis = new FileInputStream(pcapFilePath);
             DataInputStream dis = new DataInputStream(fis)) {

            // Parse the Global Header
            parseGlobalHeader(dis);

            int packetNumber = 1;

            while (dis.available() > 0) {
                // Parse each packet
                parsePacket(dis, packetNumber);
                packetNumber++;
            }

            System.out.println(tcpsegments.size());
            System.out.println(tcpsegments.get(0).sip);
            
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
        String the_protocol="";
        int timestampSeconds = dis.readInt();
        int timestampMicroseconds = dis.readInt();
        int capturedPacketLength = dis.readInt();
        int originalPacketLength = dis.readInt();
        
        System.out.println();
        System.out.println("Packet " + packetNumber + ":");
        int date_packet=hexToDecimale(Integer.toHexString(Integer.reverseBytes(timestampSeconds)));
        System.out.println("Timestamp (seconds): " +  convertTimestampToDate(date_packet));
        
        System.out.println("Captured Packet Length: " + (Integer.reverseBytes(capturedPacketLength)));
        //System.out.println("Original Packet Length: " + originalPacketLength);

        
        byte[] ethernetFrame = new byte[Integer.reverseBytes(capturedPacketLength)];
        
        //System.out.println(dis.available());
        dis.readFully(ethernetFrame);
        
       
        byte[] sourceMAC = new byte[6];
        byte[] destMAC = new byte[6];
        byte[] typeIp = new byte[2];
        System.arraycopy(ethernetFrame, 0, destMAC, 0, 6);
        System.arraycopy(ethernetFrame, 6, sourceMAC, 0, 6);
        System.arraycopy(ethernetFrame, 12, typeIp, 0, 2);

        System.out.println("-----------Couche liaison--------------");
        System.out.println("Source MAC Address: " + macAddressToString(sourceMAC));
        System.out.println("Destination MAC Address: " + macAddressToString(destMAC));
        System.out.println("Type of IP: " + macAddressToString(typeIp));
        
       
        if (macAddressToString(typeIp).equals("08:00")){
            
            byte[] ipsource=new byte[4];
            byte[] ipdest=new byte[4];
            byte[] protocol = new byte[1];
            byte[] headerlength=new byte[1];

            System.arraycopy(ethernetFrame, 14, headerlength, 0, 1);
            int ipheaderlength= Character.getNumericValue(macAddressToString(headerlength).charAt(1))*4;
            
            System.arraycopy(ethernetFrame, 14+ipheaderlength-4, ipdest, 0, 4);
            System.arraycopy(ethernetFrame, 14+ipheaderlength-8, ipsource, 0, 4);
            System.arraycopy(ethernetFrame, 14+ipheaderlength-11, protocol, 0, 1);
            System.out.println("-----------Couche réseau--------------");
            System.out.println("IP source : " + hexIPToIPAddress(macAddressToString(ipsource)) );
            System.out.println("IP destination : " + hexIPToIPAddress(macAddressToString(ipdest)) );
            System.out.println("Protocol : " + macAddressToString(protocol));
           
            
            if (macAddressToString(protocol).equals("06")){
                 byte[] sourceport=new byte[2];
                byte[] destport=new byte[2];
                byte[] headerlengthtcp=new byte[1];

                System.arraycopy(ethernetFrame, 14+ipheaderlength+12, headerlengthtcp, 0, 1);
                int tcpheaderlength= Character.getNumericValue(macAddressToString(headerlengthtcp).charAt(0))*4;
                

                System.arraycopy(ethernetFrame, 14+ipheaderlength, sourceport, 0, 2);
                System.arraycopy(ethernetFrame, 14+ipheaderlength+2, destport, 0, 2);

                System.out.println("-----------Couche transport--------------");
                System.out.println("Source port : " + hexToDecimal(macAddressToString(sourceport)));
                System.out.println("Destination port : " + hexToDecimal(macAddressToString(destport)) );

                String sport=Integer.toString(hexToDecimal(macAddressToString(sourceport)));
                String dport=Integer.toString(hexToDecimal(macAddressToString(destport)));

                byte[] seq=new byte[4];
                byte[] ack =new byte[4];

                System.arraycopy(ethernetFrame, 14+ipheaderlength+4, seq, 0, 4);
                System.arraycopy(ethernetFrame, 14+ipheaderlength+8, ack, 0, 4);

                System.out.println("Sequence number : " + hexToLong(macAddressToString(seq)));
                System.out.println("ACK number : " + hexToLong(macAddressToString(ack)));
               

                tcpsegments.add(new TcpSegment(hexToDecimal(macAddressToString(sourceport)), hexToDecimal(macAddressToString(destport)), macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(), hexToLong(macAddressToString(seq)), hexToLong(macAddressToString(ack))) );
        
                the_protocol="TCP";
                

                
                if(sport.equals("80") || dport.equals("80")){
                    
                    if(sport.equals("80")){
                        
                        byte[] httpresponse =new byte[Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-tcpheaderlength];
                        

                        System.arraycopy(ethernetFrame, 14+ipheaderlength+tcpheaderlength, httpresponse, 0, Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-tcpheaderlength);
                        

                        if (hexStringToText(macAddressToString(httpresponse)).contains("HTTP/1.1")){
                            the_protocol="HTTP";
                            System.out.println("-----------Couche application--------------");
                            System.out.println("HTTP response");
                            System.out.println(hexStringToText(macAddressToString(httpresponse))+"\n");
                            
                        }
                        
                    }
                    else if (dport.equals("80")){
                        

                        
                        byte [] httprequest= new byte[Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-tcpheaderlength];
                        
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+tcpheaderlength, httprequest, 0, Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-tcpheaderlength);
                        if (hexStringToText(macAddressToString(httprequest)).contains("HTTP/1.1")){
                            System.out.println("-----------Couche application--------------");
                            System.out.println("HTTP request");
                            the_protocol="HTTP";
                            System.out.println(hexStringToText(macAddressToString(httprequest))+"\n");
                            
                        }
                        
                    }
                }
                if(sport.equals("443") || dport.equals("443")){
                    the_protocol="TLS";
                }
            }
            else if (macAddressToString(protocol).equals("01")){
                byte[] typeicmp = new byte[1];
                the_protocol="ICMP";
                System.arraycopy(ethernetFrame, 34, typeicmp, 0, 1);
                System.out.println("-----------Couche réseau--------------");
                System.out.println("ICMP de type " + macAddressToString(typeicmp));
                
            }
            else if(macAddressToString(protocol).equals("11")){
                byte[] sourceport=new byte[2];
                byte[] destport=new byte[2];
                the_protocol="UDP";
                System.arraycopy(ethernetFrame, 34, sourceport, 0, 2);
                System.arraycopy(ethernetFrame, 36, destport, 0, 2);
                String sport=Integer.toString(hexToDecimal(macAddressToString(sourceport)));
                String dport=Integer.toString(hexToDecimal(macAddressToString(destport)));
                System.out.println("-----------Couche transport--------------");
                System.out.println("Source port : " + sport );
                System.out.println("Destination port : " + dport );
               
                

                if(sport.equals("53") || dport.equals("53")){
                    the_protocol="DNS";
                    byte [] dnsqr=new byte[2];

                    System.arraycopy(ethernetFrame, 44, dnsqr, 0, 2);
                    
                    byte[] dnsclass =new byte [2];
                    byte[] dnstype=new byte[2];
                    System.out.println("-----------Couche application--------------");
                    if (macAddressToString(dnsqr).equals("01:00")){
                        System.out.println("DNS query");
                        System.arraycopy(ethernetFrame, Integer.reverseBytes(capturedPacketLength)-2, dnsclass, 0, 2);
                        System.arraycopy(ethernetFrame, Integer.reverseBytes(capturedPacketLength)-4, dnstype, 0, 2);
                        
                        if (macAddressToString(dnsclass).equals("00:01")){
                            System.out.println("DNS Class : IN");
                        }
                        if (macAddressToString(dnstype).equals("00:01")){
                            System.out.println("DNS Type : AAAA");
                        }
                        if (macAddressToString(dnstype).equals("00:1C")){
                            System.out.println("DNS Type : A");
                        }

                    }
                    else if (macAddressToString(dnsqr).equals("81:80")){
                        System.out.println("DNS answer");
                    }
                    
                    



                }
                if(sport.equals("443") || dport.equals("443")){
                    
                    the_protocol="QUIC";
                    byte[] quicheader=new byte[1];
                    System.arraycopy(ethernetFrame, 14+ipheaderlength+8, quicheader, 0, 1);
                    
                    int firstBit = (Character.getNumericValue(macAddressToString(quicheader).charAt(0)) >> 3) & 1;
                    System.out.println("-----------Couche application--------------");
                    if(firstBit==0){

                    }
                    else if(firstBit==1){
                        byte[] quicversion=new byte[4];
                        byte[] cidlength=new byte[1];
                    

                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1, quicversion, 0, 4);
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4, cidlength, 0, 1);

                        
                        System.out.println("QUIC version : " + macAddressToString(quicversion));
                        

                        byte[] cid=new byte[hexToDecimale(macAddressToString(cidlength))];
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4+1, cid, 0, hexToDecimale(macAddressToString(cidlength)));
                        System.out.println("Destination Connection ID : "+ macAddressToString(cid));

                        byte[] sidlength=new byte[1];
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4+1+hexToDecimale(macAddressToString(cidlength)), sidlength, 0, 1);
                        
                        byte[] sid=new byte[hexToDecimale(macAddressToString(sidlength))];
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4+1+hexToDecimale(macAddressToString(cidlength))+1, sid, 0, hexToDecimale(macAddressToString(sidlength)));
                        System.out.println("Source Connection ID : "+ macAddressToString(sid));
                    }
                    
                    
                }
                if(sport.equals("67") || dport.equals("68") || sport.equals("68") || dport.equals("67")){
                    the_protocol="DHCP";
                    byte[] dhcpqr =new byte[1];
                    byte[] dhcpserver=new byte[4];
                    byte[] dhcpclient=new byte[4];
                    
                    System.arraycopy(ethernetFrame, 42, dhcpqr, 0, 1);
                    System.arraycopy(ethernetFrame, 54, dhcpclient, 0, 4);
                    System.arraycopy(ethernetFrame, 62, dhcpserver, 0, 4);
                    
                    System.out.println("-----------Couche application--------------");
                    if (macAddressToString(dhcpqr).equals("01")){

                        System.out.println("DHCP request");
                    }
                    if (macAddressToString(dhcpqr).equals("02")){
                        System.out.println("DHCP reply");
                    }
                    System.out.println("DHCP client adress : " + hexIPToIPAddress(macAddressToString(dhcpclient)));
                    System.out.println("DHCP server adress : " + hexIPToIPAddress(macAddressToString(dhcpserver)));
                    
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

            System.out.println("-----------Couche réseau--------------");
            System.out.println("ARP de type " + macAddressToString(typearp));
            System.out.println("MAC source : " + macAddressToString(macsource));
            System.out.println("MAC dest : " + macAddressToString(macdest));
            System.out.println("IP source : " + hexIPToIPAddress(macAddressToString(ipsource)));
            System.out.println("IP dest : " + hexIPToIPAddress(macAddressToString(ipdest)));
            

            the_protocol="ARP";
        }
        System.out.println("--------------------------------------");

        

        System.out.println(the_protocol);

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
        
        if (macAddress.length <1) {
            return "00"; // Gestion de l'erreur pour les adresses MAC incorrectes
        }
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
    public static Long hexToLong(String hex) {
        try {
            return Long.parseLong(hex.replace(":", ""), 16);
        } catch (NumberFormatException e) {
            e.printStackTrace();
            return null; // Remplacer par une valeur de gestion d'erreur appropriée
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
    public static String hexStringToText(String hexString) {
        String[] hexValues = hexString.split(":");
        StringBuilder textBuilder = new StringBuilder();

        for (String hexValue : hexValues) {
            try {
                int intValue = Integer.parseInt(hexValue, 16);
                if (intValue >= 0 && intValue <= 255) {
                    textBuilder.append((char) intValue);
                } else {
                    throw new IllegalArgumentException("Invalid hex value: " + hexValue);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid hex value: " + hexValue);
            }
        }

        return textBuilder.toString();
    }
    public static Date convertTimestampToDate(int timestamp) {
        
        return new java.util.Date((long)timestamp*1000);
    }
    public static int hexToDecimale(String hex) {
        try {
            // Utilisez Integer.parseInt avec la base 16 (hexadécimal)
            int decimal = Integer.parseInt(hex, 16);
            return decimal;
        } catch (NumberFormatException e) {
            e.printStackTrace();
            return -1; // Gestion de l'erreur
        }
    }
    public static String reverseString(String input) {
        if (input == null) {
            return null; // Gestion du cas où la chaîne est null
        }
        
        int length = input.length();
        StringBuilder reversed = new StringBuilder(length);
    
        for (int i = length - 1; i >= 0; i--) {
            reversed.append(input.charAt(i));
        }
    
        return reversed.toString();
    }
    

}
