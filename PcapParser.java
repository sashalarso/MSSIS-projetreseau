import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;


public class PcapParser {

    public static ArrayList<Object> packets=new ArrayList<Object>();
    public static ArrayList<TCP> tcps =new ArrayList<TCP>();
    public static void main(String[] args) {

        if(args[0].equals("help")){
            System.out.println("Pour entrer votre propre fichier, tapez son nom en premier argument");
            System.out.println("Protocoles supportés: ARP, ICMP, QUIC, HTTP, DNS, IPV4, TCP, UDP");
            System.out.println("Pour filtrer en fonction du protocole simplement taper après le fichier pcap le protocole en majuscules");
            System.out.println("Exemple de commande : java PcapParser foo.pcap ARP");
            System.out.println();
            System.out.println("Les paquets transitant par IPv6 ne sont pas disponibles, étant donné qu'on ne traite pas ce protocole");
            System.exit(0);
        }
        String pcapFilePath = args[0];
        
        
        try (FileInputStream fis = new FileInputStream(pcapFilePath);
             DataInputStream dis = new DataInputStream(fis)) {

            
            parseGlobalHeader(dis);

            int packetNumber = 1;

            while (dis.available() > 0) {
              
                parsePacket(dis, packetNumber);
                packetNumber++;
            }
            System.out.println(packets.size());
            System.out.println(tcps.size());
            
            
        } catch (IOException e) {
            e.printStackTrace();
        }
        int j=0;
        for (Object element : packets) {
            j=j+1;
            if(element.getClass().getName().equals(args[1])){
                System.out.println(element);
            }
            else if(args[1].equals("")){
                System.out.println(element);
            }
            else if(args[1].equals("UDP")){
                if(element.getClass().getName().equals("DNS") || (element.getClass().getName().equals("QUIC"))){
                    System.out.println(element);
                }
                
            }
                       
            else if(estNombreEntier(args[1]) && j==Integer.parseInt(args[1])){
                System.out.println(element);
            }
            
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
               

                TCP tcpp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                tcps.add(tcpp);
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

                            HTTP http=new HTTP(hexToDecimal(macAddressToString(sourceport)), hexToDecimal(macAddressToString(destport)), macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(), "HTTP response", hexStringToText(macAddressToString(httpresponse)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                            System.out.println(http);
                            packets.add(http);
                        }
                        else{
                            TCP tcp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                            System.out.println(tcp);
                            packets.add(tcp);
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

                            HTTP http=new HTTP(hexToDecimal(macAddressToString(sourceport)), hexToDecimal(macAddressToString(destport)), macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(), "HTTP request", hexStringToText(macAddressToString(httprequest)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                            System.out.println(http);
                            packets.add(http);
                            
                        }
                        else{
                            TCP tcp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                            System.out.println(tcp);
                            packets.add(tcp);
                        }
                        
                    }
                }
                else if(sport.equals("443") || dport.equals("443")){
                    the_protocol="TLS";
                    TCP tcp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                    System.out.println(tcp);
                    packets.add(tcp);
                }
                else{
                    TCP tcp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                    System.out.println(tcp);
                    packets.add(tcp);
                }
            }
            else if (macAddressToString(protocol).equals("01")){
                byte[] typeicmp = new byte[1];
                the_protocol="ICMP";
                System.arraycopy(ethernetFrame, 34, typeicmp, 0, 1);
                System.out.println("-----------Couche réseau--------------");
                System.out.println("ICMP de type " + macAddressToString(typeicmp));

                ICMP icmp=new ICMP( macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),getIcmpCodeMessage(macAddressToString(typeicmp)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                System.out.println(icmp);
                packets.add(icmp);
                
            }
            else if(macAddressToString(protocol).equals("11")){
                byte[] sourceport=new byte[2];
                byte[] destport=new byte[2];
                the_protocol="UDP";
                System.arraycopy(ethernetFrame, 14+ipheaderlength, sourceport, 0, 2);
                System.arraycopy(ethernetFrame, 14+ipheaderlength+2, destport, 0, 2);
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
                    byte[] dnsname=new byte[Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-8-2-2-12];
                    System.out.println("-----------Couche application--------------");
                    if (macAddressToString(dnsqr).equals("01:00")){
                        System.out.println("DNS query");
                        System.arraycopy(ethernetFrame, Integer.reverseBytes(capturedPacketLength)-2, dnsclass, 0, 2);
                        System.arraycopy(ethernetFrame, Integer.reverseBytes(capturedPacketLength)-4, dnstype, 0, 2);
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+12, dnsname, 0, Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-8-2-2-12);
                        System.out.println(hexStringToText(macAddressToString(dnsname)));
                        String dnsType="";
                        String dnsClass="";
                        if (macAddressToString(dnsclass).equals("00:01")){
                            System.out.println("DNS Class : IN");
                            dnsClass="IN";
                        }
                        if (macAddressToString(dnstype).equals("00:01")){
                            System.out.println("DNS Type : AAAA");
                            dnsType="AAAA";
                        }
                        if (macAddressToString(dnstype).equals("00:1C")){
                            System.out.println("DNS Type : A");
                            dnsType="A";
                        }
                        DNS dnsquery=new DNS( sport,dport ,macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),"DNS query ",dnsClass,dnsType,hexStringToText(macAddressToString(dnsname)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                        System.out.println(dnsquery);
                        packets.add(dnsquery);
                    
                    }
                    else if (macAddressToString(dnsqr).equals("81:80")){
                        System.out.println("DNS answer");
                        byte[] dnsresponse =new byte[Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-8];

                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+12, dnsresponse, 0, Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-8-12);
                        System.out.println(hexStringToText(macAddressToString(dnsresponse))+"\n");

                        DNS dnsanswer=new DNS( sport,dport ,macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),"DNS answer","","","", Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                        System.out.println(dnsanswer);
                        packets.add(dnsanswer);

                        StringBuilder dnsString = new StringBuilder(2 * ethernetFrame.length);
                        System.out.println(ethernetFrame.length);
                        int endnameindex=-1;

                        byte[] question= new byte[2];
                        byte[] answer= new byte[2];

                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+4, question, 0, 2);
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+4+2, answer, 0, 2);

                        int nbquestion=byteArrayToInt(question);
                        int nbanswer=byteArrayToInt(answer);

                        byte[] questiontype=new byte[2];
                        byte[] questionclass=new byte[2];

                        int indexendname=-1;
                        int indexendquestion=-1;
                        ArrayList<DNSquestion> questions=new ArrayList<DNSquestion>();
                        ArrayList<DNSanswer> answers=new ArrayList<DNSanswer>();

                        for(int j=1;j<=nbquestion;j++){
                            for (int i=14+ipheaderlength+8+12;i<= ethernetFrame.length-1;i++) {
                                dnsString.append(String.format("%02x", ethernetFrame[i]));
                                if (i < ethernetFrame.length - 1 && ethernetFrame[i] == 0 && ethernetFrame[i + 1] == 0) {
                                    indexendname=i;
                                    indexendquestion=i+5;
                                    byte[] questionname=new byte[indexendname-14-ipheaderlength-8-12];
                                    System.arraycopy(ethernetFrame, 14+ipheaderlength+8+12, questionname, 0, indexendname-14-ipheaderlength-8-12);
                                    System.arraycopy(ethernetFrame, indexendname+1, questiontype, 0, 2);
                                    System.arraycopy(ethernetFrame, indexendname+3, questionclass, 0, 2);
                                    //System.out.println(hexStringToText(macAddressToString(questionname)));
                                    //System.out.println((macAddressToString(questiontype)));
                                    //System.out.println((macAddressToString(questionclass)));

                                    questions.add(new DNSquestion(hexStringToText(macAddressToString(questionname)), macAddressToString(questiontype),macAddressToString(questionclass)));

                                    break;    
                                }
                            }
                        }
                        //System.out.println(indexendname);
                        //System.out.println(indexendquestion);

                        int indexendanswer=-1;
                        byte[] answertype=new byte[2];
                        byte[] answerclass=new byte[2];
                        
                        byte[] ttl=new byte[4];
                        byte[] datalength=new byte[2];
                        
                        int curanswer=0;
                        
                        for (int k=indexendquestion;k<= ethernetFrame.length-1;k++) {
                            if(curanswer<nbanswer){
                            dnsString.append(String.format("%02x", ethernetFrame[k]));
                            //System.out.println("k : " + k);
                            byte[] questionname=new byte[2];
                            System.arraycopy(ethernetFrame, k, questionname, 0, 2);
                            System.arraycopy(ethernetFrame, k+2, answertype, 0, 2);
                            System.arraycopy(ethernetFrame, k+4, answerclass, 0, 2);
                            System.arraycopy(ethernetFrame, k+6, ttl, 0, 4);
                            System.arraycopy(ethernetFrame, k+10, datalength, 0, 2);
                            /*
                            System.out.println(macAddressToString(questionname));
                            System.out.println((macAddressToString(answertype)));
                            System.out.println((macAddressToString(answerclass)));
                            System.out.println((macAddressToString(ttl)));
                            System.out.println((byteArrayToInt(datalength)));
                            */

                            byte[] data=new byte[byteArrayToInt(datalength)];
                            System.arraycopy(ethernetFrame, indexendquestion+12, data, 0, byteArrayToInt(datalength));
                            String adress="";
                            if(byteArrayToInt(datalength)==4){
                                //System.out.println(hexIPToIPAddress(macAddressToString(data)));
                                adress=hexIPToIPAddress(macAddressToString(data)).getHostAddress();
                            }
                            else if(byteArrayToInt(datalength)==16){
                                //System.out.println(macAddressToString(data));
                                adress=macAddressToString(data);
                            }
                            else{
                                //System.out.println(hexStringToText(macAddressToString(data)));
                                adress=hexStringToText(macAddressToString(data));
                            }
                            

                            k=k+11+byteArrayToInt(datalength);


                            answers.add(new DNSanswer(hexStringToText(macAddressToString(questionname)), macAddressToString(answertype),macAddressToString(answerclass),curanswer+1,byteArrayToInt(ttl),adress));
                            }
                            curanswer++;
                            
                            
                        }
                        

                        //System.out.println(dnsString.toString());
                        for (DNSquestion element : questions) {
                            System.out.println(element);
                        }
                        for (DNSanswer element : answers) {
                            System.out.println(element);
                        }
                        //DNS dnsanswer=new DNS( sport,dport ,macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),macAddressToString(quicversion),macAddressToString(cid),macAddressToString(sid), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                    }
                    
                    



                }
                if(sport.equals("443") || dport.equals("443")){
                    
                    the_protocol="QUIC";
                    byte[] quicheader=new byte[1];
                    System.arraycopy(ethernetFrame, 14+ipheaderlength+8, quicheader, 0, 1);
                    
                    int firstBit = (Character.getNumericValue(macAddressToString(quicheader).charAt(0)) >> 3) & 1;
                    System.out.println("-----------Couche application--------------");
                    if(firstBit==0){
                        QUIC quic=new QUIC( sport,dport ,macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),"","","", Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                        System.out.println(quic);
                        packets.add(quic);
                    }
                    else if(firstBit==1){
                        byte[] quicversion=new byte[4];
                        byte[] cidlength=new byte[1];
                    

                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1, quicversion, 0, 4);
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4, cidlength, 0, 1);

                        
                        System.out.println("QUIC version : " + macAddressToString(quicversion));
                        String quicVersion="";
                        if(macAddressToString(quicversion).equals("00:00:00:01")){
                            quicVersion="1";
                        }

                        

                        byte[] cid=new byte[hexToDecimale(macAddressToString(cidlength))];
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4+1, cid, 0, hexToDecimale(macAddressToString(cidlength)));
                        System.out.println("Destination Connection ID : "+ macAddressToString(cid));

                        byte[] sidlength=new byte[1];
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4+1+hexToDecimale(macAddressToString(cidlength)), sidlength, 0, 1);
                        
                        byte[] sid=new byte[hexToDecimale(macAddressToString(sidlength))];
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4+1+hexToDecimale(macAddressToString(cidlength))+1, sid, 0, hexToDecimale(macAddressToString(sidlength)));
                        System.out.println("Source Connection ID : "+ macAddressToString(sid));

                        QUIC quic=new QUIC( sport,dport ,macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),quicVersion,macAddressToString(cid),macAddressToString(sid), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                        System.out.println(quic);
                        packets.add(quic);
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

                    DHCP dhcp=new DHCP( (hexToDecimal(macAddressToString(sourceport))),(hexToDecimal(macAddressToString(destport))) , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),macAddressToString(dhcpqr),hexIPToIPAddress(macAddressToString(dhcpclient)).getHostAddress(),hexIPToIPAddress(macAddressToString(dhcpserver)).getHostAddress(), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                    System.out.println(dhcp);
                    packets.add(dhcp);
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
            ARP arp=new ARP( macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),getArpOpcodeMessage(macAddressToString(typearp)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
            System.out.println(arp);
            packets.add(arp);
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
    public static String hexToString(String hex) {
        int length = hex.length();
        StringBuilder texte = new StringBuilder();
        
        for (int i = 0; i < length; i += 2) {
            String paireHex = hex.substring(i, i + 2);
            int caractere = Integer.parseInt(paireHex, 16);
            texte.append((char) caractere);
        }
        
        return texte.toString();
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
    public static String getIcmpCodeMessage(String icmpCode) {
        switch (icmpCode) {
            case "00":
                return "ICMP Echo Reply";
            case "03":
                return "ICMP Destination Unreachable";
            case "04":
                return "ICMP Source Quench";
            case "05":
                return "ICMP Redirect Message";
            case "08":
                return "ICMP Echo Request";
            
            default:
                return "Code ICMP non reconnu";
        }
    }
    public static String getArpOpcodeMessage(String arpOpcode) {
        switch (arpOpcode) {
            case "00:01":
                return "ARP Request";
            case "00:02":
                return "ARP Reply";
            case "00:03":
                return "RARP Request";
            case "00:04":
                return "RARP Reply";
           
            default:
                return "Opcode ARP non reconnu";
        }
    }
    public static boolean estNombreEntier(String chaine) {
        try {
            Integer.parseInt(chaine);
            return true; // La conversion a réussi, c'est un nombre entier.
        } catch (NumberFormatException e) {
            return false; // La conversion a échoué, ce n'est pas un nombre entier.
        }
    }
    public static int byteArrayToInt(byte[] bytes) {
        int result = 0;
        for (int i = 0; i < bytes.length; i++) {
            result = (result << 8) | (bytes[i] & 0xFF);
        }
        return result;
    }
}
    


