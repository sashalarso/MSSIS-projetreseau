import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;


public class PcapParser {

    public static ArrayList<Object> packets=new ArrayList<Object>();
    public static ArrayList<tcpstream> streams =new ArrayList<tcpstream>();
    public static void main(String[] args) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {

        if(args[0].equals("help")){
            System.out.println("Pour entrer votre propre fichier, tapez son nom en premier argument");
            System.out.println("Protocoles supportés: ARP, ICMP, QUIC, HTTP, DNS, IPV4, TCP, UDP");
            System.out.println("Pour filtrer en fonction du protocole simplement taper après le fichier pcap le protocole en majuscules");
            System.out.println("Exemple de commande : java PcapParser foo.pcap ARP");
            System.out.println("Pour filtrer en fonction du numéro de paquet simplement taper après le fichier pcap le numéro");
            System.out.println("Exemple de commande : java PcapParser foo.pcap 25");
            System.out.println("Pour utiliser le tcp stream entrer -t suivi du numéro de paquet a suivre");
            System.out.println("Exemple de commande : java PcapParser foo.pcap -t 25");
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
        
            
            
            
        } catch (IOException e) {
            e.printStackTrace();
        }
        int j=0;

        for (Object element : packets) {
            j=j+1;
            if(args.length<2){
                System.out.println(element);
            }
            else if(element.getClass().getName().equals(args[1])){
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
        String portsource="";
        String portdest="";
        String ipsource="";
        String ipdest="";
        try {
            if(args[1].equals("-t")){
            String packetn=args[2];
            
            for (tcpstream element : streams){
                if (element.getpacketnumber().equals(packetn)){
                    portsource=element.getsourceport();
                    portdest=element.getdestport();
                    ipsource=element.getsourceip();
                    ipdest=element.getdestip();
                    
                }
            }
        }
        } catch (Exception e) {
            // TODO: handle exception
        }
        
       

        for(tcpstream element: streams){
            if((element.getsourceport().equals(portsource) || element.getdestport().equals(portsource)) && (element.getsourceport().equals(portdest) || element.getdestport().equals(portdest)) && (element.getsourceip().equals(ipsource) || element.getdestip().equals(ipsource)) && (element.getsourceip().equals(ipdest) || element.getdestip().equals(ipdest))) {
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
        
     
        int date_packet=hexToDecimale(Integer.toHexString(Integer.reverseBytes(timestampSeconds)));
       

        
        byte[] ethernetFrame = new byte[Integer.reverseBytes(capturedPacketLength)];
        
        
        dis.readFully(ethernetFrame);
        
       
        byte[] sourceMAC = new byte[6];
        byte[] destMAC = new byte[6];
        byte[] typeIp = new byte[2];
        System.arraycopy(ethernetFrame, 0, destMAC, 0, 6);
        System.arraycopy(ethernetFrame, 6, sourceMAC, 0, 6);
        System.arraycopy(ethernetFrame, 12, typeIp, 0, 2);

        
        
       
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
           
           
            
            if (macAddressToString(protocol).equals("06")){
                 byte[] sourceport=new byte[2];
                byte[] destport=new byte[2];
                byte[] headerlengthtcp=new byte[1];

                System.arraycopy(ethernetFrame, 14+ipheaderlength+12, headerlengthtcp, 0, 1);
                int tcpheaderlength= Character.getNumericValue(macAddressToString(headerlengthtcp).charAt(0))*4;
                

                System.arraycopy(ethernetFrame, 14+ipheaderlength, sourceport, 0, 2);
                System.arraycopy(ethernetFrame, 14+ipheaderlength+2, destport, 0, 2);

                String sport=Integer.toString(hexToDecimal(macAddressToString(sourceport)));
                String dport=Integer.toString(hexToDecimal(macAddressToString(destport)));

                byte[] seq=new byte[4];
                byte[] ack =new byte[4];

                System.arraycopy(ethernetFrame, 14+ipheaderlength+4, seq, 0, 4);
                System.arraycopy(ethernetFrame, 14+ipheaderlength+8, ack, 0, 4);

              
               

                TCP tcpp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                
                the_protocol="TCP";
                

                
                if(sport.equals("80") || dport.equals("80")){
                    
                    if(sport.equals("80")){
                        
                        byte[] httpresponse =new byte[Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-tcpheaderlength];
                        

                        System.arraycopy(ethernetFrame, 14+ipheaderlength+tcpheaderlength, httpresponse, 0, Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-tcpheaderlength);
                        

                        if (hexStringToText(macAddressToString(httpresponse)).contains("HTTP/1.1")){
                            the_protocol="HTTP";
                           

                            HTTP http=new HTTP(sport, dport, macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(), "HTTP response", hexStringToText(macAddressToString(httpresponse)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                           
                            packets.add(http);
                            streams.add(http);
                        }
                        else{
                            TCP tcp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                        
                            packets.add(tcp);
                            streams.add(tcp);
                        }
                        
                    }
                    else if (dport.equals("80")){
                        

                        
                        byte [] httprequest= new byte[Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-tcpheaderlength];
                        
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+tcpheaderlength, httprequest, 0, Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-tcpheaderlength);
                        if (hexStringToText(macAddressToString(httprequest)).contains("HTTP/1.1")){
                           
                            the_protocol="HTTP";
                           

                            HTTP http=new HTTP(sport, dport, macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(), "HTTP request", hexStringToText(macAddressToString(httprequest)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                           
                            packets.add(http);
                            streams.add(http);
                            
                        }
                        else{
                            TCP tcp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                        
                            packets.add(tcp);
                            streams.add(tcp);
                        }
                        
                    }
                }
                else if(sport.equals("443") || dport.equals("443")){
                    the_protocol="TLS";
                    TCP tcp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                   
                    packets.add(tcp);
                    streams.add(tcp);
                }
                else{
                    TCP tcp=new TCP( sport,dport , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),hexToLong(macAddressToString(seq)),hexToLong(macAddressToString(ack)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                    
                    packets.add(tcp);
                    streams.add(tcp);
                }
                
            }
            else if (macAddressToString(protocol).equals("01")){
                byte[] typeicmp = new byte[1];
                the_protocol="ICMP";
                System.arraycopy(ethernetFrame, 34, typeicmp, 0, 1);
                

                ICMP icmp=new ICMP( macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),getIcmpCodeMessage(macAddressToString(typeicmp)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
               
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

                String lastname="";              
                

                if(sport.equals("53") || dport.equals("53")){
                    the_protocol="DNS";
                    byte [] dnsqr=new byte[2];

                    System.arraycopy(ethernetFrame, 44, dnsqr, 0, 2);
                    
                    byte[] dnsclass =new byte [2];
                    byte[] dnstype=new byte[2];
                    byte[] dnsname=new byte[Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-8-2-2-12];
                   
                    if (macAddressToString(dnsqr).equals("01:00")){
                     
                        System.arraycopy(ethernetFrame, Integer.reverseBytes(capturedPacketLength)-2, dnsclass, 0, 2);
                        System.arraycopy(ethernetFrame, Integer.reverseBytes(capturedPacketLength)-4, dnstype, 0, 2);
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+12, dnsname, 0, Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-8-2-2-12);
                      
                        String dnsType="";
                        String dnsClass="";
                        if (macAddressToString(dnsclass).equals("00:01")){
                            
                            dnsClass="IN";
                        }
                        
                        
                        if (macAddressToString(dnstype).equals("00:01")){
                         
                            dnsType="AAAA";
                        }
                        else if (macAddressToString(dnstype).equals("00:1C")){
                            
                            dnsType="A";
                        }
                        else if (macAddressToString(dnstype).equals("00:0F")){
                            
                            dnsType="MX";
                        }
                        ArrayList<DNSquestion> questions=new ArrayList<DNSquestion>();
                        ArrayList<DNSanswer> answers=new ArrayList<DNSanswer>();
                        ArrayList<DNSauthoritative> authoritatives=new ArrayList<DNSauthoritative>();
                        questions.add(new DNSquestion(hexStringToText(macAddressToString(dnsname)) , dnsType, dnsClass));
                        DNS dnsquery=new DNS( sport,dport ,macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),"DNS query ",dnsClass,dnsType,hexStringToText(macAddressToString(dnsname)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength),questions,answers,authoritatives);
                        
                        packets.add(dnsquery);
                    
                    }
                    else if (macAddressToString(dnsqr).equals("81:80")){
                        
                        byte[] dnsresponse =new byte[Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-8];

                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+12, dnsresponse, 0, Integer.reverseBytes(capturedPacketLength)-14-ipheaderlength-8-12);
                        

                        

                        StringBuilder dnsString = new StringBuilder(2 * ethernetFrame.length);
                        
                        int endnameindex=-1;

                        byte[] question= new byte[2];
                        byte[] answer= new byte[2];
                        byte[] authority=new byte[2];

                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+4, question, 0, 2);
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+4+2, answer, 0, 2);
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+4+2+2, authority, 0, 2);

                        int nbquestion=byteArrayToInt(question);
                        int nbanswer=byteArrayToInt(answer);
                        int nbauthority=byteArrayToInt(authority);

                        byte[] questiontype=new byte[2];
                        byte[] questionclass=new byte[2];

                        int indexendname=-1;
                        int indexendquestion=-1;
                        ArrayList<DNSquestion> questions=new ArrayList<DNSquestion>();
                        ArrayList<DNSanswer> answers=new ArrayList<DNSanswer>();
                        ArrayList<DNSauthoritative> authoritatives=new ArrayList<DNSauthoritative>();

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
                                    String qtype="";
                                    switch((macAddressToString(questiontype))){
                                        case "00:1C":
                                            qtype="AAAA";
                                            break;
                                        case "00:05":
                                            qtype="CNAME";
                                            break;
                                        case "00:01":
                                            qtype="A";
                                            break;
                                        case "00:0F":
                                            qtype="MX";
                                            break;

                                    }
                                    String qclass="";
                                    switch(macAddressToString(questionclass)){
                                        
                                        case "00:01":
                                            qclass="IN";
                                            break;

                                    }
                                    questions.add(new DNSquestion(hexStringToText(macAddressToString(questionname)), qtype,qclass));
                                    lastname=hexStringToText(macAddressToString(questionname));
                                    break;    
                                }
                            }
                        }
                      
                        int indexendanswer=-1;
                        byte[] answertype=new byte[2];
                        byte[] answerclass=new byte[2];
                        
                        byte[] ttl=new byte[4];
                        byte[] datalength=new byte[2];
                        
                        int curanswer=0;
                        
                        for (int k=indexendquestion;k<= ethernetFrame.length-1;k++) {
                            if(curanswer<nbanswer){
                            dnsString.append(String.format("%02x", ethernetFrame[k]));
                            
                            byte[] questionname=new byte[2];
                            System.arraycopy(ethernetFrame, k, questionname, 0, 2);
                            System.arraycopy(ethernetFrame, k+2, answertype, 0, 2);
                            System.arraycopy(ethernetFrame, k+4, answerclass, 0, 2);
                            System.arraycopy(ethernetFrame, k+6, ttl, 0, 4);
                            System.arraycopy(ethernetFrame, k+10, datalength, 0, 2);
                            String atype="";
                            String qname="";
                            if(macAddressToString(questionname).length()==5){
                                    
                                    qname=lastname;
                                    
                                }
                            switch(macAddressToString(answertype)){
                                case "00:1C":
                                    atype="AAAA";
                                    break;
                                case "00:05":
                                    atype="CNAME";
                                    break;
                                case "00:01":
                                    atype="A";
                                    break;
                                case "00:0F":
                                    atype="MX";
                                    break;

                            }
                            String aclass="";
                            switch(macAddressToString(answerclass)){
                                
                                case "00:01":
                                    aclass="IN";
                                    break;

                            }

                            byte[] data=new byte[byteArrayToInt(datalength)];
                            System.arraycopy(ethernetFrame, indexendquestion+12, data, 0, byteArrayToInt(datalength));
                            String adress="";
                            if(byteArrayToInt(datalength)==4){
                                
                                adress=hexIPToIPAddress(macAddressToString(data)).getHostAddress();
                            }
                            else if(byteArrayToInt(datalength)==16){
                               
                                adress=macAddressToString(data);
                            }
                            else{
                               
                                adress=hexStringToText(macAddressToString(data));
                            }
                            

                            k=k+11+byteArrayToInt(datalength);
                            indexendanswer=k;


                            answers.add(new DNSanswer(qname, atype,aclass,curanswer+1,byteArrayToInt(ttl),adress));
                            }
                            curanswer++;
                            
                            
                        }
                        int curauthority=0;

                        byte[] authotype=new byte[2];
                        byte[] authoclass=new byte[2];
                        
                        byte[] authottl=new byte[4];
                        byte[] authoname=new byte[2];

                        String authname="";

                        for(int l=indexendanswer+1;l<ethernetFrame.length-1;l++){
                            if(curauthority<nbauthority){
                                curauthority++;
                                System.arraycopy(ethernetFrame, l, authoname, 0, 2);
                                System.arraycopy(ethernetFrame, l+2, authotype, 0, 2);
                                System.arraycopy(ethernetFrame, l+4, authoclass, 0, 2);
                                System.arraycopy(ethernetFrame, l+6, authottl, 0, 4);
                                byte[] pointer=new byte[1];
                                if(macAddressToString(authoname).length()==5){
                                    System.arraycopy(ethernetFrame, l+1, pointer, 0, 1);
                                    authname=lastname;
                                }

                                String authtype="";
                                switch(macAddressToString(authotype)){
                                    case "00:1C":
                                        authtype="AAAA";
                                        break;
                                    case "00:05":
                                        authtype="CNAME";
                                        break;
                                    case "00:01":
                                        authtype="A";
                                        break;
                                    case "00:06":
                                        authtype="SOA";
                                        break;

                                }
                                String authclass="";
                                switch(macAddressToString(authoclass)){
                                    
                                    case "00:01":
                                        authclass="IN";
                                        break;

                                }
                                /*
                                System.out.println(macAddressToString(authoname));
                                System.out.println(authtype);
                                System.out.println(authclass);
                                System.out.println(byteArrayToInt(authottl));
                                */
                                authoritatives.add(new DNSauthoritative(authname, authtype, authclass, curauthority, byteArrayToInt(authottl)));
                                
                            }
                        }

                        

                        DNS dnsanswer=new DNS( sport,dport ,macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),"DNS answer","","","", Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength),questions,answers,authoritatives);
                       
                        packets.add(dnsanswer);
                        
                    }
                    
                    



                }
                if(sport.equals("443") || dport.equals("443")){
                    
                    the_protocol="QUIC";
                    byte[] quicheader=new byte[1];
                    System.arraycopy(ethernetFrame, 14+ipheaderlength+8, quicheader, 0, 1);
                    
                    int firstBit = (Character.getNumericValue(macAddressToString(quicheader).charAt(0)) >> 3) & 1;
                   
                    if(firstBit==0){
                        QUIC quic=new QUIC( sport,dport ,macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),"","","", Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                       
                        packets.add(quic);
                    }
                    else if(firstBit==1){
                        byte[] quicversion=new byte[4];
                        byte[] cidlength=new byte[1];
                    

                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1, quicversion, 0, 4);
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4, cidlength, 0, 1);

                        
                        
                        String quicVersion="";
                        if(macAddressToString(quicversion).equals("00:00:00:01")){
                            quicVersion="1";
                        }

                        

                        byte[] cid=new byte[hexToDecimale(macAddressToString(cidlength))];
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4+1, cid, 0, hexToDecimale(macAddressToString(cidlength)));
                        

                        byte[] sidlength=new byte[1];
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4+1+hexToDecimale(macAddressToString(cidlength)), sidlength, 0, 1);
                        
                        byte[] sid=new byte[hexToDecimale(macAddressToString(sidlength))];
                        System.arraycopy(ethernetFrame, 14+ipheaderlength+8+1+4+1+hexToDecimale(macAddressToString(cidlength))+1, sid, 0, hexToDecimale(macAddressToString(sidlength)));
                        

                        QUIC quic=new QUIC( sport,dport ,macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),quicVersion,macAddressToString(cid),macAddressToString(sid), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                        
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
                    
                   
                    if (macAddressToString(dhcpqr).equals("01")){

                        
                    }
                    if (macAddressToString(dhcpqr).equals("02")){
                        
                    }
                   

                    DHCP dhcp=new DHCP( (hexToDecimal(macAddressToString(sourceport))),(hexToDecimal(macAddressToString(destport))) , macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),getDHCPMessage(macAddressToString(dhcpqr)),hexIPToIPAddress(macAddressToString(dhcpclient)).getHostAddress(),hexIPToIPAddress(macAddressToString(dhcpserver)).getHostAddress(), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
                    
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

            the_protocol="ARP";
            ARP arp=new ARP( macAddressToString(sourceMAC), macAddressToString(destMAC), hexIPToIPAddress(macAddressToString(ipsource)).getHostAddress(), hexIPToIPAddress(macAddressToString(ipdest)).getHostAddress(),getArpOpcodeMessage(macAddressToString(typearp)), Integer.toString(packetNumber), convertTimestampToDate(date_packet).toString(), Integer.reverseBytes(capturedPacketLength));
            
            packets.add(arp);
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
            return -1; 
        }
    }
    public static Long hexToLong(String hex) {
        try {
            return Long.parseLong(hex.replace(":", ""), 16);
        } catch (NumberFormatException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static InetAddress hexIPToIPAddress(String hexIP) {
        
        hexIP = hexIP.replaceAll(":", "");

        if (hexIP.length() != 8) {
            System.err.println("La chaîne hexadécimale doit contenir exactement 8 caractères.");
            return null;
        }

        try {
           
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
           
            int decimal = Integer.parseInt(hex, 16);
            return decimal;
        } catch (NumberFormatException e) {
            e.printStackTrace();
            return -1; 
        }
    }
    public static String reverseString(String input) {
        if (input == null) {
            return null; 
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
    public static String getDHCPMessage(String dhcpcode) {
        switch (dhcpcode) {
            case "01":
                return "Boot request";
            case "02":
                return "Boot reply";
            
            default:
                return "Message DHCP non reconnu";
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
    


