public class DHCP {
    public String packetnumber;
    public String timestamp;
    public int packetlength;
    public int sport;
    public int dport;
    public String smacadress;
    public String dmacadress;
    public String sip;
    public String dip;
    public String dhcpqr;
    public String dhcpclient;
    public String dhcpserver;
    public DHCP(int sport,int dport,String smacadress,String dmacadress, String sip, String dip,String dhcpqr, String dhcpclient,String dhcpserver,String packetnumber,String timestamp,int packetlength){
        this.sport = sport;
        this.dport =  dport;
        this.smacadress= smacadress;
        this.dmacadress =  dmacadress;
        this.sip = sip;
        this.dip = dip;
        this.dhcpqr= dhcpqr;
        this.dhcpclient=dhcpclient;
        this.dhcpserver=dhcpserver;
        this.packetnumber=packetnumber;
        this.timestamp=timestamp;
        this.packetlength=packetlength;
    }
    public String toString(){
        return  "------------------------------------------\n"+
                "Packet " + this.packetnumber +" : \n"+
                "Timestamp : " + this.timestamp +"\n" +
                "Packet length : " + this.packetlength +"\n"+
                "--------------Couche liaison-------------\n"+
                "Source MAC Adress: " + this.smacadress +"\n"+
                "Destination MAC Adress : " +this.dmacadress +"\n"+
                "--------------Couche réseau--------------\n"+
                "IP source: " +this.sip + "\n"+
                "IP destination: " + this.dip+"\n"+
                "-------------Couche transport------------\n"+
                "Source port: " + this.sport + "\n"+
                "Destination port : " + this.dport + "\n"+
                "--------------Couche application----------\n"+
                "DHCP \n"+
                this.dhcpqr +"\n"+
                "DHCP client : "+this.dhcpclient+"\n"+
                "DHCP server : "+this.dhcpserver+"\n"+
                "-------------------------------------------\n";



    }
}
