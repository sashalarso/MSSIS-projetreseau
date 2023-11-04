public class QUIC {
    public String packetnumber;
    public String timestamp;
    public int packetlength;
    public String sport;
    public String dport;
    public String smacadress;
    public String dmacadress;
    public String sip;
    public String dip;
    public String quicversion;
    public String cid;
    public String sid;
    public QUIC(String sport,String dport,String smacadress,String dmacadress, String sip, String dip,String quicversion,String cid,String sid,String packetnumber,String timestamp,int packetlength){
        this.sport = sport;
        this.dport =  dport;
        this.smacadress= smacadress;
        this.dmacadress =  dmacadress;
        this.sip = sip;
        this.dip = dip;
        this.quicversion=quicversion;
        this.cid=cid;
        this.sid=sid;
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
            "QUIC \n"+
            "QUIC version : "+this.quicversion +"\n"+
            "Source connection ID : "+this.sid+"\n"+
            "Destination connection ID : "+this.cid+"\n"+
            "-------------------------------------------\n";



}
}