public class TCP {
    public String packetnumber;
    public String timestamp;
    public int packetlength;
    public String sport;
    public String dport;
    public String smacadress;
    public String dmacadress;
    public String sip;
    public String dip;
    public Long seq;
    public Long ack;
    public TCP(String sport,String dport,String smacadress,String dmacadress, String sip, String dip,Long seq, Long ack,String packetnumber,String timestamp,int packetlength){
        this.sport = sport;
        this.dport =  dport;
        this.smacadress= smacadress;
        this.dmacadress =  dmacadress;
        this.sip = sip;
        this.dip = dip;
        this.seq=  seq;
        this.ack = ack;
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
                "TCP \n"+
                "Source port: " + this.sport + "\n"+
                "Destination port : " + this.dport + "\n"+
                "Sequence number : "+ this.seq+"\n"+
                "Acknowledgment number : "+this.ack+"\n"+
                
                "-------------------------------------------\n";



    }
}
