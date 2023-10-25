public class ARP {
    public String packetnumber;
    public String timestamp;
    public int packetlength;
    public String smacadress;
    public String dmacadress;
    public String sip;
    public String dip;
    public String arptype;
    
    public ARP(String smacadress,String dmacadress, String sip, String dip,String arptype,String packetnumber,String timestamp,int packetlength){
       
        this.smacadress= smacadress;
        this.dmacadress =  dmacadress;
        this.sip = sip;
        this.dip = dip;
        this.arptype=arptype;
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
                "ARP \n" +
                "ARP Type : "+this.arptype+"\n"+
                "-------------------------------------------\n";



    }
}