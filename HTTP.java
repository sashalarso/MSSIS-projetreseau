import java.util.stream.Stream;

public class HTTP implements tcpstream {
    public String packetnumber;
    public String timestamp;
    public int packetlength;
    public String sport;
    public String dport;
    public String smacadress;
    public String dmacadress;
    public String sip;
    public String dip;
    public String httpqr;
    public String httpdata;

    public HTTP(String sport,String dport,String smacadress,String dmacadress, String sip, String dip,String httpqr,String httpdata,String packetnumber,String timestamp,int packetlength){
        this.sport = sport;
        this.dport =  dport;
        this.smacadress= smacadress;
        this.dmacadress =  dmacadress;
        this.sip = sip;
        this.dip = dip;
        this.httpqr=httpqr;
        this.httpdata=httpdata;
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
                "HTTP \n"+
                this.httpqr +"\n"+
                this.httpdata+"\n"+
                "-------------------------------------------\n";



    }

    @Override
    public String getpacketnumber() {
        return this.packetnumber;
    }

    @Override
    public String getsourceip() {
        return this.sip;
    }

    @Override
    public String getdestip() {
        return this.dip;
    }

    @Override
    public String getsourceport() {
        return this.sport;
    }

    @Override
    public String getdestport() {
        return this.dport;
}
}
