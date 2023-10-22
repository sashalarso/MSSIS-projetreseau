public class TcpSegment {
    public int sport;
    public int dport;
    public String smacadress;
    public String dmacadress;
    public String sip;
    public String dip;
    public int seq;
    public int ack;
    public TcpSegment(int sport,int dport,String smacadress,String dmacadress, String sip, String dip,int seq, int ack){
        this.sport = sport;
        this.dport =  dport;
        this.smacadress= smacadress;
        this.dmacadress =  dmacadress;
        this.sip = sip;
        this.dip = dip;
        this.seq=  seq;
        this.ack = ack;
    }
}
