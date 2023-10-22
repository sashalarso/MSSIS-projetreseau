public class TcpSegment {
    public int sport;
    public int dport;
    public String smacadress;
    public String dmacadress;
    public String sip;
    public String dip;
    public Long seq;
    public Long ack;
    public TcpSegment(int sport,int dport,String smacadress,String dmacadress, String sip, String dip,Long seq, Long ack){
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
