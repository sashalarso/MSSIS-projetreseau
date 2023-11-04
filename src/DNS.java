import java.util.ArrayList;

public class DNS {
    public String packetnumber;
    public String timestamp;
    public int packetlength;
    public String sport;
    public String dport;
    public String smacadress;
    public String dmacadress;
    public String sip;
    public String dip;
    public String dnsqr;
    public String dnstype;
    public String dnsclass;
    public String dnsname;
    public ArrayList<DNSquestion> questions;
    public ArrayList<DNSanswer> answers;
    public ArrayList<DNSauthoritative> authoritatives;

    public DNS(String sport,String dport,String smacadress,String dmacadress, String sip, String dip,String dnsqr,String dnstype, String dnsclass,String dnsname,String packetnumber,String timestamp,int packetlength,ArrayList<DNSquestion> questions,ArrayList<DNSanswer> answers,ArrayList<DNSauthoritative> authoritatives){
        this.sport = sport;
        this.dport =  dport;
        this.smacadress= smacadress;
        this.dmacadress =  dmacadress;
        this.sip = sip;
        this.dip = dip;
        this.dnsqr=dnsqr;
        this.dnstype=dnstype;
        this.dnsclass=dnsclass;
        this.dnsname=dnsname;
        this.packetnumber=packetnumber;
        this.timestamp=timestamp;
        this.packetlength=packetlength;
        this.questions=questions;
        this.answers=answers;
        this.authoritatives=authoritatives;
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
                "DNS \n"+
                this.dnsqr +"\n"+
                
                "Questions : " +this.questions+"\n"+
                "Answers : " + this.answers+"\n"+
                "Authoritatives : " + this.authoritatives+"\n"+
                "-------------------------------------------\n";



    } 
}