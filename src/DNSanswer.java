public class DNSanswer {
    public String name;
    public String type;
    public String dnsclass;
    public int number;
    public int ttl;
    public String adress;
    
    
    public DNSanswer(String name,String type,String dnsclass,int number,int ttl,String adress){
       this.name=name;
       this.type=type;
       this.dnsclass=dnsclass;
       this.number=number;
       this.ttl=ttl;
       this.adress=adress;
        
    }
    public String toString(){
        return  
                "Answer number : " + this.number + "\n"+
                "Name : " + this.name +"\n"+
                "Type : " + this.type +"\n" +
                "Class : " + this.dnsclass +"\n"+
                "TTL : " + this.ttl +"\n"+
                "Adress/CNAME : " + this.adress;
                



    }
}