public class DNSauthoritative {
    public String name;
    public String type;
    public String dnsclass;
    public int number;
    public int ttl;
  
    
    
    public DNSauthoritative(String name,String type,String dnsclass,int number,int ttl){
       this.name=name;
       this.type=type;
       this.dnsclass=dnsclass;
       this.number=number;
       this.ttl=ttl;
      
        
    }
    public String toString(){
        return  
                "Authoritative Namerserver number : " + this.number + "\n"+
                "Name : " + this.name +"\n"+
                "Type : " + this.type +"\n" +
                "Class : " + this.dnsclass +"\n"+
                "TTL : " + this.ttl +"\n";
                
                



    }
}