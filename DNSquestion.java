public class DNSquestion {
    public String name;
    public String type;
    public String dnsclass;
    
    
    public DNSquestion(String name,String type,String dnsclass){
       this.name=name;
       this.type=type;
       this.dnsclass=dnsclass;
        
    }
    public String toString(){
        return  
                "Query \n" +
                "Name : " + this.name +"\n"+
                "Type : " + this.type +"\n" +
                "Class : " + this.dnsclass +"\n";
                



    }
}