Compilation `javac src/PcapParser.java`

Obtenir de l'aide `java PcapParser help`

Visualiser tout les protocoles parsés `java PcapParser file.pcap`

Filtrer par protocole `java PcapParser file.pcap NOM_DU_PROTOCOLE` nom du protocole à passer en majuscule

Filtrer par numéro du paquet `java PcapParser file.pcap numero_du_paquet`

Suivre un paquet `java PcapParser file.pcap -t numero_du_paquet` Cette fonctionnalité est valide pour les paquets de type HTTP ou TCP
