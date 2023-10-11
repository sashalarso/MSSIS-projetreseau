import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class PcapParser {
    public static void main(String[] args) {
        String pcapFilePath = "test.pcap";

        try (FileInputStream fis = new FileInputStream(pcapFilePath);
             DataInputStream dis = new DataInputStream(fis)) {

            // Parse the Global Header
            parseGlobalHeader(dis);

            int packetNumber = 0;

            while (dis.available() > 0) {
                // Parse each packet
                parsePacket(dis, packetNumber);
                packetNumber++;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void parseGlobalHeader(DataInputStream dis) throws IOException {
        // Read and parse the Global Header
        byte[] globalheader = new byte[24];
        dis.readFully(globalheader);
        /*
        int magicNumber = dis.readInt();
        short majorVersion = dis.readShort();
        short minorVersion = dis.readShort();
        int timeZoneOffset = dis.readInt();
        int timestampAccuracy = dis.readInt();
        int maxLengthCaptured = dis.readInt();
        
        // Print Global Header information
        System.out.println("PCAP Global Header:");
        System.out.println("Magic Number: 0x" + Integer.toHexString(magicNumber));
        System.out.println("Major Version: " + Integer.toHexString(majorVersion));
        System.out.println("Minor Version: " + Integer.toHexString(minorVersion));
        System.out.println("Time Zone Offset: " + Integer.toHexString(timeZoneOffset));
        System.out.println("Timestamp Accuracy: " + Integer.toHexString(timestampAccuracy));
        System.out.println("Max Length Captured: " + Integer.toHexString(maxLengthCaptured));
        System.out.println();
        */
    }

    private static void parsePacket(DataInputStream dis, int packetNumber) throws IOException {
        // Parse each packet
        
        int timestampSeconds = dis.readInt();
        int timestampMicroseconds = dis.readInt();
        int capturedPacketLength = dis.readInt();
        int originalPacketLength = dis.readInt();
        
        // Print Packet information
        System.out.println("Packet " + packetNumber + ":");
        System.out.println("Timestamp (seconds): " + Integer.toHexString(timestampSeconds));
        System.out.println("Timestamp (microseconds): " + Integer.toHexString(timestampMicroseconds));
        System.out.println("Captured Packet Length: " + (Integer.reverseBytes(capturedPacketLength)));
        System.out.println("Original Packet Length: " + originalPacketLength);

        // Read and parse Ethernet frame (Assuming Ethernet II frame)
        byte[] ethernetFrame = new byte[Integer.reverseBytes(capturedPacketLength)];
        System.out.println(dis.available());
        dis.readFully(ethernetFrame);
        
        // Extract source and destination MAC addresses
        byte[] sourceMAC = new byte[6];
        byte[] destMAC = new byte[6];
        byte[] typeIp = new byte[2];
        System.arraycopy(ethernetFrame, 0, destMAC, 0, 6);
        System.arraycopy(ethernetFrame, 6, sourceMAC, 0, 6);
        System.arraycopy(ethernetFrame, 12, typeIp, 0, 2);

        System.out.println("Source MAC Address: " + macAddressToString(sourceMAC));
        System.out.println("Destination MAC Address: " + macAddressToString(destMAC));
        System.out.println("Type of IP: " + macAddressToString(typeIp));
        // You can continue parsing other layers like IP and TCP/UDP as needed.
        
        System.out.println();
    }

    private static String macAddressToString(byte[] macAddress) {
        StringBuilder sb = new StringBuilder();
        for (byte b : macAddress) {
            sb.append(String.format("%02X:", b));
        }
        return sb.substring(0, sb.length() - 1); // Remove the trailing ':'
    }
}
