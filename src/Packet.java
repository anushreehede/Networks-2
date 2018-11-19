// import java.sql.Timestamp;
// import java.text.SimpleDateFormat;
// import java.util.Date;

class Packet
{
	int id; // Packet ID
	int frame; // Frame number (pcap)
	int incoming; // Whether packet is incoming to server (1) or not (0)
	String sourceIP; 
	String destIP;
	String sourcePort;
	String destPort;
	String timestamp;
	int size; // Payload size
	int trans_point; // 1 if packet marks transition point 1, 2 for transition point 2, 0 otherwise
	int login; // 1 if packet is a login packet from client to server, 0 otherwise

	public Packet()
	{
		
	}

	Packet(int id, int frame, int incoming, String sourceIP, String destIP, String sourcePort,String destPort,String timestamp,int size,int trans_point, int login)
	{
		this.id = id;
		this.frame = frame;
		this.incoming=incoming;
		this.sourceIP = sourceIP;
		this.destIP = destIP;
		this.sourcePort = sourcePort;
		this.destPort = destPort;
		this.timestamp = timestamp;
		this.size=size;
		this.trans_point=trans_point;
		this.login = login;
		
	}

	void printPacket()
	{
		System.out.println("Packet ID: "+id+ ", Frame: "+frame+", Incoming: "+incoming+"\nSource IP: "+sourceIP+", Destination IP: "+destIP+"\nSource port no: "+sourcePort+", Destination port: "+destPort+"\nTimestamp: "+timestamp+", Size: "+size+"\n");
	}
}