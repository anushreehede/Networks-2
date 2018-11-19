import java.util.*;
import java.text.SimpleDateFormat;

class Flow implements Comparable<Flow>
{
	int id; // Flow ID

	// List of all the packets in the flow
	ArrayList<Packet> features = new ArrayList<Packet>();
	// Lines in the logs of the flow
	ArrayList<String> logs = new ArrayList<String>();
	// Which holds the predicted type of flow
	String label;
	// Which holds the actual type of flow
	String actual;

	// Flow constructor
	public Flow(int i,ArrayList<Packet> p, ArrayList<String> l)
	{
		id = i;
		for(Packet pk : p)
		{
			features.add(pk);
		}
		for(String s : l)
		{
			logs.add(s);
		} 

		actual = "";
		label = "";
	}

	// Printing flow
	void printFlow()
	{
		System.out.print("\nFlow: "+id+"\n");
		for(Packet i:this.features)
			i.printPacket();
		System.out.println("Actual: "+this.actual);
		System.out.println("Predicted: "+this.label);
	}

	public int compareTo(Flow f)
	{
		long lhs = 0;
		try 
		{
		    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
		    Date parsedDate = dateFormat.parse(this.features.get(0).timestamp);
		    lhs = parsedDate.getTime();
		    // System.out.println(ts+"\n-------------");

		} catch(Exception e) { //this generic but you can control another types of exception
		    // look the origin of excption 
		    System.out.println(e);
		}
		long rhs = 0;
		try 
		{
		    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
		    Date parsedDate = dateFormat.parse(f.features.get(0).timestamp);
		    rhs = parsedDate.getTime();
		    // System.out.println(ts+"\n-------------");

		} catch(Exception e) { //this generic but you can control another types of exception
		    // look the origin of excption 
		    System.out.println(e);
		}
	    return (int)(lhs - rhs);
	}
}