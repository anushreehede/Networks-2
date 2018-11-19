import java.io.File;
import java.util.*;

public class Main
{
	public static void main(String args[]) throws Exception
	{
		// object to call methods 
		Functionality f = new Functionality();

		// contain details of all packets in each flow
		ArrayList<Flow> flows = f.createFlows(args[0]);

		Hashtable<String, ArrayList<Flow>> grouped_flows = f.groupAllFlows(flows);

		// detects those targets that are being subjected to brute force attacks
		f.bruteForceDetection(grouped_flows);

		// detects those targets which are compromised after the attack is successful
		f.compromiseDetection(flows);


	}


}