import java.io.File;
import java.util.*;

public class Main
{
	public static void main(String args[]) throws Exception
	{
		// object to call methods 
		Training t = new Training();

		// contain details of all packets in each flow
		ArrayList<Flow> flows = t.createFlows(args[0]);

		Hashtable<String, ArrayList<Flow>> grouped_flows = t.groupAllFlows(flows);

		// detects those targets that are being subjected to brute force attacks
		ArrayList<String> brute_force = t.bruteForceDetection(grouped_flows);

		// detects those targets which are compromised after the attack is successful
		t.compromiseDetection(grouped_flows, brute_force);

		// calculates accuracy of identification of compromises 
		t.calcAccuracy(grouped_flows, brute_force);
	}


}