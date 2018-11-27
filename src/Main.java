import java.io.File;
import java.util.*;

public class Main
{
	public static void main(String args[]) throws Exception
	{
		long sTime = System.currentTimeMillis();

		// object to call methods 
		Training t = new Training();

		// contain details of all packets in each flow
		ArrayList<Flow> flows = t.createFlows(args[0]);

		Hashtable<String, ArrayList<Flow>> grouped_flows = t.groupAllFlows(flows);

		// detects those targets that are being subjected to brute force attacks
		ArrayList<String> brute_force = t.bruteForceDetection(grouped_flows);
		System.out.println("Number of clients carrying out brute force attacks: "+brute_force.size());

		// detects those targets which are compromised after the attack is successful
		t.compromiseDetection(grouped_flows, brute_force);

		long eTime = System.currentTimeMillis();

		long timeTaken = eTime-sTime;
		System.out.println("\nTime taken for algorithm execution: "+timeTaken+" seconds");

		// calculates accuracy of identification of compromises 
		t.calcAccuracy(grouped_flows, brute_force);
	}


}