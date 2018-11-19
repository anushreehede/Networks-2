import java.util.*;
import java.io.*;
import java.lang.*; 

class Functionality
{
	// Method to get flow information from the logs
	ArrayList<Flow> createFlows(String dirName) throws Exception
	{
		// ArrayList to hold the flows
		ArrayList<Flow> flows = new ArrayList<Flow>();
		int z = 0; // counts the number of flows present in the logs files
		int w = 0; // counts the number of log file flows mapped to the pcap files

		// There are 33 kippo log files. 
		// We go through each one chronologically.
		for(int k=33; k>=0; --k)
		{
			// Open the required file and iterate through the lines
			String counter = Integer.toString(k);
			String directoryPath = "../Project_Dataset/D1/kippo-logs/kippo.log."+counter;
			// String directoryPath = "../joint_logs";
			File logs = new File(directoryPath);
			Scanner sc = new Scanner(logs);
			int r = 0;			
			while(sc.hasNextLine())
			{
				String line = sc.nextLine();

				// System.out.println(line);

				// To check for the start of a new flow
				String checkStr = "New connection: ";
				if(line.contains(checkStr))
				{
					++z; // increment the number of flows in log files

					// Get the source and dest IP, source and dest port

					// System.out.println(z+":-");	
					int i = line.indexOf(checkStr);
					i += checkStr.length();
					int j = line.indexOf(')');
					String connection = line.substring(i, j+1);
					// System.out.println(connection);

					i = connection.indexOf(" (");
					String s = connection.substring(0, i);
					String d = connection.substring(i+2, connection.length()-1);
					// System.out.println(s+" , "+d);

					j = s.indexOf(":");
					String sourceIP = s.substring(0, j);
					String sourcePort = s.substring(j+1);
					j = d.indexOf(":");
					String destIP = d.substring(0, j);
					String destPort = d.substring(j+1);

		// 			// System.out.println("*.*.*.*.*.*.*\n"+sourceIP+" : "+sourcePort+" , "+destIP+" : "+destPort);

					// Begin iterating through pcap files
					File dir = new File(dirName);
			  		File[] directoryListing = dir.listFiles();
			  		if (directoryListing != null) 
			  		{
			    		for (File child : directoryListing) 
			    		{
			    			// Get the source and dest IP, source and dest port of pcap file
			    			int x = child.getName().indexOf("TCP_");
			    			int y = child.getName().indexOf(".pcap.txt");

			    			String values = child.getName().substring(x+4, y);
			    			String[] V = values.split("_");
			    			V[0] = V[0].replace("-", ".");
			    			V[2] = V[2].replace("-", ".");
			    			// StringBuffer SIP = new StringBuffer(V[0]);
			    			// StringBuffer SP = new StringBuffer(V[1]);
			    			String SIP = V[0];
			    			String SP = V[1];
			    			String DIP = V[2];
			    			String DP = V[3];

			    			// If there is a match
			    			if((SIP.equals(sourceIP) && SP.equals(sourcePort)) || (DIP.equals(sourceIP) && DP.equals(sourcePort)))
							{
								++w; // increment the number of matches of log file and 

								// Store all the log file lines of the flow
								
								// System.out.println("x-x-x-x-x-x-x-x-x\n"+sourceIP+" : "+sourcePort+" , "+destIP+" : "+destPort);
								ArrayList<String> loglines = new ArrayList<String>();
								while(sc.hasNextLine())
								{
									String nline = sc.nextLine();
									// System.out.println(nline);
									String check2 = "connection lost";
									if(!nline.contains(check2))
										loglines.add(nline);
									else 
										break;
								}

								// Create a new flow to store flow info and log info

								Scanner scan = new Scanner(child);
								ArrayList<Packet> data  = new ArrayList<Packet>();

								int id=0; // Packet ID 
								
								/* Converting each pcap file line into a transaction */
								while(scan.hasNextLine())
								{
									String mline = scan.nextLine();
									String[] W = mline.split(",");

									++id;
									int frame = Integer.parseInt(W[0]);
									int incoming;
									if(W[1].equals("True"))
										incoming = 1;
									else
										incoming = 0;

									String sourceIP2 = W[2];
									String destIP2 = W[3];
									String sourcePort2 = W[4];
									String destPort2 = W[5];
									String timestamp = W[6];
									int size = Integer.parseInt(W[7]);
									int trans_point = Integer.parseInt(W[8]);
									int login = Integer.parseInt(W[9]);

									Packet temp = new Packet(id, frame, incoming, sourceIP2,destIP2,sourcePort2,destPort2,timestamp,size,trans_point, login);

									data.add(temp);
								}

								flows.add(new Flow(w, data, loglines));

							}
			    		}
			    	}
		
				}
				
			}
		}
		System.out.println("No. of flows in log files: "+w);
		return flows;
			
	}

	Hashtable<String, ArrayList<Flow>> groupAllFlows(ArrayList<Flow> flows)
	{
		Hashtable<String, ArrayList<Flow>> attackerIPs = new Hashtable<String, ArrayList<Flow>>();
	
		for(Flow f : flows)
		{
			String IP = "";

			if(f.features.size()>=11 && f.features.size()<=51)
			{
				// System.out.println(f.id+" : ["+f.features.size()+"]\t("+f.features.get(0).sourceIP+"_"+f.features.get(0).sourcePort+" : "+f.features.get(0).destIP+"_"+f.features.get(0).destPort+")");
				if(f.features.get(0).destPort.equals("22"))
				{
					IP = f.features.get(0).sourceIP;
					// System.out.println(f.features.get(0).sourceIP+" , "+f.features.get(0).sourcePort);
				}
				else if(f.features.get(0).sourcePort.equals("22"))
				{
					IP = f.features.get(0).destIP;
					// System.out.println(f.features.get(0).destIP+" , "+f.features.get(0).destPort);
				}
			}
			// else
			// 	System.out.println("-------------");

			if(!attackerIPs.containsKey(IP))
			{
				ArrayList<Flow> ffs = new ArrayList<Flow>();
				ffs.add(f);
				attackerIPs.put(IP, ffs);
			}
			else
			{
				ArrayList<Flow> fl = attackerIPs.get(IP);
				fl.add(f);
				attackerIPs.replace(IP, fl);
			}
		}
		// System.out.println(attackerIPs.size());
		// System.out.println(attackerIPs.keys().getClass());
		
		return attackerIPs;
	}

	void bruteForceDetection(Hashtable<String, ArrayList<Flow>> attackerIPs)
	{
		Enumeration ips = attackerIPs.keys();
		while(ips.hasMoreElements()) 
		{
        	String str = (String) ips.nextElement();
        	ArrayList<Flow> fl = attackerIPs.get(str);
         	System.out.println(str + ": " + fl.size());
         	if(str.equals(""))
         		continue;
         	
         	Collections.sort(fl);

         	for(Flow f : fl)
         	{
         		System.out.println("\t"+f.features.size());
         	}

         	int found = 0;
         	for(int i = 0; i<fl.size(); ++i)
         	{	
         		int j;
         		for(j = i+1; j<fl.size(); ++j)
         		{
         			if(fl.get(i).features.size() != fl.get(j).features.size())
         			{
         				if(j - i >= 2)
         					found = 1;
         			
         				break;
         			}
         		}
         		if(j - i >= 2)
         			found = 1;

         		if(found == 1)
         			break;
         	}

         	if(found == 1)
         		System.out.println(" Brute Force!\n");
      	}
	}

	void compromiseDetection(ArrayList<Flow> flows)
	{
		
	}
}