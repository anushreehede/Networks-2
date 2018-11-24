import java.util.*;
import java.io.*;
import java.lang.*; 
import java.text.SimpleDateFormat;

class Training
{
	// threshold values used in the functions
	int packet_thresh = 3;
	float time_thresh = 42500;
	
	// pre defined value
	float login_grace_time = 120000;
	
	// Method to get flow information from the logs
	static ArrayList<Flow> createFlows(String dirName) throws Exception
	{
		// ArrayList to hold the flows
		ArrayList<Flow> flows = new ArrayList<Flow>();
		int session_id = -1; // counts the number of flows present in the logs files
		int w = 0; // counts the number of log file flows mapped to the pcap files
		
		// Object to store all the lines in the log file for easier iteration
		ArrayList<String> log_file = new ArrayList<String>();

		// File containing all the kippo logs information
		String directoryPath = "../all_logs";
		File logs = new File(directoryPath);
		Scanner sc = new Scanner(logs);

		// store all the lines in an arraylist object
		while(sc.hasNextLine())
		{
			log_file.add(sc.nextLine());
		}

		// System.out.println(log_file.size());
		
		// iterate over each line of the log file 
		for(int k=0; k< log_file.size(); ++k)
		{
			String line = log_file.get(k);
			// System.out.println(line);

			// To check for the start of a new flow
			String checkStr = "New connection: ";
			if(line.contains(checkStr))
			{
				++session_id; // increment the number of flows in log files

				// Get the source and dest IP, source and dest port

				// System.out.println(session_id+":-");	
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

				// System.out.println("*.*.*.*.*.*.*\n"+sourceIP+" : "+sourcePort+" , "+destIP+" : "+destPort);

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

		    			// If there is a match between flow found in log file and pcap file
		    			if((SIP.equals(sourceIP) && SP.equals(sourcePort)) || (DIP.equals(sourceIP) && DP.equals(sourcePort)))
						{
							++w; // increment the number of matches of log file and 
							System.out.print(w+" ");
							// System.out.println("x-x-x-x-x-x-x-x-x\n"+sourceIP+" : "+sourcePort+" , "+destIP+" : "+destPort);
							
							// Store all the log file lines of the flow
							ArrayList<String> loglines = new ArrayList<String>();
							loglines.add(line); // add the current line
							int m = k+1; // go to the next line in the file
							String check2 = "connection lost";
							while(m<log_file.size())
							{
								String nline = log_file.get(m);
								// System.out.println(nline);

								// if the current line belongs to the current flow (using the session_id)
								if(nline.contains("HoneyPotTransport,"+Integer.toString(session_id)))
								{
									// if the current line is not the end of the flow
									if(!log_file.get(m).contains(check2))
										loglines.add(nline);
									else
									{
										loglines.add(nline);
										break;
									}
								}

								++m;
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

		System.out.println("\nNo. of flows in log files: "+w);
		return flows;
			
	}

	// Method to group flows according to source IP address
	Hashtable<String, ArrayList<Flow>> groupAllFlows(ArrayList<Flow> flows)
	{
		// store the groups of flows from same IP 
		Hashtable<String, ArrayList<Flow>> attackerIPs = new Hashtable<String, ArrayList<Flow>>();
		
		// iterate through flows
		for(Flow f : flows)
		{
			String IP = "";

			// check if the PPF of the flow is in the range for brute force attack
			if(f.features.size()>=11 && f.features.size()<=51)
			{
				// Get the IP of attacker 

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

			// if the hashtable doeesn't contain the found IP
			if(!attackerIPs.containsKey(IP))
			{
				// create a new list of flows and add the IP and the new list to the table
				ArrayList<Flow> ffs = new ArrayList<Flow>();
				ffs.add(f);
				attackerIPs.put(IP, ffs);
			}
			else
			{
				// find the list corresponding to the IP and add the flow to it
				ArrayList<Flow> fl = attackerIPs.get(IP);
				fl.add(f);
				attackerIPs.replace(IP, fl);
			}
		}
		// System.out.println(attackerIPs.size());
		// System.out.println(attackerIPs.keys().getClass());
		
		return attackerIPs;
	}

	// Method to detect a brute force attack
	ArrayList<String> bruteForceDetection(Hashtable<String, ArrayList<Flow>> attackerIPs)
	{
		// list to store the IPs which generate brute force attacks
		ArrayList<String> brute_force = new ArrayList<String>();

		// iterate through the table of IPs
		Enumeration ips = attackerIPs.keys();
		while(ips.hasMoreElements()) 
		{
        	String str = (String) ips.nextElement();
        	ArrayList<Flow> fl = attackerIPs.get(str);
         	// System.out.println(str + ": " + fl.size());
         	if(str.equals(""))
         		continue;
         	
         	// sort the list of flows by an attacker according to timestamp
         	Collections.sort(fl);

         	// for(Flow f : fl)
         	// {
         	// 	System.out.println("\t"+f.features.size());
         	// }

         	// if a pair of 2 or more consecutive flows have same number of PPF
         	// then brute force attack is found
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
         	{
         		System.out.println(" Brute Force!\n");
         		brute_force.add(str);
         	}
      	}
      	return brute_force;
	}

	// Method to find the number of encrypted packets sent to server after logins 
	int encryptedPackets(Flow f)
	{
		int total_logins = 0;
		for(String line: f.logs)
		{
			if(line.contains("login attempt"))
			{
				++total_logins;
			}
		}
		int encrypted = 0;
		for(Packet p: f.features)
		{
			if(p.login == 1)
				++encrypted;
		}

		int encr_data = encrypted-total_logins;

		return encr_data;
	}

	// Method to get the time difference between two packets
	long getTimeDifference(Packet p1, Packet p2)
	{
		long t1 = 0, t2 = 0;
		try 
		{
		    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
		    Date parsedDate1 = dateFormat.parse(p1.timestamp);
		    t1 = parsedDate1.getTime();
		    Date parsedDate2 = dateFormat.parse(p2.timestamp);
		    t2 = parsedDate2.getTime();

		} catch(Exception e) { //this generic but you can control another types of exception
		    // look the origin of excption 
		    System.out.println(e);
		}
		long diff = t2-t1;

		return diff;
	}

	// Method to get the time difference between compromise and end of flow connection
	long timeTillClose(Flow f, String line)
	{
		int x = line.indexOf("+");
		String timestamp = line.substring(0, x); 
		String end_line = f.logs.get(f.logs.size()-1);
		int y = end_line.indexOf("+");
		String end_timestamp = end_line.substring(0, y); 

		long ts=0, end_ts=0;
		try
		{
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
			Date parsedDate1 = dateFormat.parse(timestamp);
			ts = parsedDate1.getTime() + 330*60*1000;
			Date parsedDate2 = dateFormat.parse(end_timestamp);
			end_ts = parsedDate2.getTime() + 330*60*1000;
		}catch(Exception e) { //this generic but you can control another types of exception
		    // look the origin of excption 
		    System.out.println(e);
		}

		long close_time = end_ts-ts;

		return close_time;
	}

	// Method to
	float idleTime(Flow f)
	{
		//
		return 0;
	}

	// Method to label a flow with the ground truth
	void labelFlow(Flow f)
	{
		int total_logins = 0;
		for(String line: f.logs)
		{
			if(line.contains("login attempt"))
			{
				++total_logins;
			}
		}
		if(total_logins>=6 )//&& idleTime > 60)
		{
			f.actual = "Compromise";
		}
		else
		{
			f.actual = "Not Compromise";
		}
	}

	// Method to detect a compromise
	void compromiseDetection(Hashtable<String, ArrayList<Flow>> attackerIPs, ArrayList<String> brute_force)
	{
		// int pack = 0;
		// int total = 0;
		// float time = 0;
		// int tt = 0;

		// iterate through the attacker IPs
		Enumeration ips = attackerIPs.keys();
		while(ips.hasMoreElements()) 
		{
			String str = (String) ips.nextElement();

			// if the attacker is not conducting a brute force attack, let it be
			if(!brute_force.contains(str))
				continue;

        	ArrayList<Flow> flows = attackerIPs.get(str);
        	
        	// iterate through each flow
        	for(int i=0; i<flows.size(); ++i)
        	{
        		Flow f = flows.get(i);
        		int g = 0; // flag 

        		// iterate through the log file of the flow
        		for(String line : f.logs)
        		{
        			// if a successful auth has taken place
        			if(line.contains("root authenticated with password"))
        			{
        				// pack += encryptedPackets(f);
        				// total++;

        				// if the number of encrypted packets sent after auth
        				// is greater than a threshold, connection is maintained 
        				if(encryptedPackets(f) > packet_thresh)
        				{
        					// if the time taken to close the connection is
        					// greater than the login_grace_time, then target is
        					// not compromised
        					if(timeTillClose(f, line) > login_grace_time)
        					{
        						System.out.println("Not Compromise");
        						f.label = "Not Compromise";
        						g = 1;
        						break;
        					}

        					// else check if attacker makes any other attacks
        					else
        					{
        						// if end of the list, then attacker aborts dictionary 
        						if(i+1 == flows.size())
        						{
        							System.out.println("Maintain connection, abort dictionary");
        							f.label = "Compromise";
        						}
        						else
        						{
        							// get the next attack from the IP
        							Flow f1 = flows.get(i+1);

        							// get the time difference between the two consecutive flows 
        							float t = getTimeDifference(f.features.get(f.features.size()-1), f1.features.get(0));
        							// time += t;
        							// tt++;

        							// if the time difference is greater than a threshold, then attacker aborts dictionary
        							if(t > time_thresh)
        							{
        								System.out.println("Maintain connection, abort dictionary");
        								f.label = "Compromise";
        							}
        							// else he continues dictionary
        							else
        							{
        								System.out.println("Maintain connection, continue dictionary");
        								f.label = "Compromise";
        							}	
        						}
        					}
        				}

        				// the attacker instantly logs out after compromise
        				else
        				{
        					// check if attacker makes any other attacks
        					if(i+1 == flows.size())
    						{
    							System.out.println("Instant logout, abort dictionary");
    							f.label = "Compromise";
    						}
    						else
    						{
    							// get the next attack from the IP
    							Flow f1 = flows.get(i+1);

    							// get the time difference between the two consecutive flows 
    							float t = getTimeDifference(f.features.get(f.features.size()-1), f1.features.get(0));
    							// time += t;
        			 			// tt++;

        			 			// if the time difference is greater than a threshold, then attacker aborts dictionary
    							if(t > time_thresh)
    							{
    								System.out.println("Instant logout, abort dictionary");
    								f.label = "Compromise";
    							}

    							// else he continues dictionary
    							else
    							{
    								System.out.println("Instant logout, continue dictionary");
    								f.label = "Compromise";
    							}
    						} 

        				}
        			}

        			else
        				f.label = "Not Compromise";
        		}

        		// provide actual labels to the flow
        		labelFlow(f);

        		// flag conditions
        		if(g == 1)
        		{
        			continue;
        		}
        	}
		}

		// float w = (float)pack/total;
		// float v = time/tt;
		// System.out.println("Avg packets: "+w+" Avg time: "+v);
	}

	// Method to calculate accuracy of labelling predictions
	void calcAccuracy(Hashtable<String, ArrayList<Flow>> attackerIPs, ArrayList<String> brute_force)
	{
		int correct = 0;
		int total = 0;
		Enumeration ips = attackerIPs.keys();
		while(ips.hasMoreElements()) 
		{
			String str = (String) ips.nextElement();

			if(!brute_force.contains(str))
				continue;

        	ArrayList<Flow> flows = attackerIPs.get(str);
        	total += flows.size();

        	for(Flow f : flows)
        	{
        		if(f.label.equals(f.actual))
        		{
        			++correct;
        		}
        	}
        }

    	float accuracy = (float)correct/total*100;

    	System.out.println("Accuracy: "+accuracy+"%");
	}

}