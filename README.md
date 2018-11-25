Paper 2 Implementation.

Dataset

1. Log files are combined all together in the file `all_logs`, using the Python script `logsParse.py`
2. The pcap files are converted to text and stored in `/pcap2txt`, using the Python script `pcapParse.py` 

Model 

1. Compile using `javac *.java`
2. Run with `java -cp . Main ../pcap2txt`
5. The final accuracy of the algorithm is printed 

Classes

1. Main: controls execution of all steps in the algorithm
2. Training: contains a main function, and all methods part of the algorithm
3. Flow
4. Packet

3-4 are self explanatory

Checking points
- TCP idle time calculation
- Check the algorithm and all the assumptions made

