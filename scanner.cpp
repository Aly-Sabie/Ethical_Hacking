
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <signal.h>
using namespace std;
int memoryparsed[5][3]={0};
int cpuparsed[5]={0};
int i=0;
int y=0;
char response;
int threatsleft=0;
string pid[5],processName,processPath,processHash,processHashComp;
/*counter to the number of malicious programs found in the device*/
int threatCounter=0;
/*variable stores the locations of malicious PIDs and the behavior: 1 is memory and 2 is CPU*/ 
int pidloc[5][2];
void scanner()
{
/*
the next code line contains three linux commands
1-top command which list the statistics of all the running processes
and it is modified to refresh every 10 secs for 6 iterations only and
list the processes run by the user not the kernel and sorted by the memory
used by the process.

2-take the output of top commands and filter it to list only the PID and the memory used by it.

3-save the filtered list in a text file to use it in further processing
*/
	system("top -b -o +VIRT -d 10 -n 6|awk '{print $1,$5,$9}'>analysis.txt");
	cout<<"\t\t\t\n\nscanned successfully"<<endl;
	cout<<"\t\t\t\n\nsearching for any suspecious behavior"<<endl;
}

void memoryBehaviorDetector()
{
/*variable that count the occurence of the process
  for a Process id(pid) to be suspecious the count of it must be 2
  one with the allocated memory and one with it not allocating any memory
*/
	int count=0;
/*the following line consists of four commands

1- sort the list saved to make the similar PIDs after each other in the list

2-count the number of occurences of each row(which contains the same PID and the same memory allocated and then leave one occurence only but add the number of occurences of it to the list.

3-search for the rows which its number of occurences was 3 times as it tells that in the 6 iteration of searching this row changes every time

4-print the PID and the Memory and save the output of the search in another text file named top1*/
	system("awk '{print $1,$2}' analysis.txt>mem_behavior.txt");
	system("sort mem_behavior.txt|uniq -c|grep \" 3 \" |awk '{print $2,$3}'>mem_behavior_mod.txt");
	ifstream infile("mem_behavior_mod.txt");
	while (infile >>memoryparsed[i][0]>>memoryparsed[i][1])
	{
		i++;
	}
	/*go through the array and do the computations on it*/
	for(int j=0;j<i;j++)
	{
		for(int q=0;q<i;q++)
		{
/*calculate number of occurences of the PID*/
  			if(memoryparsed[j][0]==memoryparsed[q][0])
  			count++;
		}
/*save the number of occurences as an element of the array*/
		memoryparsed[j][2]=count;
		count=0;
	}
	for(int j=0;j<i;j++)
	{
		
/*if the number of occurences of the PID = 2 so we need to compute the difference of memory used in each occurence*/

 		if(memoryparsed[j][2]==2)
 		{
 			
 			if(j!=i)
 			{
 				memoryparsed[j+1][2]=7;
 				memoryparsed[j][1]=memoryparsed[j][1]-memoryparsed[j+1][1];
 			}
 /*if the difference is nearly 200Mb so this pid is suspicious*/
 			if(memoryparsed[j][1]>199000)
 			{	
				pidloc[threatCounter][0]=j;
				pidloc[threatCounter][1]=1;
				threatCounter++;
			}
		}
	}
}
void CPUBehaviorDetector()
{
	system("cat analysis.txt |awk '($3>90.0 && $3<=100) {print $3,$1}'|sort|uniq -f 1|awk '{print $2}'>CPU_behavior.txt");
	ifstream infile("CPU_behavior.txt");
	while (infile >>cpuparsed[y])
	{
		y++;
	}
	for(int j = 0;j<y;j++)
	if(cpuparsed[j]!=0)
	{
		
		pidloc[threatCounter][0]=j;
		pidloc[threatCounter][1]=2;
		threatCounter++;
	}
}
void whiteListCheck()
{
	threatsleft=threatCounter;
	for(int z=0;z<threatCounter;z++)
	{
		stringstream ss;
		if(pidloc[z][1]==1)
		{
			ss << memoryparsed[pidloc[z][0]][0];
			ss>>pid[z];
		}
		else if(pidloc[z][1]==2)
		{
			ss << cpuparsed[pidloc[z][0]];
			ss>>pid[z];
		}
		/*take the PID and output the name of the suspecious process*/	
		system(("ps -p "+pid[z]+" -o comm= >top1.txt").c_str());
ifstream infile("top1.txt");
//cin>>response;
		while(infile>>processName);
		system(("pwdx "+pid[z]+">top1.txt").c_str());
		ifstream infile1("top1.txt");
		while(infile1>>processPath);
		system(("sha256sum "+processPath+"/"+processName+" >hash.txt").c_str());
		ifstream infile3("hash.txt");
		while(infile3>>processHash);
		ifstream infile4("whitelist.txt");
		while(infile4>>processHashComp)
		{
			if(processHashComp==processHash && processHash!=" ")
			{
				
				if(pidloc[z][1]==1)
					memoryparsed[pidloc[z][0]][0]=-1;
				else if(pidloc[z][1]==2)
					cpuparsed[pidloc[z][0]]=-1;
				
				threatsleft--;
			}
		}

	}
}
void processKill()
{
	for(int z=0;z<threatCounter;z++)
	{
		stringstream ss;
		if((pidloc[z][1]==1)&&(memoryparsed[pidloc[z][0]][0]!=-1))
		{
			ss << memoryparsed[pidloc[z][0]][0];
			ss>>pid[z];
		}
		else if((pidloc[z][1]==2)&&(cpuparsed[pidloc[z][0]]!=-1))
		{
			ss << cpuparsed[pidloc[z][0]];
			ss>>pid[z];
		}
		else
		continue;
/*take the PID and output the name of the suspecious process*/

		system(("ps -p "+pid[z]+" -o comm= >top1.txt; cat top1.txt").c_str());
		cout<<endl;
		cout<<"Do you want to kill it? Y\\N "<<endl;
		cin>>response;
		ifstream infile("top1.txt");
		while(infile>>processName);

		system(("pwdx "+pid[z]+">top1.txt").c_str());
		ifstream infile1("top1.txt");
		while(infile1>>processPath);

		if(response == 'Y')
		{
			if(pidloc[z][1]==1)
				kill(memoryparsed[pidloc[z][0]][0],SIGSEGV);
			else if(pidloc[z][1]==2)
				kill(cpuparsed[pidloc[z][0]],SIGSEGV);
			threatsleft--;
			cout<<"killed "<<processName<< " successfully"<<endl;
			system(("chmod -rwx "+processPath+"/"+processName).c_str());
		}
		else if(response == 'N')
		{
			threatsleft--;
			system(("sha256sum "+processPath+"/"+processName+" >>whitelist.txt").c_str());
			
		}
	}


}

int main()
{

	system("clear");
	cout << "\t\t\tBEHAVIORAL BASED MALICIOUS SCANNER\t\t\t\t\n\n" << endl;
	while(1)
	{
		cout << "Do you want to scan for any malicious program? Y\\N" << endl;
	
		cin >> response;
		if ( response == 'N')
		{
			cout << "\t\t\t\t\t\n\nThank you!" <<endl;
			break;
		}
		else 
		{
			system("clear");
			scanner();
			memoryBehaviorDetector();
			CPUBehaviorDetector();
			
			whiteListCheck();
			cout<<threatsleft<< " malicious program(s) \n\n";
			
			processKill();
		}


		if(threatCounter!=threatsleft)
			cout<<"there are "<<threatsleft<<" threats left"<<endl;
		cout<<"Do you want to scan again? Y\\N"<<endl;
		cin>>response;
		if(response=='Y')
		{
			threatCounter=0;
			threatsleft=0;
			i=0;
			y=0;
		}	
		else
		{
			cout<<"\t\t\tTHANK YOU!"<<endl;
			break;
		}
	}
}
