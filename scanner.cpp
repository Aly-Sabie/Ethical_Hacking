#include <iostream>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <signal.h>
using namespace std;
int main()
{
/*variable that count the occurence of the process
  for a Process id(pid) to be suspecious the count of it must be 2
  one with the allocated memory and one with it not allocating any memory
*/

int count=0;
string pid,processName,processPath;
/*variable stores the locations of malicious PIDs*/ 
int pidloc[5];
/*counter to the number of malicious programs found in the device*/
int threatCounter=0;
system("clear");
cout << "\t\t\tBEHAVIORAL BASED MALICIOUS SCANNER\t\t\t\t\n\n" << endl;
while(1)
{
cout << "Do you want to scan for any malicious program? Y\\N" << endl;
char response;
cin >> response;
if ( response == 'N')
{
cout << "\t\t\t\t\t\n\nThank you!" <<endl;
break;
}
else {
system("clear");
/*
the next code line contains three linux commands
1-top command which list the statistics of all the running processes
and it is modified to refresh every 10 secs for 6 iterations only and
list the processes run by the user not the kernel and sorted by the memory
used by the process.

2-take the output of top commands and filter it to list only the PID and the memory used by it.

3-save the filtered list in a text file to use it in further processing
*/
system("top -b -o +VIRT -d 10 -n 6|awk '{print $1,$5}'>top.txt");
cout<<"\t\t\t\n\nscanned successfully"<<endl;
cout<<"\t\t\t\n\nsearching for any suspecious behavior"<<endl;

/*the following line consists of four commands

1- sort the list saved to make the similar PIDs after each other in the list

2-count the number of occurences of each row(which contains the same PID and the same memory allocated and then leave one occurence only but add the number of occurences of it to the list.

3-search for the rows which its number of occurences was 3 times as it tells that in the 6 iteration of searching this row changes every time

4-print the PID and the Memory and save the output of the search in another text file named top1*/
system("sort top.txt|uniq -c|grep \" 3 \" |awk '{print $2,$3}'>top1.txt");


/*this variable will parse the elements of the top1.txt and save it to do computations easily*/
int parsed[5][3];
int i=0;
/*take the value from top1.txt and save it in the variable*/
ifstream infile("top1.txt");
while (infile >>parsed[i][0]>>parsed[i][1])
{
i++;
}

/*go through the array and do the computations on it*/
for(int j=0;j<i;j++)
{
for(int q=0;q<i;q++)
{
/*calculate number of occurences of the PID*/
  if(parsed[j][0]==parsed[q][0])
  count++;
}
/*save the number of occurences as an element of the array*/
parsed[j][2]=count;
count=0;
}

for(int j=0;j<i;j++)
{
/*if the number of occurences of the PID = 2 so we need to compute the difference of memory used in each occurence*/
 if(parsed[j][2]==2)
 {
 parsed[j+1][2]=7;
 parsed[j][1]=parsed[j][1]-parsed[j+1][1];
 /*if the difference is nearly 200Mb so this pid is suspicious*/
 if(parsed[j][1]>199000)
 {	
	pidloc[threatCounter]=j;
	threatCounter++;
	}
}
}

cout<<threatCounter<< " malicious program(s) \n\n";
int threatsleft=threatCounter;
for(int z=0;z<threatCounter;z++)
{
stringstream ss;
ss << parsed[pidloc[z]][0];
ss>>pid;
/*take the PID and output the name of the suspecious process*/
system(("ps -p "+pid+" -o comm= >top1.txt; cat top1.txt").c_str());
cout<<endl;
cout<<"Do you want to kill it? Y\\N "<<endl;
cin>>response;


if(response == 'Y'){
ifstream infile1("top1.txt");
while(infile1>>processName);
system(("pwdx "+pid+">top1.txt").c_str());
ifstream infile2("top1.txt");
while(infile2>>processPath);
kill(parsed[pidloc[z]][0],SIGSEGV);
threatsleft--;

cout<<"killed "<<processName<< " successfully"<<endl;
system(("chmod -rwx "+processPath+"/"+processName).c_str());
}
}
if(threatCounter!=threatsleft)
cout<<"there are "<<threatsleft<<" threats left"<<endl;
cout<<"Do you want to scan again? Y\\N"<<endl;
cin>>response;
if(response=='Y')
threatCounter=0;
else{
cout<<"\t\t\tTHANK YOU!"<<endl;
break;
}
}
}
}
