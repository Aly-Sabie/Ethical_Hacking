#include <iostream>
#include <unistd.h>
using namespace std;
int main()
{
int* x;
while(1)
{
x=new int[52428800];
if(x==NULL)
cout<<"failed to allocate memory"<<endl;
else
cout<<"memory is allocated successfully"<<endl;
sleep(10);
delete[] x;
cout<<"Memory is deallocated"<<endl;
x=0;
sleep(10);

}
}
