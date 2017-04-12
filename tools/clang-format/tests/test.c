/*
This is used to check if includes are sorted or not
*/
#include<unistd.h>
#include<stdio.h>
#define true 1

struct sample{
	int a;
};

/*
This is used to check support for small function in a line
*/
int a(int x, int y)
{}

int main()
{
	//This will test indentation

if(true)
{
if(true)
{
printf("this should be indented\n");
if(true)
{
printf("this should be indented too\n");
			}
}
}

/*
This will check whitespaces format
*/

if((1&2)==42)
printf("dfadsf\n" );

/*
This will test that whitespaces are not added for . and -> and the left position of *
*/
 struct sample ob;
 struct sample* ob1;
ob.a = 10;
ob1->a =10;
	int x;
	int y;
	char *p;

/*
This will break the line. It also checks addition of spaces in binary operators
*/
	if (1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2 && 1>2)
	p = "adsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	printf("addddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddadad");

	for(;;)
		{
		int z = 5;
break;
}
/*
Check for template break in template
*/
template <class P>	void updateMenuList(P*, struct menu*);
	return 0;
}