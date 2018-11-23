#include <stdio.h>

void vuln(void)
{
	// Declare the buffer
        char vulnBuf[100];

        // Print the address of the buffer
        printf("%p\n", &vulnBuf);

        // Here is the vulnerabillity
        // It allows us to scan in as much data as
        // we want into the 100 byte vulnBuf buffer
        gets(vulnBuf);

        return;
}

int main(void)
{
	// Call the vulnerable function
        vuln();
}
