#include <stdio.h>
#include <string.h>


int main(){

	FILE* fp = fopen("decFile.txt","r");
	FILE* fp1 = fopen("orgFile.txt","r");

	char buffer[1024] = { 0x00, };
	char buffer1[1024] = { 0x00, };

	int check = 100;
	int len = 0;
	int len1 = 0;

	len = fread(buffer, 1, 1024, fp);
	len1= fread(buffer1, 1, 1024, fp1);

	check = strcmp(buffer,buffer1);


	printf("%d\n", check);
	printf("%d\n", len);
	printf("%d\n", len1);


	fclose(fp);
	fclose(fp1);

	return 0;




}
