#include<stdio.h>       //printf
#include<string.h>      //strlen
#include<sys/socket.h>  //socket
#include<arpa/inet.h>   //inet_addr
#include<string.h>
#include<sys/ioctl.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<stdio.h>
#include<net/if_arp.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>      //strlen
#include<sys/socket.h>
#include<arpa/inet.h>   //inet_addr
#include<unistd.h>      //write
#define PORT 20000 
#define BACKLOG 5
#define LENGTH 128 
#include <glob.h>
#include<time.h>
#include<sys/fcntl.h>

typedef unsigned long int UINT4;
typedef struct {

	UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */

	UINT4 buf[4];                                    /* scratch buffer */

	unsigned char in[64];                              /* input buffer */

	unsigned char digest[16];     /* actual digest after MD5Final call */

} MD5_CTX;
void MD5Init ();
void MD5Update ();
void MD5Final ();
static void Transform ();
static unsigned char PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define FF(a, b, c, d, x, s, ac) \
{(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	      (a) += (b); \
}

#define GG(a, b, c, d, x, s, ac) \
{(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	      (a) += (b); \
}

#define HH(a, b, c, d, x, s, ac) \
{(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	      (a) += (b); \
}

#define II(a, b, c, d, x, s, ac) \
{(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	      (a) += (b); \
}
void MD5Init (mdContext)
	MD5_CTX *mdContext;
{
	mdContext->i[0] = mdContext->i[1] = (UINT4)0;
	mdContext->buf[0] = (UINT4)0x67452301;
	mdContext->buf[1] = (UINT4)0xefcdab89;
	mdContext->buf[2] = (UINT4)0x98badcfe;
	mdContext->buf[3] = (UINT4)0x10325476;
}
void MD5Update (mdContext, inBuf, inLen)
	MD5_CTX *mdContext;
	unsigned char *inBuf;
	unsigned int inLen;
{
	UINT4 in[16];
	int mdi;
	unsigned int i, ii;
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);
	if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
		mdContext->i[1]++;
	mdContext->i[0] += ((UINT4)inLen << 3);
	mdContext->i[1] += ((UINT4)inLen >> 29);
	while (inLen--) {
		mdContext->in[mdi++] = *inBuf++;
		if (mdi == 0x40) {
			for (i = 0, ii = 0; i < 16; i++, ii += 4)
				in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
					(((UINT4)mdContext->in[ii+2]) << 16) |
					(((UINT4)mdContext->in[ii+1]) << 8) |
					((UINT4)mdContext->in[ii]);
			Transform (mdContext->buf, in);
			mdi = 0;
		}
	}
}
void MD5Final (mdContext)
	MD5_CTX *mdContext;
{
	UINT4 in[16];
	int mdi;
	unsigned int i, ii;
	unsigned int padLen;
	/* save number of bits */
	in[14] = mdContext->i[0];
	in[15] = mdContext->i[1];
	/* compute number of bytes mod 64 */
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);
	/* pad out to 56 mod 64 */
	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
	MD5Update (mdContext, PADDING, padLen);
	/* append length in bits and transform */
	for (i = 0, ii = 0; i < 14; i++, ii += 4)
		in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
			(((UINT4)mdContext->in[ii+2]) << 16) |
			(((UINT4)mdContext->in[ii+1]) << 8) |
			((UINT4)mdContext->in[ii]);
	Transform (mdContext->buf, in);
	/* store buffer in digest */
	for (i = 0, ii = 0; i < 4; i++, ii += 4) {
		mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
		mdContext->digest[ii+1] =
			(unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
		mdContext->digest[ii+2] =
			(unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
		mdContext->digest[ii+3] =
			(unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
	}
}
static void Transform (buf, in)
	UINT4 *buf;
	UINT4 *in;
{
	UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];
#define S11 7
#define S12 12
#define S13 17
#define S14 22

	FF ( a, b, c, d, in[ 0], S11, 3614090360); /* 1 */

	FF ( d, a, b, c, in[ 1], S12, 3905402710); /* 2 */

	FF ( c, d, a, b, in[ 2], S13,  606105819); /* 3 */

	FF ( b, c, d, a, in[ 3], S14, 3250441966); /* 4 */

	FF ( a, b, c, d, in[ 4], S11, 4118548399); /* 5 */

	FF ( d, a, b, c, in[ 5], S12, 1200080426); /* 6 */

	FF ( c, d, a, b, in[ 6], S13, 2821735955); /* 7 */

	FF ( b, c, d, a, in[ 7], S14, 4249261313); /* 8 */

	FF ( a, b, c, d, in[ 8], S11, 1770035416); /* 9 */

	FF ( d, a, b, c, in[ 9], S12, 2336552879); /* 10 */

	FF ( c, d, a, b, in[10], S13, 4294925233); /* 11 */

	FF ( b, c, d, a, in[11], S14, 2304563134); /* 12 */

	FF ( a, b, c, d, in[12], S11, 1804603682); /* 13 */

	FF ( d, a, b, c, in[13], S12, 4254626195); /* 14 */

	FF ( c, d, a, b, in[14], S13, 2792965006); /* 15 */

	FF ( b, c, d, a, in[15], S14, 1236535329); /* 16 */



	/* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20

	GG ( a, b, c, d, in[ 1], S21, 4129170786); /* 17 */

	GG ( d, a, b, c, in[ 6], S22, 3225465664); /* 18 */

	GG ( c, d, a, b, in[11], S23,  643717713); /* 19 */

	GG ( b, c, d, a, in[ 0], S24, 3921069994); /* 20 */

	GG ( a, b, c, d, in[ 5], S21, 3593408605); /* 21 */

	GG ( d, a, b, c, in[10], S22,   38016083); /* 22 */

	GG ( c, d, a, b, in[15], S23, 3634488961); /* 23 */

	GG ( b, c, d, a, in[ 4], S24, 3889429448); /* 24 */

	GG ( a, b, c, d, in[ 9], S21,  568446438); /* 25 */

	GG ( d, a, b, c, in[14], S22, 3275163606); /* 26 */

	GG ( c, d, a, b, in[ 3], S23, 4107603335); /* 27 */

	GG ( b, c, d, a, in[ 8], S24, 1163531501); /* 28 */

	GG ( a, b, c, d, in[13], S21, 2850285829); /* 29 */

	GG ( d, a, b, c, in[ 2], S22, 4243563512); /* 30 */

	GG ( c, d, a, b, in[ 7], S23, 1735328473); /* 31 */

	GG ( b, c, d, a, in[12], S24, 2368359562); /* 32 */



	/* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23

	HH ( a, b, c, d, in[ 5], S31, 4294588738); /* 33 */

	HH ( d, a, b, c, in[ 8], S32, 2272392833); /* 34 */

	HH ( c, d, a, b, in[11], S33, 1839030562); /* 35 */

	HH ( b, c, d, a, in[14], S34, 4259657740); /* 36 */

	HH ( a, b, c, d, in[ 1], S31, 2763975236); /* 37 */

	HH ( d, a, b, c, in[ 4], S32, 1272893353); /* 38 */

	HH ( c, d, a, b, in[ 7], S33, 4139469664); /* 39 */

	HH ( b, c, d, a, in[10], S34, 3200236656); /* 40 */

	HH ( a, b, c, d, in[13], S31,  681279174); /* 41 */

	HH ( d, a, b, c, in[ 0], S32, 3936430074); /* 42 */

	HH ( c, d, a, b, in[ 3], S33, 3572445317); /* 43 */

	HH ( b, c, d, a, in[ 6], S34,   76029189); /* 44 */

	HH ( a, b, c, d, in[ 9], S31, 3654602809); /* 45 */

	HH ( d, a, b, c, in[12], S32, 3873151461); /* 46 */

	HH ( c, d, a, b, in[15], S33,  530742520); /* 47 */

	HH ( b, c, d, a, in[ 2], S34, 3299628645); /* 48 */



	/* Round 4 */

#define S41 6

#define S42 10

#define S43 15

#define S44 21

	II ( a, b, c, d, in[ 0], S41, 4096336452); /* 49 */

	II ( d, a, b, c, in[ 7], S42, 1126891415); /* 50 */

	II ( c, d, a, b, in[14], S43, 2878612391); /* 51 */

	II ( b, c, d, a, in[ 5], S44, 4237533241); /* 52 */

	II ( a, b, c, d, in[12], S41, 1700485571); /* 53 */

	II ( d, a, b, c, in[ 3], S42, 2399980690); /* 54 */

	II ( c, d, a, b, in[10], S43, 4293915773); /* 55 */

	II ( b, c, d, a, in[ 1], S44, 2240044497); /* 56 */

	II ( a, b, c, d, in[ 8], S41, 1873313359); /* 57 */

	II ( d, a, b, c, in[15], S42, 4264355552); /* 58 */

	II ( c, d, a, b, in[ 6], S43, 2734768916); /* 59 */

	II ( b, c, d, a, in[13], S44, 1309151649); /* 60 */

	II ( a, b, c, d, in[ 4], S41, 4149444226); /* 61 */

	II ( d, a, b, c, in[11], S42, 3174756917); /* 62 */

	II ( c, d, a, b, in[ 2], S43,  718787259); /* 63 */

	II ( b, c, d, a, in[ 9], S44, 3951481745); /* 64 */



	buf[0] += a;

	buf[1] += b;

	buf[2] += c;

	buf[3] += d;

}
static void MDPrint (mdContext)
	MD5_CTX *mdContext;
{
	int i;
	for (i = 0; i < 16; i++)
		printf ("%02x", mdContext->digest[i]);
}
#define TEST_BLOCK_SIZE 1000
#define TEST_BLOCKS 10000
static long TEST_BYTES = (long)TEST_BLOCK_SIZE * (long)TEST_BLOCKS;
static void MDTimeTrial ()
{
	MD5_CTX mdContext;
	time_t endTime, startTime;
	unsigned char data[TEST_BLOCK_SIZE];
	unsigned int i;
	for (i = 0; i < TEST_BLOCK_SIZE; i++)
		data[i] = (unsigned char)(i & 0xFF);
	printf ("MD5 time trial. Processing %ld characters...\n", TEST_BYTES);
	time (&startTime);
	MD5Init (&mdContext);
	for (i = TEST_BLOCKS; i > 0; i--)
		MD5Update (&mdContext, data, TEST_BLOCK_SIZE);
	MD5Final (&mdContext);
	time (&endTime);
	MDPrint (&mdContext);
	printf (" is digest of test input.\n");
	printf
		("Seconds to process test input: %ld\n", (long)(endTime-startTime));
	printf
		("Characters processed per second: %ld\n",
		 TEST_BYTES/(endTime-startTime));
}
static void MDString (inString)

	char *inString;

{
	MD5_CTX mdContext;
	unsigned int len = strlen (inString);
	MD5Init (&mdContext);
	MD5Update (&mdContext, inString, len);
	MD5Final (&mdContext);
	MDPrint (&mdContext);
	printf (" \"%s\"\n\n", inString);
}
static void MDFile (filename)
	char *filename;
{
	FILE *inFile = fopen (filename, "rb");
	MD5_CTX mdContext;
	int bytes;
	unsigned char data[1024];
	if (inFile == NULL) {
		printf ("%s can't be opened.\n", filename);
		return;
	}
	MD5Init (&mdContext);
	while ((bytes = fread (data, 1, 1024, inFile)) != 0)
		MD5Update (&mdContext, data, bytes);
	MD5Final (&mdContext);
	MDPrint (&mdContext);
	printf (" %s\n", filename);
	fclose (inFile);
}
static void MDFilter ()
{
	MD5_CTX mdContext;
	int bytes;
	unsigned char data[16];
	MD5Init (&mdContext);
	while ((bytes = fread (data, 1, 16, stdin)) != 0)
		MD5Update (&mdContext, data, bytes);
	MD5Final (&mdContext);
	MDPrint (&mdContext);
	printf ("\n");
}
static void MDTestSuite ()
{
	printf ("MD5 test suite results:\n\n");
	MDString ("");
	MDString ("a");
	MDString ("abc");
	MDString ("message digest");
	MDString ("abcdefghijklmnopqrstuvwxyz");
	MDString
		("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	MDString
		("1234567890123456789012345678901234567890\
		 1234567890123456789012345678901234567890");
	MDFile ("foo");
}
void Upload(int client_sock,char * st1)
{
	char revbuf[LENGTH];
	//char fr_name[200] = "/home/kriti/work/tempp/t2/";
	char fr_name[200] = "./";
	char nn[100];
	strcpy(nn,st1);
	strcat(fr_name,st1);
	//strcpy(fr_name,charr[1]);
	bzero(revbuf,LENGTH);
	puts("Client wants to upload file..Answer yes(1) or no(0):");
	while(strlen(revbuf)<=0)
	{    
		gets(revbuf);
	}    
	if(strcmp(revbuf,"0")==0)
	{    
		bzero(revbuf,LENGTH);
		strcpy(revbuf,"Deny");
		write(client_sock, revbuf, LENGTH);
		//continue;
	}    
	else 
	{	bzero(revbuf,LENGTH);
		strcpy(revbuf,"Yes");
		write(client_sock, revbuf, LENGTH);
		FILE *fr = fopen(fr_name, "w");
		if(fr == NULL)
			printf("File %s Cannot be opened.\n", fr_name);
		else
		{
			bzero(revbuf, LENGTH); 
			while(strlen(revbuf)<=0)
			{
				read(client_sock,revbuf,LENGTH);
			}

			//printf("SIZZZ %s\n",revbuf);
			int siz=atoi(revbuf);
			//printf("SIZZZ %d\n",siz);

			int fr_block_sz = 0;
			//while(read(client_sock, revbuf, 1000)<0)
			//{
			bzero(revbuf, LENGTH); 
			while(1)
			{
				while(strlen(revbuf)<=0)
				{
					read(client_sock,revbuf,1);
				}
				printf("revbuf siz-%d   data-%s\n",siz,revbuf);
				fwrite(revbuf, sizeof(char), 1, fr);
				bzero(revbuf, 1);
				siz-=1;
				if(siz<=0)
					break;
			}
			read(client_sock,revbuf,100);
			printf("revbuf siz-%d   data-%s\n",siz,revbuf);

			fclose(fr);
		}
	}
}
int FileSize(char * ss);
char * LastModified(char * ss);
void Download(int client_sock,char * st1)
{
	//printf("Endjkjhev\n");
	//char fs_name[20] ;
	//char fs_name[200] = "/home/kriti/work/tempp/t2/";
	char fs_name[200] = "./";
	strcat(fs_name,st1);
	//scanf("%s" , fs_name);
	//char* fs_name = "/home/aryan/Desktop/quotidiani.txt";
	//strcpy(fs_name,st1);
	char sdbuf[2*LENGTH];
	int nn1=FileSize(fs_name);	
	//printf("[Client] Sending %s to the Server... ", fs_name);
	FILE *fs = fopen(fs_name, "r");
	if(fs == NULL)
	{
		printf("ERROR: File %s not found.\n", fs_name);
		exit(1);
	}
	bzero(sdbuf, 2*LENGTH); 
	//int fs_block_sz;//,errno=0; 
	sprintf(sdbuf,"%d",nn1);
	write(client_sock, sdbuf, 2*LENGTH);
	//printf("SIZ %s\n",sdbuf);
	bzero(sdbuf, 2*LENGTH);
	int fs_block_sz=0;	
	while((fs_block_sz = fread(sdbuf, sizeof(char),2*LENGTH, fs)) > 0)
	{
		//printf("SENDING  %s\n",sdbuf);
		if(write(client_sock, sdbuf, 2*LENGTH) <= 0)
		{
			//fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs_name, errno);

			break;
		}

		//sdbuf[0]='\0';
		//printf("SENDING file:   %s\n",sdbuf);
		bzero(sdbuf, 2*LENGTH);
	}
	fclose(fs);

	bzero(sdbuf, 2*LENGTH);
	char ss1[100],ss2[100];
	strcpy(ss1,"md5sum ");
	strcpy(ss2," > aa.txt");
	strcat(ss1,fs_name);
	strcat(ss1,ss2);
	system(ss1);
	FILE *fs1 = fopen("aa.txt", "r");
	char ff5[100];
	bzero(ff5,100);
	fread(ff5, sizeof(char), 100, fs1); 
	fclose(fs1);
	strcpy(sdbuf,ff5);
	strcat(sdbuf," ");
	strcat(sdbuf,LastModified(fs_name));
	char nn2[100];
	sprintf(nn2,"%d",nn1);
	strcat(sdbuf,nn2);
   	strcat(sdbuf,"\n");

	write(client_sock, sdbuf, 2*LENGTH);

	printf("Ok File %s from Client was Sent!\n", fs_name);
}
int Month(char * s)
{
	if(strcmp("Jan",s)==0)
		return 1;
	else if(strcmp("Feb",s)==0)
		return 2;
	else if(strcmp("Mar",s)==0)
		return 3;
	else if(strcmp("Apr",s)==0)
		return 4;
	else if(strcmp("May",s)==0)
		return 5;
	else if(strcmp("Jun",s)==0)
		return 6;
	else if(strcmp("Jul",s)==0)
		return 7;
	else if(strcmp("Aug",s)==0)
		return 8;
	else if(strcmp("Sep",s)==0)
		return 9;
	else if(strcmp("Oct",s)==0)
		return 10;
	else if(strcmp("Nov",s)==0)
		return 11;
	else if(strcmp("Dec",s)==0)
		return 12;
}
int CompareTime(char ** charr,char * t)
{
	char *ch1;
	int chcount=0;
	char *charr2[1000];

	ch1 = strtok(t," ");
	while(ch1 != NULL)
	{
		charr2[chcount]=ch1;
		chcount++;
		ch1 = strtok(NULL, " ");
	}


	char *ch3;
	chcount=0;
	char *charr3[1000];

	ch3 = strtok(charr[5],":");
	while(ch3 != NULL)
	{
		charr3[chcount]=ch3;
		chcount++;
		ch3 = strtok(NULL, ":");
	}
	char *ch4;
	chcount=0;
	char *charr4[1000];

	ch4 = strtok(charr[10],":");
	while(ch4 != NULL)
	{
		charr4[chcount]=ch4;
		chcount++;
		ch4 = strtok(NULL, ":");
	}

	char *ch5;
	chcount=0;
	char *charr5[1000];

	ch5 = strtok(charr2[3],":");
	while(ch5 != NULL)
	{
		charr5[chcount]=ch5;
		chcount++;
		ch5 = strtok(NULL, ":");
	}



	struct tm time_str1;
	struct tm time_str2;
	struct tm time_str3;
	time_str1.tm_year = atoi(charr[6]);
	time_str1.tm_mon = Month(charr[3])-1;
	time_str1.tm_mday = atoi(charr[4]);
	time_str1.tm_hour = atoi(charr3[0]);
	time_str1.tm_min = atoi(charr3[1]);
	time_str1.tm_sec = atoi(charr3[2]);
	time_str1.tm_isdst = -1;

	time_str2.tm_year = atoi(charr[11]);
	time_str2.tm_mon = Month(charr[8])-1;
	time_str2.tm_mday = atoi(charr[9]);
	time_str2.tm_hour = atoi(charr4[0]);
	time_str2.tm_min = atoi(charr4[1]);
	time_str2.tm_sec = atoi(charr4[2]);
	time_str2.tm_isdst = -1;
		
	
	time_str3.tm_year = atoi(charr2[4]);
	time_str3.tm_mon = Month(charr2[1])-1;
	time_str3.tm_mday = atoi(charr2[2]);
	time_str3.tm_hour = atoi(charr5[0]);
	time_str3.tm_min = atoi(charr5[1]);
	time_str3.tm_sec = atoi(charr5[2]);
	time_str3.tm_isdst = -1;

	int l1=mktime(&time_str1);
	int l2=mktime(&time_str2);
	int l3=mktime(&time_str3);
	if(l3>=l1 && l3<=l2)
	{
		return 1;	
	}
	else
	{
		return 0;
	}
		
	//int i;
	/*char s1[1000]="\0";
	strcat(s1,charr[2]);//DAY
	strcat(s1," ");
	strcat(s1,charr[3]);//MONTH
	strcat(s1," ");
	strcat(s1,charr[4]);//DATE-19,20 etc
	strcat(s1," ");
	strcat(s1,charr[5]);//TIME
	strcat(s1," ");
	strcat(s1,charr[6]);//YEAR
	strcat(s1,"\0");

	char s2[1000]="\0";
	strcat(s2,charr[7]);//DAY
	strcat(s2," ");
	strcat(s2,charr[8]);//MONTH
	strcat(s2," ");
	strcat(s2,charr[9]);//DATE-19,20 etc
	strcat(s2," ");
	strcat(s2,charr[10]);//TIME
	strcat(s2," ");
	strcat(s2,charr[11]);//YEAR
	strcat(s2,"\0");

	printf()	*/

	/*if(atoi(charr2[4])>=atoi(charr[6]) && atoi(charr2[4])<=atoi(charr[11]))
	{
		if(atoi(charr[6])==atoi(charr[11]))
		{
			if(Month(charr2[1])>=Month(charr[3]) && Month(charr2[1])<=Month(charr[8]))
			{
				if(Month(charr[3])==Month(charr[8]))
				{
					if(atoi(charr2[2])<=atoi(charr[4]) && atoi(charr2[2])>=atoi(charr[9]))
					{
						if(atoi(charr[4])==atoi(charr[9]))
						{
							if(strcmp(charr2[3],charr[5])>=0 && strcmp(charr2[3],charr[10])<=0)
							{
								return 1;
							}
						}
						else
						{
							return 1;
						}

					}
				}
				else
				{
					return 1;
				}
			}
		
		}
		else if(atoi(charr[6])<atoi(charr[11]))
		{
			return 1;
		}
	}
	return 0;*/
}

char checksum(char * s1)
{
	MDFile (s1);
}

char * LastModified(char *argv)
{
	struct stat fst;
	bzero(&fst,sizeof(fst));

	if (stat(argv,&fst) != 0) { printf("stat() failed with errno %d\n",errno); exit(-1); }

	/*printf("Information for %s\n",argv);
	printf("----------------------------\n\n");
	printf("Last accessed:\t %s",ctime(&fst.st_atime));
	printf("Last modified:\t %s",ctime(&fst.st_mtime));
	printf("Last changed:\t %s",ctime(&fst.st_ctime)); */

	return ctime(&fst.st_mtime);

}
int FileSize(char * ss){

	FILE* fp=fopen(ss,"r");
	int prev=ftell(fp);
	fseek(fp, 0L, SEEK_END);
	int sz=ftell(fp);
	fseek(fp,prev,SEEK_SET); //go back to where we were
	fclose(fp);
	return sz;

}
int regex(char * s1,char * s2)
{
	int l1=strlen(s1);
	int i,l2=strlen(s2),j;
	for(i=0;i<l1;i++)
	{
		for(j=0;j<l2;j++)
		{
			if(s1[i+j]!=s2[j])
			{
				break;
			}
			if(j==l2-1)
			{
				return 1;
			}
		}
	}
	return 0;
}
void setnonblock(int socket)
{
	int flags;
	flags = fcntl(socket,F_GETFL,0);
	// assert(flags != -1);
	fcntl(socket, F_SETFL, flags | O_NONBLOCK);
	fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
	
}
int main(int argc , char *argv[])
{
	if (argc < 2) { //printf("Usage: %s filename\n",argv[0]); exit(-1); 
	}

	int client_sock;
	struct sockaddr_in server;
	char client_message[1000]={0} , server_reply[2000];
	char sip[25];
	struct hostent *he;
	char revbuf[LENGTH];

	he=gethostbyname(sip);
	//Create socket
	client_sock = socket(AF_INET , SOCK_STREAM , 0);
	if (client_sock == -1)
	{
		//printf("Could not create socket");
	}
	//puts("Socket created");
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons( 8080 );

	if (connect(client_sock , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		perror("connect failed. Error");
		return 1;
	}
/*	int flags;
	flags = fcntl(client_sock,F_GETFL,0);
	// assert(flags != -1);
	fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);
	fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
	//puts("Connection accepted");
*///puts("Connection accepted");
	setnonblock(client_sock);

	char newww[1024];
	char messagesend[8000];
	while(1)
	{
//puts("Connection accepted");
	bzero(client_message,LENGTH);
	read(client_sock, client_message, LENGTH);
	if(strlen(client_message)>0)
	{
	bzero(messagesend,8000);
	char *ch1;
	int chcount=0;
	char *charr[1000];

	ch1 = strtok(client_message," ");
	while(ch1 != NULL)
	{
		charr[chcount]=ch1;
		chcount++;
		ch1 = strtok(NULL, " ");
	}

	if(strcmp(charr[0],"FileHash")==0)
			{
				if(strcmp(charr[1],"Verify")==0)
				{
					//printf("%s %s",charr[2],LastModified(charr[2]));	
					//strcat(messagesend,charr[2]);
					char ss1[100],ss2[100];
					strcpy(ss1,"md5sum ");
					strcpy(ss2," > aa.txt");
					strcat(ss1,charr[2]);
					strcat(ss1,ss2);
					system(ss1);
					FILE *fs = fopen("aa.txt", "r");
					char ff5[100];
					bzero(ff5,100);
					fread(ff5, sizeof(char), 100, fs);
					fclose(fs);
					strcat(messagesend,ff5);
					strcat(messagesend,LastModified(charr[2]));
					//printf("verify %s\n",ff5);
					
					//checksum(charr[2]);

					//strcat(messagesend,abc);
				}
				else if(strcmp(charr[1],"CheckAll")==0)
				{
					glob_t data;
					switch( glob("*.*", 0, NULL, &data ) ) 
					{   
						case 0:
							break;
						case GLOB_NOSPACE:
							printf( "Out of memory\n" );
							break;
						case GLOB_ABORTED:
							printf( "Reading error\n" );
							break;
						case GLOB_NOMATCH:
							printf( "No files found\n" );
							break;
						default:
							break;
					}
					int i,j=0;
					for(i=0; i<data.gl_pathc; i++)
					{   
						char ss[20]={0};
						strcpy(ss,data.gl_pathv[i]);
						//checksum(ss);
						//strcat(messagesend,abc);
						//printf("%s %s",ss,LastModified(ss));
						char ss1[100],ss2[100];
						strcpy(ss1,"md5sum ");
						strcpy(ss2," > aa.txt");
						char ss3[100];
						strcpy(ss3,ss);
						strcat(ss1,ss3);
						strcat(ss1,ss2);
						system(ss1);
						FILE *fs = fopen("aa.txt", "r");
						char ff5[100];
						bzero(ff5,100);
						fread(ff5, sizeof(char), 100, fs);
						fclose(fs);
						strcat(messagesend,ff5);
						strcat(messagesend,LastModified(ss));
						//strcat(messagesend,"\n");
					}
					globfree( &data );
				}
			}
	else if(strcmp(charr[0],"IndexGet")==0) 
	{
		if(strcmp(charr[1],"ShortList")==0 || strcmp(charr[1],"LongList")==0)
		{
			glob_t data;
			switch( glob("*.*", 0, NULL, &data ) ) 
			{   
				case 0:
					break;
				case GLOB_NOSPACE:
					printf( "Out of memory\n" );
					break;
				case GLOB_ABORTED:
					printf( "Reading error\n" );
					break;
				case GLOB_NOMATCH:
					printf( "No files found\n" );
					break;
				default:
					break;
			}
			int i,j=0;
			for(i=0; i<data.gl_pathc; i++)
			{   
				char ss[20]={0};
				strcpy(ss,data.gl_pathv[i]);
				if(strcmp(charr[1],"ShortList")==0)
				{
					if(CompareTime(charr,LastModified(ss))==1)
					{
						//printf("%s %s %d\n",ss,LastModified(ss),FileSize(ss));
						strcat(messagesend,ss);
						strcat(messagesend," ");
						strcat(messagesend,LastModified(ss));
						char ff1[100];
						bzero(ff1,100);
						sprintf(ff1,"%d",FileSize(ss));
						strcat(messagesend,ff1);
						strcat(messagesend,"\n");
					}
				}
				else
				{
					//printf("%s %s %d\n",ss,LastModified(ss),FileSize(ss));
					strcat(messagesend,ss);
					strcat(messagesend," ");
					strcat(messagesend,LastModified(ss));
					char ff2[100];
					bzero(ff2,100);
					sprintf(ff2,"%d",FileSize(ss));
					strcat(messagesend,ff2);
					strcat(messagesend,"\n");
				}
			}
			globfree( &data );
		}
		else if(strcmp(charr[1],"RegEx")==0)
		{
			glob_t data;
			switch( glob("*.*", 0, NULL, &data ) ) 
			{   
				case 0:
					break;
				case GLOB_NOSPACE:
					printf( "Out of memory\n" );
					break;
				case GLOB_ABORTED:
					printf( "Reading error\n" );
					break;
				case GLOB_NOMATCH:
					printf( "No files found\n" );
					break;
				default:
					break;
			}
			int i,j=0;
			for(i=0; i<data.gl_pathc; i++)
			{   
				char ss[20]={0};
				strcpy(ss,data.gl_pathv[i]);
				//printf( "charr[2]-%s   ss-%s\n", charr[2],ss );
				if(regex(ss,charr[2])==1)
				{
					int size=FileSize(ss);
					//printf( "compared %s  %d\n", ss,size );
					strcat(messagesend,ss);
					char ff3[100];
					sprintf(ff3," %d",size);
					strcat(messagesend,ff3);
					strcat(messagesend,"\n");
				}
				/*if(strstr(charr[2],ss)!=NULL)
				{
					printf( " compared %s\n", ss );
				}*/
				for(j=0;j<strlen(ss);j++)
					ss[j]='\0';	
			}
			globfree( &data );
		}
	}
	else if(strcmp(charr[0],"FileUpload")==0)
	{
		Upload(client_sock,charr[1]);
		char buf[1000];
		bzero(buf,1000);
		printf("File Details\n");
		while(strlen(buf)<=0)
		{
			read(client_sock,buf,1000);
		//printf("SSSIII\n");
		}
		//printf("HIIIII\n");
		printf("%s\n",buf);
	}	
	else if(strcmp(charr[0],"FileDownload")==0)
	{
		Download(client_sock,charr[1]);
	}
	write(client_sock,messagesend,8000);
	}
	//wait();
	//}
	//}
	//else
	//{
		//int enter=0;
		//char extra;
		//while(1)
		//{
			bzero(newww, 1024);
			/*if(enter==0)
			{
				scanf("%[^\n]",newww);
				enter=1;
			}
			else
			{
				scanf("%c",&extra);
				scanf("%[^\n]",newww);
			}*/
			//scanf("%s",newww);
			//while(strlen(newww)<=0)
			//{
			gets(newww);
			//}
			//printf("hiii %s\n",newww);
			//printf("HURRAYYYY %d\n",strlen(newww));
			if(strlen(newww)>0)
			{
			write(client_sock, newww,1024) ;

			char *ch1;
			int chcount=0;
			char *charr[1000];
			
			ch1 = strtok(newww," ");
			while(ch1 != NULL)
			{
				charr[chcount]=ch1;
				chcount++;
				ch1 = strtok(NULL, " ");
			}
			if(strcmp(charr[0],"FileDownload")==0)
			{
				//strcpy(fr_name,charr[1]);
				//char fr_name[200] = "/home/kriti/work/tempp/t2/";
				
				char fr_name[200] = "./";
				strcat(fr_name,charr[1]);
				//strcpy(fr_name,charr[1]);
				FILE *fr = fopen(fr_name, "w");
				if(fr == NULL)
					printf("File %s Cannot be opened.\n", fr_name);
				else
				{
					bzero(revbuf, LENGTH); 
					while(strlen(revbuf)<=0)
					{
						read(client_sock,revbuf,LENGTH);
					}
					//printf("SIZZZ %s\n",revbuf);
					int siz=atoi(revbuf);
					//printf("SIZZZ %d\n",siz);

					int fr_block_sz = 0;
					//while(read(client_sock, revbuf, 1000)<0)
					//{
					bzero(revbuf, LENGTH); 
					while(1)
					{
						while(strlen(revbuf)<=0)
						{
							read(client_sock,revbuf,1);
						}
						//printf("revbuf siz-%d   data-%s\n",siz,revbuf);
						fwrite(revbuf, sizeof(char), 1, fr);
						bzero(revbuf, 1);
						siz-=1;
						if(siz<=0)
							break;
					}
					//siz-=LENGTH;
					/*while((fr_block_sz = read(client_sock, revbuf, LENGTH)) > 0)
					  {
					  printf("revbuf: %s\n",revbuf);
					  int write_sz = fwrite(revbuf, sizeof(char), fr_block_sz, fr);
					  if(write_sz < fr_block_sz)
					  {
					  error("File write failed.\n");
					  }
					  if (fr_block_sz == 0 || fr_block_sz != LENGTH) 
					  {
					  break;
					  }
					  fr_block_sz=0;
					//printf("IN LOOOPPP siz=%d    %s\n",siz,revbuf);
					bzero(revbuf, LENGTH);
					siz-=LENGTH;
					if(siz<=0)
					break;
					}
					if(fr_block_sz < 0)
					{
					if (errno == EAGAIN)
					{
					printf("recv() timed out.\n");
					}
					else
					{
					fprintf(stderr, "recv() failed due to errno = %d\n", errno);
					}
					}*/
					bzero(revbuf, LENGTH);
					while(strlen(revbuf)<=0)
					{    
						read(client_sock,revbuf,1);
					}    
					printf("Ok File %s received from server!\n",fr_name);
					printf("MD5 sum %s\n",revbuf);
				}
				fclose(fr);

				}
				if(strcmp(charr[0],"FileUpload")==0)
				{
					//char fs_name[200] = "/home/kriti/work/tempp/t2/";
					
					char fs_name[200] = "./";
					strcat(fs_name,charr[1]);
					//scanf("%s" , fs_name);
					//char* fs_name = "/home/aryan/Desktop/quotidiani.txt";
					//strcpy(fs_name,st1);
					char sdbuf[2*LENGTH];
					bzero(sdbuf,2*LENGTH);
					while(strlen(sdbuf)<=0)
					{    
						read(client_sock,sdbuf,2*LENGTH);
					}   
				       //printf("%s",sdbuf);	
					if(strcmp(sdbuf,"Deny")==0)
					{    
						printf("Request Denied\n");
					}    
					else 
					{    
						//printf("Ok File %s from Client was Sent!\n", fs_name);

						bzero(sdbuf,2*LENGTH);
						int nn1=FileSize(fs_name);	
						//printf("[Client] Sending %s to the Server... ", fs_name);
						FILE *fs = fopen(fs_name, "r");
						if(fs == NULL)
						{
							printf("ERROR: File %s not found.\n", fs_name);
							exit(1);
						}
						bzero(sdbuf, 2*LENGTH); 
						//int fs_block_sz;//,errno=0; 
						sprintf(sdbuf,"%d",nn1);
						write(client_sock, sdbuf, 2*LENGTH);

						//printf("SIZ %s\n",sdbuf);
						bzero(sdbuf, 2*LENGTH);
						int fs_block_sz=0;	
						while((fs_block_sz = fread(sdbuf, sizeof(char),2*LENGTH, fs)) > 0)
						{
							//printf("SENDING  %s\n",sdbuf);
							if(write(client_sock, sdbuf, 2*LENGTH) <= 0)
							{
								//fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs_name, errno);

								break;
							}

							//sdbuf[0]='\0';
							//printf("SENDING file:   %s\n",sdbuf);
							bzero(sdbuf, 2*LENGTH);
						}
						fclose(fs);
						
						bzero(sdbuf, 8000);
						char ss1[100],ss2[100];
						strcpy(ss1,"md5sum ");
						strcpy(ss2," > aa.txt");
						strcat(ss1,fs_name);
						strcat(ss1,ss2);
						system(ss1);
						FILE *fs1 = fopen("aa.txt", "r");
						char ff5[100];
						bzero(ff5,100);
						fread(ff5, sizeof(char), 100, fs1);
						fclose(fs1);
						strcpy(sdbuf,ff5);
						strcat(sdbuf," ");
						strcat(sdbuf,LastModified(fs_name));
						char nn2[100];
						sprintf(nn2,"%d",nn1);
						strcat(sdbuf,nn2);
						strcat(sdbuf,"\n");

						write(client_sock,sdbuf,8000);

						printf("DATA %s from Client was Sent!\n", sdbuf);
						printf("Ok File %s from Client was Sent!\n", fs_name);
					}
				}
			else
			{
				char message[8000];
				bzero(message,8000);
				while(strlen(message)<=0)
				{
				 read(client_sock , message , 8000);
				}
				 printf("%s",message);
			}
			}
		//}

	//}
	}
	close(client_sock);
	return 0;
}
