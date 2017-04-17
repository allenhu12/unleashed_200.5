#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>         /* For _MAX_PATH definition */
#include <malloc.h>
#include <fcntl.h>
// #include <io.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <time.h>

#include "md5.h"
#include "rks_imagehdr.h"

#ifdef V54_TARGET_SIGN
#include "rks_upgrade_api.h"   /* Image signing definitions are here*/
#endif

#include "bd_strings.c"

#if 0
// TODO:  need to fix nested include problems
#include "v54bsp/ar531x_bsp.h"
#else

#endif

#define FALSE	0
#define TRUE	1
#define EOS     '\0'

#define HDR_SIG 0
#define	MAXTYPESTRING 1024
#define MAX_BUF_SIZE   512 

unsigned char hdrBuf[MAX_IMGHDR];
struct bin_hdr *hdrp = (struct bin_hdr *)hdrBuf;

struct stat bufFileStat;

/* Print help and exit */
void helpexit(void)
{
	printf("\nBINMD5: create a firmware download image from BIN file.");
	printf("\n");
	printf("\nUsage:");
	printf("\n");
	printf("\nbinmd5 -i<input_file> -r<ramdisk> -d -o<output_file> -e<entry_point>");
	printf("\nbinmd5 -i<input_file> -r<ramdisk> -o<output_file> -e<entry_point>");
	printf("\n");
	printf("\nbinmd5 -l -i<input_file>"); 
	printf("\n");
	printf("\n  <input_file> is a BIN format FW file.");
	printf("\n  <ramdisk> is a BIN format root file.");
	printf("\n  -d will display the MD5 of the input BIN file.");
	printf("\n  Assumed that the file is l7 compressed");
	printf("\n");
	fcloseall();
	exit(0);
}

static void
header_info(FILE *inElf)
{
	int i;

	i = fread((unsigned char*)hdrBuf, 1, sizeof(hdrBuf), inElf);
	if ( i != sizeof(hdrBuf) ) {
		fprintf(stderr, "fread(%d) = %d ... failed\n", sizeof(hdrBuf), i);
		return;
	}

    bin_hdr_dump(hdrp, printf);
    
    return;

}

#ifdef V54_TARGET_SIGN
int rks_write_to_file(unsigned char *buf, unsigned int len, FILE *fd)
{
	unsigned int rc = 0;
	rc = fwrite(buf, sizeof(unsigned char), len, fd);

	if ( rc != len) {
		printf("AP Image Signing: Line:%d:fwrite(%d) = %d ... failed\n",__LINE__, len , rc);
		exit(EXIT_FAILURE);
	}
	return rc;
}
/*
 *  Function to construct the Image Tail TLV  
 */
int rks_construct_tail_tlv(FILE *tail_fd, int type, char *path)
{
	char buf[MAX_TAIL_SIZE];
	int i = 0, total_len = 0; 
	FILE *value;
	memset(buf, 0, sizeof buf);

	buf[TLV_TYPE] = (unsigned char)type;

	if ((value = fopen((unsigned char *)path, "rb")) == NULL)
	{
		printf("AP Image Signing: Line:%d :Cannot open file %s to construct the Tail TLV.\n",__LINE__, path);
		exit(EXIT_FAILURE);
	}
	while ((i = fread(&buf[TLV_VALUE], 1, sizeof buf, value )) > 0)
	{
		*((unsigned short *) &buf[TLV_LENGTH])=(unsigned short) i;   // Length
		total_len += rks_write_to_file(buf, (TL_LEN+i), tail_fd);
	}
	fclose(value);
	return total_len;
}

/*
 *  Function to construct the Image Tail for Signed Images (ISI or FSI) 
 */
int
rks_construct_tail(char *tail_path, struct tail_tlv_info info, char *sign_path, char *cert_path)
{
	char buff[MAX_TAIL_SIZE];
	FILE *tail_fd;
	int tail_len = 0;

	memset(buff, 0, sizeof buff);

	if ((tail_fd = fopen((unsigned char *)tail_path, "w+")) == NULL)
	{
		printf("AP Image Signing: Line:%d :Cannot open tail output file %s for signing\n",__LINE__, tail_fd);
		return -1;
	}

	/* TLV 1.  Construct the tail info */ 
	buff[TLV_TYPE] = TAIL_INFO_TLV;
	*((unsigned short *) &buff[TLV_LENGTH])= (unsigned short)(sizeof(struct tail_tlv_info));       
	*((unsigned short *) &buff[TLV_VALUE])= info.num_of_tlvs;      			// Number of TLVs
	*((unsigned int*) &buff[TLV_VALUE + sizeof(unsigned short)]) = info.tail_size;       
	printf("Size of tail_tlv_info is %d \n",(sizeof(struct tail_tlv_info)));

	// Length of tail TLVs- to be filled after the Tail TLVs are constructed
	tail_len += rks_write_to_file(buff, (TL_LEN+ sizeof(struct tail_tlv_info)), tail_fd);

	/* Update the tail length*/
	tail_len += rks_construct_tail_tlv(tail_fd, SIGN_TLV, sign_path);
	tail_len += rks_construct_tail_tlv(tail_fd, CERT_TLV, cert_path);

	/* Update the entire tail length in the tail file */
	rewind(tail_fd);
	if(fseek(tail_fd, TL_LEN + sizeof(unsigned short),SEEK_SET) == -1)
	{
		printf("AP Image Signing: Line:%d :Error while seeking the tail fd\n",__LINE__);
	        fclose(tail_fd);
		return -1;
	}
	*((unsigned int*) &buff) = (unsigned int)hton32(tail_len);
	rks_write_to_file(buff, sizeof(unsigned int), tail_fd);

	fclose(tail_fd);
	return tail_len;
}

/* Function to print possible AP Image signing errors in a build machine and exit the binmd5 
   */
void 
AIS_print_help_n_exit()
{
    printf("\n***** Error while getting the firmware signed. Please check the following:-\n\
            1. Check if curl command is present on the build machine.\n\
            2. Check if the build machine is reachable to HQ-CA1.\n\n");
    exit(EXIT_FAILURE);
}

void
check_curl_command(void)
{
	char result[MAX_BUF_SIZE];
	memset(result,0,MAX_BUF_SIZE);
	FILE* fp = popen("which curl", "r");
	if(fp == NULL){
		printf("AP Image Signing: Line:%d : fp is NULL, error while checking curl command.\n",__LINE__);
	}else{
		fgets(result, 255, fp);
		pclose(fp);
		if(strstr(result,"curl")==NULL){
			printf("AP Image Signing : curl command not found.\n");
			AIS_print_help_n_exit();
		}
	}
}
#endif


/*  Main program  */
int main(int argc, char **argv)
{
	int i;
	int rc;
	int flagI, flagD, flagR, flagS, flagT, flagM;
	int dump_header = 0;
	char *cp, *in, *rfs, opt;
	char *out = NULL;
	unsigned char sw;
	FILE *inElf, *inRfs, *inPlat, *outFile, *inSign, *inCert, *inModel;
	unsigned char buffer[16384], signature[16];
	struct MD5Context md5c;
	int numread;
	u_int32_t entry_point = 0;
	u_int32_t load_address = 0;
	u_int32_t output_len  = 0;

	unsigned char * build_version = BR_BUILD_VERSION;
	unsigned char * product_type = "" ;
	unsigned char * board_type = "" ;
	unsigned char * board_class = "" ;
	unsigned char * flash_chipset = "";

#ifdef V54_TARGET_SIGN
	FILE *tmp_fd;             /* Temporary file = (header+vmlinux+rootfs) */
	FILE *tail_fd;            /* Temporary file = Tail TLVs */
	char *tmp_path = NULL;    /* path to create the above temp file */
	char *tail_path = NULL;   /* path to create the above Image tail */
	unsigned char buf[MAX_BUF_SIZE];
	char *sign_path = NULL;  
	char *cert_path = NULL;  
	unsigned int tail_len = 0;
#endif

	flagI = flagD = flagR = flagS = flagT= flagM= 0;

	if (argc < 2)
		helpexit();

	for (i = 1; i < argc; i++)
	{
		cp = argv[i];
		if (*cp == '-')
		{
			opt = *(++cp);
			if (islower(opt))
			{
				opt = toupper(opt);
			}
			cp++;

			switch (opt)
			{
			/* -Fflash  -- Flash Chipset string*/
			case 'F':
				flash_chipset = (unsigned char *) cp;
				break;  

			/* -L  --  Display header info */
			case 'L':
				dump_header = 1;
				break;

			/* -Vversion -- version string */
			case 'V':
				build_version = (unsigned char *) cp;
				break;

			/* -Bboard_type -- board_type string */
			case 'B':
				board_type = (unsigned char *) cp;
				break;

			/* -Cboard_class -- board_class string */
			case 'C':
				board_class = (unsigned char *) cp;
				break;

			/* -Pproduct_type -- product string */
			case 'P':
				product_type = (unsigned char *) cp;
				break;

			/* -Iinputfile -- Input ELF file, required argument */
			case 'I':
				if ((inElf = fopen((unsigned char *)cp, "rb")) == NULL)
				{
					printf("Cannot open input file %s\n", cp);
					return 2;
				}
				else
				{
					flagI = 1;
					printf("opened input file %s\n", cp);
				}
				in = cp;
				break;

			/* -Rinputfile -- Input root file syatem */
			case 'R':
				if ((inRfs = fopen((unsigned char *)cp, "rb")) == NULL)
				{
					printf("Cannot open root file %s\n", cp);
					return 2;
				}
				else
				{
					flagR = 1;
					printf("opened root file %s\n", cp);
				}
				rfs = cp;
				break;

			/* TODO: Archaic to be removed. But is still in discussion */
#if 0
			/* -Minputfile -- Input model support file, required argument */
			case 'M':
				if ((inModel = fopen((unsigned char *)cp, "rb")) == NULL) {
					printf("Cannot open model support file %s\n", cp);
					return 2;
				} else {
					flagM = 1;
					printf("opened model support file %s\n", cp);
				}
				ins = cp;
				break;
#endif
#ifdef V54_TARGET_SIGN
			/* -Sinputfile -- Input signature file, required argument */
			case 'S':
				flagS = 1;
				sign_path = cp;
				break;

			/* -Tinputfile -- Input certificate file, required argument */
			case 'T':
				flagT = 1;
				cert_path =cp;
				break;

			/* -Kpath
			 * Path to create the temporary file conataining =
			 * (hdr+vmlinux+rootfs) -FSI
			 * (vmlinux+rootfs) -ISI
			 *   to get it signed from the Image
			 * signing server*/
			case 'K':
				tmp_path = (unsigned char *)cp;
				break;

			/* -Zpath
			 * Path to create the Image Tail 
			 */
			case 'Z':
				tail_path = (unsigned char *)cp;
				break;
#endif 
			/* -D  --  Display MD5 of input ELF file */
			case 'D':
				flagD = 1;
				break;

			/* -Ooutputfile */
			case 'O':
				out = (unsigned char *)cp;
				break;

			/* -Eentry_point */
			case 'E':
				entry_point = strtoul((unsigned char*)cp, NULL, 0);
                printf("entry_point = 0x%x -- argv[]='%s'\n", entry_point, cp);
				break;

			/* -Aload_address */
			case 'A':
				load_address = strtoul((unsigned char*)cp, NULL, 0);
                printf("load_address = 0x%x -- argv[]='%s'\n", load_address, cp);
				break;

			/* -? -H  --  Print help info. */
			case '?':
			case 'H':
			default:
				helpexit();
				break;

			} // end switch
		} // end if
	} // end for loop parse cmd line

	/* check cmd line arg consistancy */
	if( flagI == 0 )
	{
		printf("Input file required.\n");
		return(3);
	}
	
	if ( dump_header ) {
		header_info(inElf);
		return 0;
	}

	if ( out == NULL ) {
		printf("Output file required.\n");
		return(4);
	}

#ifdef V54_TARGET_SIGN
	if ( tmp_path == NULL ) {
		printf("AP Image Signing: Line:%d :Temporary Output file path required for Image signing.\n",__LINE__);
		exit(EXIT_FAILURE);
	}
	if ( tail_path == NULL ) {
		printf("AP Image Signing: Line:%d :Temporary Tail file path required for Image signing.\n",__LINE__);
		exit(EXIT_FAILURE);
	}
#endif

#if 0 /* powerpc entry point is 0x0 */
	if ( entry_point == 0 ) {
		printf("Entry_point required.\n");
		return(3);
	}
#endif

#if 0 /* powerpc entry point is 0x0 */ && ( BINHDR_VERSION > BINHDR_VERSION_2 )
	if ( load_address == 0 ) {
		printf("Load_address required.\n");
		return(3);
	}
#endif

	if ((outFile = fopen((unsigned char *)out, "wb")) == NULL)
	{
		printf("Cannot open output file %s for writing\n", out);
		return 3;
	}

#ifdef V54_TARGET_SIGN
	if ((tmp_fd = fopen((unsigned char *)tmp_path, "wb")) == NULL)
	{
		printf("AP Image Signing: Line:%d Cannot open temp output file %s for signing\n",__LINE__, tmp_path);
		exit(EXIT_FAILURE);
	}
#endif

	memset((char *)hdrBuf, 0, sizeof(hdrBuf));

	/* Signature for this Header */
	memcpy(hdrp->magic, BIN_HDR_MAGIC, sizeof(hdrp->magic));

    hdrp->next_image = 0;
	hdrp->invalid = 0;     // > 0 means invalid
	hdrp->hdr_len = (u_int8_t) sizeof(struct bin_hdr);

	hdrp->compression[0] = 'l';
	hdrp->compression[1] = '7';

	hdrp->entry_point = hton32(entry_point);

#if ( BINHDR_VERSION > BINHDR_VERSION_2 )
	hdrp->load_address = hton32(load_address);
#endif

    hdrp->hdr_version = hton16(BINHDR_VERSION);

	/* Get timestamp and length of input ELF file */
	stat(in, &bufFileStat );
	hdrp->timestamp = hton32(bufFileStat.st_mtime);
	hdrp->bin_len = hton32(bufFileStat.st_size);
	
	{
	int ver_len = strlen(build_version) + 1;	// including the trailing '\0'
	memcpy(hdrp->version, build_version, 
			(ver_len < sizeof(hdrp->version)) ?
				ver_len : sizeof(hdrp->version)
			);
#if ( BINHDR_VERSION > BINHDR_VERSION_1 )
	memcpy(hdrp->version_v1, build_version, 
			(ver_len < sizeof(hdrp->version_v1)) ?
				ver_len : sizeof(hdrp->version_v1)
			);
#endif
	}

#if ( BINHDR_VERSION > BINHDR_VERSION_1 )
// leave space for the terminating NULL
#define BINHDR_PRODUCT_SIZE	 (sizeof(hdrp->product) - 1)
	strncpy(hdrp->product, product_type, BINHDR_PRODUCT_SIZE);
	hdrp->product[BINHDR_PRODUCT_SIZE] = '\0';
	hdrp->product_v1 = 0;	// previous field always set to zero
#else
    hdrp->product = 
#if defined(BR2_PRODUCT_AP)
		PRODUCT_AP;
#elif defined(BR2_PRODUCT_ADAPTER)
		PRODUCT_ADAPTER;
#elif defined(BR2_PRODUCT_ROUTER)
		PRODUCT_ROUTER;
#else
		PRODUCT_ALL;
#endif
#endif

    hdrp->architecture =
#if defined(MIPS_BE)
            ARCH_MIPS_BE;
#elif defined(MIPS_LE)
            ARCH_MIPS_LE;
#else
            ARCH_ALL;
#endif

    hdrp->chipset=atoi(flash_chipset);

#if ( BINHDR_VERSION > BINHDR_VERSION_1 )
    if ( *board_type != '\0' ) {
        hdrp->boardType = v54_BType_code(board_type);
    } else {
        hdrp->boardType = V54_BTYPE_ALL;
    }
#else
    hdrp->boardType =
#if defined(GD4)
            V54_BTYPE_GD4;
#elif defined(GD6_1)
            V54_BTYPE_GD6_1;
#elif defined(GD6_5)
            V54_BTYPE_GD6_5;
#elif defined(DF1)
            V54_BTYPE_DF1;
#else
            V54_BTYPE_ALL;
#endif
#endif

#if ( BINHDR_VERSION > BINHDR_VERSION_1 )
    if ( *board_class != '\0' ) {
        hdrp->boardClass = v54_BClass_code(board_class);
    } else {
        hdrp->boardClass = V54_BCLASS_ALL ;
    }
#endif

#ifdef BR2_CUSTOMER_ID
    memcpy(hdrp->customer, BR2_CUSTOMER_ID, RKS_BD_CN_SIZE);
    hdrp->customer[RKS_BD_CN_SIZE-1] = '\0';
#else
    hdrp->customer[0] = '\0';	// default to no customer
#endif

#ifdef V54_TARGET_SIGN
	if (flagS)
	{
#ifdef V54_BUILD_FSI_IMG
		printf("********* Building a FSI IMage. ************\n");
		hdrp->sign = hton32(BIN_HDR_FSI_IMG_VER);
#else 
		printf("********* Building an ISI IMage. ************\n");
		hdrp->sign = hton32(BIN_HDR_ISI_IMG_VER);
#endif
	}
#endif

	rc = fwrite((unsigned char *)hdrp,sizeof( char ), sizeof(struct bin_hdr), outFile);
	if(rc != sizeof(struct bin_hdr))
	{
		printf("%d: fwrite(%d) = %d ... failed\n",__LINE__, sizeof(struct bin_hdr), rc);
		fcloseall();
		return 5;
	}

#ifdef V54_TARGET_SIGN
	if(IS_IMG_FSI)
	{
		/* For FSI - Header is also signed */
		rc = fwrite((unsigned char *)hdrp,sizeof( char ), sizeof(struct bin_hdr), tmp_fd);
		if(rc != sizeof(struct bin_hdr))
		{
			printf("AP Image Signing: Line:%d: fwrite(%d) = %d ... failed\n",__LINE__, sizeof(struct bin_hdr), rc);
			fcloseall();
            exit(EXIT_FAILURE);
		}
	}
#endif
	output_len += sizeof(struct bin_hdr);

	/* Read and check input file */
	MD5Init(&md5c);
	while ((i = fread(buffer, 1, sizeof buffer, inElf)) > 0)
	{
		MD5Update(&md5c, buffer, (unsigned) i);
		rc = fwrite(buffer, sizeof(unsigned char ), i, outFile);
#ifdef V54_TARGET_SIGN
		rc = fwrite(buffer, sizeof(unsigned char ), i, tmp_fd);
#endif
		if ( rc != i ) {
			printf("fwrite(%d) = %d ... failed\n", i, rc);
			fcloseall();
			return 5;
		}
		output_len += rc;
	}
	fclose(inElf);
	printf("Elf end @0x%x\n", output_len);

	if (flagR)
	{
		int pad_size = ((output_len + 0xffff) & 0xffff0000) - output_len;
		
		if (pad_size)
		{
			for (i = 0; i < sizeof(buffer); i++)
			{
				buffer[i] = 0xff;
			}
			while (pad_size > 0)
			{
				i = (pad_size > sizeof(buffer))? sizeof(buffer) : pad_size;
				MD5Update(&md5c, buffer, (unsigned) i);
				rc = fwrite(buffer, sizeof(unsigned char ), i, outFile);
#ifdef V54_TARGET_SIGN
				rc = fwrite(buffer, sizeof(unsigned char ), i, tmp_fd);
#endif
				if ( rc != i ) {
					printf("fwrite(%d) = %d ... failed\n", i, rc);
					fcloseall();
					return 5;
				}
				pad_size   -= rc;
				output_len += rc;
			}
		}
	    if(flagD)
	    {
			printf("Root = 0x%x\n", output_len);
		}
		hdrp->next_image = hton32(output_len);
		while ((i = fread(buffer, 1, sizeof buffer, inRfs)) > 0)
		{
			MD5Update(&md5c, buffer, (unsigned) i);
			rc = fwrite(buffer, sizeof(unsigned char ), i, outFile);
#ifdef V54_TARGET_SIGN
			rc = fwrite(buffer, sizeof(unsigned char ), i, tmp_fd);
#endif
			if ( rc != i ) {
				printf("fwrite(%d) = %d ... failed\n", i, rc);
				fcloseall();
				return 5;
			}
			output_len += rc;
		}
		fclose(inRfs);
	}

	if(IS_IMG_ISI)
	{
		hdrp->tail_offset = output_len - hdrp->hdr_len;
		hdrp->tail_offset = hton32(hdrp->tail_offset);
	}
	else
	{
		MD5Final(signature, &md5c);

		if (flagR)
		{
			output_len -= hdrp->hdr_len;
			hdrp->bin_len = hton32(output_len) ;
		}
		// md5 checksum
		memcpy(hdrp->signature, signature, sizeof(signature));
		DO_CKSUM(hdrp, sizeof(hdrBuf));

		/* Write the updated header to the output files */
		rewind(outFile);
		fwrite((unsigned char *)hdrp,sizeof( char ), sizeof(struct bin_hdr), outFile);
	}

#ifdef V54_TARGET_SIGN
	if(IS_IMG_FSI)
	{
		/* Rewind to write hdr in FSI Image  */
		rewind(tmp_fd);
		fwrite((unsigned char *)hdrp,sizeof( char ), sizeof(struct bin_hdr), tmp_fd);
	}
	fclose(tmp_fd);

    check_curl_command();

	/* We are in buildroot so use path relative to buildroot to execute the signing scripts */ 
	sprintf(buf,"sh toolchain/binmd5/Image_signing_scripts/make_dsp.sh -i %s"
			" -s %s -c %s", tmp_path, sign_path, cert_path);
	printf("Executing %s\n",buf);
    if(system(buf) == -1){
        printf("AP Image Signing: Line:%d :Unable to run the scripts.\n");
        AIS_print_help_n_exit();
    }

    if( (access(sign_path, F_OK) < 0) || (access(cert_path, F_OK) < 0) ){
        printf("AP Image Signing: Line:%d :Signature or certificate not found.\n",__LINE__);
        AIS_print_help_n_exit();
    }   

	fseek(outFile, 0 , SEEK_END);

	struct tail_tlv_info info;
	info.num_of_tlvs = (flagS+flagT);
	info.tail_size   = 0;
	if(rks_construct_tail(tail_path, info, sign_path, cert_path) == -1)
	{
		printf("AP Image Signing: Line:%d: Unable to constuct the Image tail.\n",__LINE__);
        AIS_print_help_n_exit();
	}
	/*Construct the Tail in tail path and append to bl7*/

	if ((tail_fd = fopen((unsigned char *)tail_path, "r")) == NULL)
	{
		printf("AP Image Signing: Line:%d: Cannot open tail output file %s for signing\n",__LINE__, tail_fd);
        AIS_print_help_n_exit();
	}
	/* Append the tail file to bl7 file (i.e. outFile)*/
	rewind(tail_fd);
	fseek(outFile, 0 , SEEK_END);
	while ((i = fread(buffer, 1, sizeof buffer, tail_fd)) > 0)
	{
		rc = rks_write_to_file(buffer, i, outFile);
		/* For an ISI - MD5 is run over tail as well*/ 
		if(IS_IMG_ISI)
		{
			MD5Update(&md5c, buffer, (unsigned) rc);
			output_len+=rc;
		}
	}

	if(IS_IMG_ISI)
	{
		MD5Final(signature, &md5c);
		if (flagR)
		{
			output_len -= hdrp->hdr_len;
			hdrp->bin_len = hton32(output_len) ;
		}

		// md5 checksum
		memcpy(hdrp->signature, signature, sizeof(signature));
		DO_CKSUM(hdrp, sizeof(hdrBuf));

		/* Write the updated header to the output files */
		rewind(outFile);
		fwrite((unsigned char *)hdrp,sizeof( char ), sizeof(struct bin_hdr), outFile);
	}
#endif
	printf("BIN len is %d Tail offset %d \n",ntoh32(hdrp->bin_len), ntoh32(hdrp->tail_offset));

	/* If display of MD5 enabled */
	if(flagD)
	{
		printf("MD5 = ");
		for (i = 0; i < sizeof signature; i++)
		{
			printf("%02X", signature[i]);
		}
		printf("\n");
		printf("Size = %d\n", output_len);
	}

	fcloseall();
	return 0;
}

