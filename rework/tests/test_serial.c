#include "../include/serial.h"
#include "../include/settings.h"

#define TESTSET1 "TEST1DATA"
#define TESTSET2 "TEST2DATA"

void hexdump(byte* ptr, size_t size){
	printf("----HEX_DUMP OF %p ----\n",(void*)ptr);	
	
	for(int i = 0;i < size; i++){
		printf(" %c[0x%x]",ptr[i],ptr[i]);
	}
	printf("\n----END HEX_DUMP ----\n");
	
	return;
}

int main(int argc,char** argv){
	sscso* obj = SSCS_object();
	
	SSCS_object_add_data(obj,"label1",TESTSET1,strlen(TESTSET1));
	SSCS_object_add_data(obj,"label2",TESTSET2,strlen(TESTSET2));


	byte* ec = SSCS_object_encoded(obj);
	size_t ecl = SSCS_object_encoded_size(obj);

	printf("buffer is %s w size %d\n",ec,ecl);
	hexdump(ec,ecl);
	
	sscso* dcobj =  SSCS_open(ec);
	
	byte* r1 = SSCS_object_string(dcobj,"label1");
	if(!r1){
		logerr("could not retrieve obj");
		exit(EXIT_FAILURE);
	}
	hexdump(r1,strlen(r1));


	return 0;
}
