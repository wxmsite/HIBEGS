#include "common.h"
status_t g2_read_str(g2_t g,char* str){
	if(g == NULL) return ELEMENT_UNINITIALIZED;	
	int len = FP_BYTES;
	 
	fp_read_str(g->x[0],str,len,BASE);
	str+=len;
	fp_read_str(g->x[1],str,len,BASE);
	str+=len;
	fp_read_str(g->y[0],str,len,BASE);
	str+=len;
	fp_read_str(g->y[1],str,len,BASE);
	str+=len;
	fp_read_str(g->z[0],str,len,BASE);
	str+=len;
	fp_read_str(g->z[1],str,len,BASE);

	
}