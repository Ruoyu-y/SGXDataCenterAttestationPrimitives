#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"
#include "sgx_error.h"
#include "sgx_quote_3.h"

#include "Enclave_u.h"

#define SGX_AESM_ADDR "SGX_AESM_ADDR"
#if defined(_MSC_VER)
#define ENCLAVE_PATH _T("enclave.signed.dll")
#else
#define ENCLAVE_PATH "enclave.signed.so"
#endif
#if !defined(NDEBUG) || defined(EDEBUG)
#define SGX_DEBUG_FLAG 1
#else
#define SGX_DEBUG_FLAG 0
#endif


bool load_libs_and_libraries(bool is_out_of_proc, quote3_error_t &qe_result)
{
	bool ret = false;
	if(!is_out_of_proc)
    	{
    		qe_result = sgx_qe_set_enclave_load_policy(SGX_QL_EPHEMERAL);
	    	if (SGX_QL_SUCCESS != qe_result)
    		{
    			syslog(LOG_ERR, "Error in setup enclave load policy. Error code is %x\n", qe_result);
    			//printf("Error in setup enclave load policy. Error code is %s", &qe_result);
    			return ret;
   		 	}
    		printf("Setting Enclave load policy success")

	    	if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so") ||
	                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so")) {

	            // Try to load PCE and QE3 from RHEL-like OS system path
	            if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib64/libsgx_pce.signed.so") ||
	                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib64/libsgx_qe3.signed.so")) {
	            	syslog(LOG_ERR, "Error in set PCE/QE3 directory.\n");
	                //printf("Error in set PCE/QE3 directory.\n");
	                return ret;
	            }
	        }

	        qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1");
	        if (SGX_QL_SUCCESS != qe3_ret) {
	            qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib64/libdcap_quoteprov.so.1");
	            if(SGX_QL_SUCCESS != qe3_ret) {
	            	syslog(LOG_ERR, "Error in set QPL directory.\n");
	                //printf("Error in set QPL directory.\n");
	                return ret;
        	    }
        	}
        }
    ret = true;
    return ret;
}

bool generate_app_report(sgx_target_info_t qe_target_info, sgx_report_t *initiator_report)
{
    bool ret = true;
    uint32_t retval = 0;
	sgx_launch_token_t launch_token = { 0 };
	int launch_token_updated = 0;
	sgx_enclave_id_t eid = 0;

	sgx_status = sgx_create_enclave(ENCLAVE_PATH,
                SGX_DEBUG_FLAG,
                &launch_token,
                &launch_token_updated,
                &eid,
                NULL);
        if (SGX_SUCCESS != sgx_status) {
                printf("Error, call sgx_create_enclave fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
                ret = false;
                goto CLEANUP;
        }

    sgx_status = enclave_create_report(eid,
                &retval,
                &qe_target_info,
                initiator_report);
        if ((SGX_SUCCESS != sgx_status) || (0 != retval)) {
                printf("\nCall to get_app_enclave_report() failed\n");
                ret = false;
                goto CLEANUP;
        }

CLEANUP:
        sgx_destroy_enclave(eid);
        return ret;
}


int main(int argc, char* argv[])
{
	(void)(argc);
    (void)(argv);

    int result = 0;
    quote3_error_t qe_result = SGX_QL_SUCCESS;
    uint32_t quote_size = 0;
    uint8_t* quote_buffer_size = NULL;
    sgx_target_info_t qe_target_info;
    sgx_report_t initiator_report;
    sgx_quote3_t *p_quote;
    sgx_ql_auth_data_t *p_auth_data;
    sgx_ql_ecdsa_sig_data_t *p_sig_data;
    sgx_ql_certification_data_t *p_cert_data;
    FILE *fptr = NULL;
    bool is_out_of_proc = false;
    char *out_of_proc = getenv(SGX_AESM_ADDR);
    if(out_of_proc)
        is_out_of_proc = true;

    result = load_libs_and_libraries(is_out_of_proc, qe_result);
    if (result != 0)
    	goto CLEANUP;

    // Get QE target info to generate App report
    qe_result = sgx_qe_get_target_info(&qe_target_info)
    if (SGX_QL_SUCCESS != qe_result)
    {
    	printf("Error in getting QE target info. Error code %x\n", qe_result);
    	result = -1;
    	goto CLEANUP;
    }
    // Generate App report
    result = generate_app_report(qe_target_info, &initiator_report)
    if (result != true):
        printf("Initiator enclave report creation failed\n");
        goto CLEANUP;

    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }

    printf("succeed!");
    p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        printf("Couldn't allocate quote_buffer\n");
        ret = -1;
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, quote_size);

    // Get the Quote
    ret = sgx_qe_get_quote(&initiator_report,
        quote_size,
        p_quote_buffer);
    if (SGX_QL_SUCCESS != ret) {
        printf( "Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }

    p_quote = (_sgx_quote3_t*)p_quote_buffer;
    p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
    p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

    #if _WIN32
    fopen_s(&fptr, "quote.dat", "wb");
    #else
    fptr = fopen("quote.dat","wb");
    #endif
    if( fptr )
    {
        fwrite(p_quote, quote_size, 1, fptr);
        fclose(fptr);
    }

    CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }
    return result;

}