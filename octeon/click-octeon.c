// -*- c-basic-offset: 4 -*-
/*
 * Copyright (c) 2011-2012 Technical Research Centre of Finland (VTT)
 *
 * Matias.Elo@vtt.fi
 * Markku.Savela@vtt.fi
 *
 * The basic octeon initialization code has been copied and modified
 * from the OCTEON-SDK/examples/passthrough/passthrough.c, which had
 * the following licence:
 */

/***********************license start***************
 * Copyright (c) 2003-2010  Cavium Networks (support@cavium.com). All rights 
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.

 *   * Neither the name of Cavium Networks nor the names of
 *     its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.  

 * This Software, including technical data, may be subject to U.S. export  control
 * laws, including the U.S. Export Administration Act and its  associated
 * regulations, and may be subject to export or import  regulations in other
 * countries. 

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" 
 * AND WITH ALL FAULTS AND CAVIUM  NETWORKS MAKES NO PROMISES, REPRESENTATIONS OR
 * WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
 * THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR
 * DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,
 * MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF
 * VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR
 * PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 ***********************license end**************************************/

#define _GNU_SOURCE
#include <sched.h>
#include <errno.h>

#include <click/config.h>
#include <click-octeon/click-octeon.h>

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-sysinfo.h"
#include "cvmx-helper.h"
#include "cvmx-helper-util.h"
#include "cvmx-spinlock.h"
#include "cvmx-fpa.h"
#include "cvmx-pip.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"
#include "cvmx-dfa.h"
#include "cvmx-pow.h"
#include "cvmx-gmx.h"
#include "cvmx-coremask.h"
#include "cvmx-bootmem.h"
#include "cvmx-helper.h"
#include "cvmx-app-init.h"

#include <pthread.h>

/*
 * Available CPU's
 */
static cpu_set_t cpu;

static int click_assign_cpu(cpu_set_t *my_cpu)
{
    static last_cpu = CPU_SETSIZE;

    CPU_ZERO(my_cpu);
    while (last_cpu > 0) {
	--last_cpu;
	if (CPU_ISSET(last_cpu, &cpu)) {
	    CPU_SET(last_cpu, my_cpu);
	    return last_cpu;
	}
    }
    warnx("All available CPU's assigned");
    return -1;
}

click_octeon_opt_t click_octeon_opt_defaults()
{
    static const click_octeon_opt_t opt = {
	.no_wptr = 0,	/* use separate WQE entries */
	.dyn_rs = 1,	/* short packets only in WQE */
	.red = 1,	/* RED enabled */
    };
    return opt;
}

/**
 * Setup the Cavium Simple Executive Libraries using defaults
 * @opt Configuration options
 * @return Zero on success
 */
static int application_init_simple_exec(const click_octeon_opt_t opt)
{
    /* This code is mostly cut/paste from passthrough.c example */

    int pool;
    for (pool = 0; pool < CVMX_FPA_NUM_POOLS; ++pool) {
	uint64_t current_num = cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(pool));
	cvmx_dprintf("Fpa pool %d had %llu buffers\n", pool, (unsigned long long)current_num);
    }
    
    /* This style of init copied from traffic-gen.c */
    int num_packet_buffers = cvmx_pow_get_num_entries() - 16;
    cvmx_dprintf("num_packet_buffer=%d\n", num_packet_buffers);
    if (cvmx_helper_initialize_fpa(num_packet_buffers,
				   (CVMX_FPA_PACKET_POOL == CVMX_FPA_WQE_POOL) ? 0 : num_packet_buffers,
				   CVMX_PKO_MAX_OUTPUT_QUEUES*2, 0, 0))
	return -1;

    for (pool = 0; pool < CVMX_FPA_NUM_POOLS; ++pool) {
	uint64_t current_num = cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(pool));
	cvmx_dprintf("Fpa pool %d has %llu buffers\n", pool, (unsigned long long)current_num);
    }

    /* ...seems to be only for CN68XX, and then allocates bootmem that
       cannot be released... */
    if (cvmx_helper_initialize_sso(num_packet_buffers)) {
	printf("Failed to initialize SSO\n");
	return -1;
    }

    /* Enter NO_WPTR mode if requested and hardware supports it. */
    if (octeon_has_feature(OCTEON_FEATURE_NO_WPTR)) {
	cvmx_ipd_ctl_status_t ipd_ctl_status;
	ipd_ctl_status.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
	ipd_ctl_status.s.no_wptr = opt.no_wptr;
	cvmx_write_csr(CVMX_IPD_CTL_STATUS, ipd_ctl_status.u64);

	if (opt.no_wptr) {
	    printf("Enabled CVMX_IPD_CTL_STATUS[NO_WPTR]\n");
	    /* WQE's belong into packet pool now */
	    click_octeon_wqe_pool = CVMX_FPA_PACKET_POOL;
	}
    } else if (opt.no_wptr) {
	    printf("CVMX_IPD_CTL_STATUS[NO_WPTR] not supported by device\n");
    }

    int result = cvmx_helper_initialize_packet_io_global();

    /* Don't enable RED for Pass 1 due to errata */
    if (opt.red && cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM)
	cvmx_helper_setup_red(num_packet_buffers/4, num_packet_buffers/8);

    /* Leave 16 bytes space for the ethernet header */
    cvmx_write_csr(CVMX_PIP_IP_OFFSET, 2);
    int num_interfaces = cvmx_helper_get_number_of_interfaces();
    int interface;
    for (interface = 0; interface < num_interfaces; interface++) {
        /* Set the frame max size and jabber size to 65535, as the defaults
           are too small. */
        cvmx_helper_interface_mode_t imode = cvmx_helper_interface_get_mode(interface);
        int num_ports = cvmx_helper_ports_on_interface(interface);
	int port;

        switch (imode) {
	case CVMX_HELPER_INTERFACE_MODE_SGMII:
	case CVMX_HELPER_INTERFACE_MODE_XAUI:
	    for (port=0; port < num_ports; port++)
		cvmx_write_csr(CVMX_GMXX_RXX_JABBER(port,interface), 65535);
	    if (octeon_has_feature(OCTEON_FEATURE_PKND)) {
		cvmx_pip_prt_cfgx_t pip_prt;
		cvmx_pip_frm_len_chkx_t pip_frm_len_chkx;
		pip_frm_len_chkx.u64 = 0;
		pip_frm_len_chkx.s.minlen = 64;
		pip_frm_len_chkx.s.maxlen = -1;
		for (port=0; port<num_ports; port++) {
		    /* Check which PIP_FRM_LEN_CHK register is used for this port-kind
		       for MINERR and MAXERR checks */
		    int pknd = cvmx_helper_get_pknd(interface, port);
		    pip_prt.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(pknd));
		    cvmx_write_csr(CVMX_PIP_FRM_LEN_CHKX(pip_prt.cn68xx.len_chk_sel), pip_frm_len_chkx.u64);
		}
	    } else {
		cvmx_pip_frm_len_chkx_t pip_frm_len_chkx;
		pip_frm_len_chkx.u64 = cvmx_read_csr(CVMX_PIP_FRM_LEN_CHKX(interface));
		pip_frm_len_chkx.s.minlen = 64;
		pip_frm_len_chkx.s.maxlen = -1;
		cvmx_write_csr(CVMX_PIP_FRM_LEN_CHKX(interface), pip_frm_len_chkx.u64);
	    }
	    break;

	case CVMX_HELPER_INTERFACE_MODE_RGMII:
	case CVMX_HELPER_INTERFACE_MODE_GMII:
	    if (OCTEON_IS_MODEL(OCTEON_CN50XX)) {
		cvmx_pip_frm_len_chkx_t pip_frm_len_chkx;
		pip_frm_len_chkx.u64 = cvmx_read_csr(CVMX_PIP_FRM_LEN_CHKX(interface));
		pip_frm_len_chkx.s.minlen = 64;
		pip_frm_len_chkx.s.maxlen = -1;
		cvmx_write_csr(CVMX_PIP_FRM_LEN_CHKX(interface), pip_frm_len_chkx.u64);
	    }
	    for (port=0; port < num_ports; port++) {
		if (!OCTEON_IS_MODEL(OCTEON_CN50XX))
		    cvmx_write_csr(CVMX_GMXX_RXX_FRM_MAX(port,interface), 65535);
		cvmx_write_csr(CVMX_GMXX_RXX_JABBER(port,interface), 65535);
	    }
	    break;
	default:
	    break;
        }

        for (port=0; port < num_ports; port++) {
            cvmx_pip_port_cfg_t port_cfg;
            int pknd = port;
            if (octeon_has_feature(OCTEON_FEATURE_PKND))
                pknd = cvmx_helper_get_pknd(interface, port);
            else
                pknd = cvmx_helper_get_ipd_port(interface, port);
	    cvmx_dprintf("Interface %d port %d is IPD Port %d\n", interface, port, pknd);
            port_cfg.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(pknd));
            port_cfg.s.dyn_rs = opt.dyn_rs;
            cvmx_write_csr(CVMX_PIP_PRT_CFGX(pknd), port_cfg.u64);
        }
    }
    return result;
}

/**
 * Clean up and properly shutdown the simple exec libraries.
 *
 * @return Zero on success. Non zero means some resources are
 *         unaccounted for. In this case error messages will have
 *         been displayed during shutdown.
 */
static int application_shutdown_simple_exec(void)
{
    int result = 0;
    int status;
    int pool;

    cvmx_helper_shutdown_packet_io_global();
    cvmx_helper_uninitialize_sso();

#if 0
    // cvmx_helper_initialize_fpa allocates the pools using
    // cvmx_bootmem_alloc. cvmx_fpa_shutdown_pool does not free them
    // back, and there is no helper function to free the pool
    // memory.

    // This code is commented out and the pools remain allocated
    // after the application exits. Next invocation of the app
    // will not re-intialise buffers, and most things should work
    // just fine using the already initialized buffers. However,
    // the pool info in current app image may not be correct.

    for (pool=0; pool<CVMX_FPA_NUM_POOLS; pool++)
    {
        if (cvmx_fpa_get_block_size(pool) > 0)
        {
            status = cvmx_fpa_shutdown_pool(pool);

            /* Special check to allow PIP to lose packets due to hardware prefetch */
            if ((pool == CVMX_FPA_PACKET_POOL) && (status > 0) && (status < CVMX_PIP_NUM_INPUT_PORTS))
                status = 0;

            result |= status;
        }
    }

#endif

    return result;
}

void *click_make_work(click_work_t type, void *user_data)
{
    static const cvmx_wqe_t wqe_init;

    cvmx_wqe_t *wqe = cvmx_fpa_alloc(CVMX_FPA_WQE_POOL);
    if (!wqe)
	return NULL;

    *wqe = wqe_init;
    cvmx_dprintf("click_make_work: packing work[%llx, %d] type=%d %llu\n",
		 (uint64_t)wqe, (int)wqe->word2.s.bufs,
		 type, (uint64_t)user_data);
    cvmx_wqe_set_unused8(wqe, type);
    wqe->word1.tag_type = CVMX_POW_TAG_TYPE_NULL;
    wqe->word2.s.software = 1;
    wqe->packet_ptr.u64 = (unsigned long)user_data;
    return wqe;
}

void *click_handle_work(void *work)
{
    cvmx_wqe_t *wqe = work;
    void *user_data = (void *)wqe->packet_ptr.u64;

    cvmx_dprintf("click_handle_work: unpacked work[%llx, %d] type=%d %llu\n",
		 (uint64_t)wqe, (int)wqe->word2.s.bufs,
		 cvmx_wqe_get_unused8(wqe), (uint64_t)user_data);
    cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
    return user_data;
}


/*
 * Support function for Click Timestamp using the the octeon cycle
 * count (should be MUCH faster than reading the real time from the
 * linux kernel).
 */
static uint64_t rate;
static uint64_t rate2;
static uint64_t rate_div;
static uint64_t rate_mod;
#if TIMESTAMP_NANOSEC
const unsigned int per_sec = 1000000000;
#define PER_SEC "nsec"
#else
const unsigned int per_sec = 1000000;
#define PER_SEC "msec"
#endif

int64_t click_octeon_time()
{
    const uint64_t cycle = cvmx_clock_get_count(CVMX_CLOCK_CORE);
    const uint64_t stamp = cycle * rate_div + (rate_mod * cycle + rate2) / rate;

#if 0
    cvmx_dprintf("octeon_time: cycle=%llu stamp=%llu sec1=%f sec2=%f\n",
		 cycle,
		 stamp,
		 (double)cycle/(double)rate,
		 (double)stamp/(double)per_sec);
#endif
    return stamp;
}


static void timestamp_setup()
{
    /*
     * Click supports only two precisions for the time stamp
     * (millisecond and nanosecond). The cycle precision/rate
     * is variable between hardware versions, and the cycle
     * count needs to be converted into click timestamp units.
     *
     * Precompute multipliers for "click_octeon_time".
     */
    rate = cvmx_clock_get_rate(CVMX_CLOCK_CORE);
    rate_div = per_sec / rate;
    rate_mod = per_sec % rate;
    rate2 = rate / 2;
    const int64_t stamp = click_octeon_time();
    cvmx_dprintf("timestamp_setup: octeon cycles to " PER_SEC
		 " = cycle*%llu + (cycle*%llu+%llu)/%llu\n"
		 "\tnow = %llu " PER_SEC " (%f)\n",
		 rate_div, rate_mod, rate2, rate, stamp, (double)stamp/(double)per_sec);
}


static int octeon_initialized = 0;

static void print_on_off(const char *str, int flag)
{
    cvmx_dprintf("%s: %s\n", str, flag ? "on" : "off");
}

void click_octeon_init(const click_octeon_opt_t opt)
{
    octeon_initialized = 1;

    cvmx_dprintf("Configuration options\n");
    print_on_off("- no_wptr", opt.no_wptr);
    print_on_off("-  dyn_rs", opt.dyn_rs);
    print_on_off("-     red", opt.red);

    cvmx_linux_enable_xkphys_access(0);
    cvmx_sysinfo_t *system_info = cvmx_sysinfo_get();
#ifdef CVMX_BUILD_FOR_LINUX_USER
    cvmx_sysinfo_linux_userspace_initialize();
    cvmx_bootmem_init(cvmx_sysinfo_get()->phy_mem_desc_addr);
#else
    cvmx_user_app_init(); // Initialize Octeon hardware
#endif

    if (sizeof(void*) == 4)
    {
	//        if (linux_mem32_min)
	//  setup_reserve32();
        //else
        {
            warnx("\nFailed to access 32bit shared memory region. Most likely the Kernel\n"
                   "has not been configured for 32bit shared memory access. Check the\n"
                   "kernel configuration.\n"
                   "Aborting...\n\n");
            return;
        }
    }

    /* Check to make sure the Chip version matches the configured version */
    octeon_model_version_check(cvmx_get_proc_id());

    /* Get list of allowed cores */
    if (sched_getaffinity(0, sizeof(cpu), &cpu))
	warn("sched_getaffinity failed");
    cpu_set_t my_cpu;
    const int cpu_num = click_assign_cpu(&my_cpu);
    if (cpu_num < 0)
	warnx("Main thread not locked!");
    else {
	if (sched_setaffinity(0, sizeof(my_cpu), &my_cpu))
	    warn("sched_setaffinity failed");
	int core_num = cvmx_get_core_num();
	cvmx_dprintf("Main thread locked on cpu=%d\n", cpu_num);
	if (core_num != cpu_num)
	    warnx("Octeon core_num=%d is not same!", core_num);
	system_info->core_mask |= 1<<core_num;
    }

    cvmx_dprintf("Version: %s\n", cvmx_helper_get_version());
    if (application_init_simple_exec(opt) != 0) { // More hardware initializations
	warnx("Simple Executive initialization failed.\n");
    }
    cvmx_helper_initialize_packet_io_local();
    cvmx_dprintf("Max POW entries: %d\n", cvmx_pow_get_num_entries());

    timestamp_setup();
}

int click_octeon_thread(pthread_t thread, int index)
{
    cpu_set_t my_cpu;
    
    if (index == 0) {
	warnx("invalid call index=%d", index);
	return -1;
    }
    int cpu_num = click_assign_cpu(&my_cpu);
    if (cpu_num < 0) {
	warnx("Thread %d not locked", index);
	return -1;
    }

    if (pthread_setaffinity_np(thread, sizeof(my_cpu), &my_cpu)) {
	warn("failed setaffinity for thread %d", index);
	return -1;
    }
    cvmx_dprintf("Thread %d locked on cpu=%d\n", index, cpu_num);
    return 0;
}

void click_octeon_exit(void)
{
    if (octeon_initialized)
	application_shutdown_simple_exec();
}

static void back_to_PACKET_POOL(unsigned char *buf, size_t dummy)
{
    cvmx_fpa_free(buf, CVMX_FPA_PACKET_POOL, 0);
}

static void back_to_WQE_POOL(unsigned char *buf, size_t dummy)
{
    cvmx_fpa_free(buf, CVMX_FPA_WQE_POOL, 0);
}

static void back_to_OUTPUT_BUFFER_POOL(unsigned char *buf, size_t dummy)
{
    cvmx_fpa_free(buf, CVMX_FPA_OUTPUT_BUFFER_POOL, 0);
}

const click_octeon_pool_t click_octeon_pool_info[CVMX_FPA_NUM_POOLS+1] =
{
    [CVMX_FPA_PACKET_POOL]	= {back_to_PACKET_POOL, CVMX_FPA_PACKET_POOL_SIZE},
    [CVMX_FPA_WQE_POOL]		= {back_to_WQE_POOL, CVMX_FPA_WQE_POOL_SIZE},
    [CVMX_FPA_OUTPUT_BUFFER_POOL] = {back_to_OUTPUT_BUFFER_POOL, CVMX_FPA_OUTPUT_BUFFER_POOL_SIZE},
};
// FIXME?: click_octeon_pool function stops looking at first
// NULL. So, if the above values are not actually [0..2],
// that function will not find the pool after first NULL.

unsigned click_octeon_wqe_pool = CVMX_FPA_WQE_POOL;

unsigned char *click_octeon_alloc(size_t size, click_octeon_destructor_t *destructor)
{
    unsigned char *data = NULL;
    if (size <= CVMX_FPA_PACKET_POOL_SIZE)
	data = cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
    *destructor = data ? back_to_PACKET_POOL : 0;
    //cvmx_dprintf("click_octeon_alloc data=%llx, size=%d dest=%llu\n", (uint64_t)data, size, (uint64_t)*destructor);
    return data;
}
