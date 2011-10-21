#ifndef _CLICK_OCTEON_H
#define _CLICK_OCTEON_H

/*
 * This header defines the definitions used by the patched click
 * mainline code to interface with the octeon. This file must be
 * independent of the any "cvmx-*" headers and definitions, this
 * should not include or require any of them.
 *
 * Copyright (c) 2011-2012 Technical Research Centre of Finland (VTT)
 *
 * Markku.Savela@vtt.fi
 */

__BEGIN_DECLS

#include <pthread.h>
#include <stdint.h>

/*
 * 'click_octeon_destructor_t' is defined only because Click
 * does not define it for itself -- this is same as the Click
 * dectructor for releasing the packet buffer space.
 */
typedef void (*click_octeon_destructor_t)(unsigned char *, size_t);

typedef struct {
    click_octeon_destructor_t destructor;
    uint32_t size;
} click_octeon_pool_t;

/* Array of octeon pool descriptions. Index with octeon pool number,
 * guaranteed to be long enough for all used pools, and assumed
 * to be NULL terminated.
 *
 * When a Click packet data points to a buffer used by octeon FPA,
 * the destructor identifies the pool.
 */
extern const click_octeon_pool_t click_octeon_pool_info[];
/*
 * The FPA pool used for WQE entries. This is always CVMX_FPA_WQE_POOL,
 * except when NO_WPTR mode has been enabled and the value is
 * CVMX_FPA_DATA_POOL.
 *
 * This is only required for short packets included into WQE. In such
 * situation either the mode of the octeon should be directly tested
 * or to use this "precomputed" value to choose the pool
 *
 * Note: Test click_octeon_wqe_pool != CVMX_FPA_WQE_POOL may indicate
 * NO_WPTR mode, but not 100% sure, as the value of CVMX_FPA_WQE_POOL
 * is ignored elsewhere in such configuration...
 */
extern unsigned click_octeon_wqe_pool;

/**
 * Return current time in flat int64 format
 *
 * @return 64 bit timestamp value
 *
 * This is for Click Timestamp and the unit is either microseconds
 * or nanoseconds depending on the Click compile time option.
 */
int64_t click_octeon_time();

typedef enum {
    CLICK_OCTEON_NORMAL = 0,	/* Octeon generated work item */
    CLICK_OCTEON_PACKET,	/* Synthetic work item containing Click Packet reference */
} click_work_t;

/*
 * Because cvmx-* headers should not be mixed in with click
 * compilation, we use 'void *' as a cvmx_wqe_t in following
 * methods. It should always be casted into 'cvmx_wqe_t' before use.
 */

void *click_make_work(click_work_t type, void *user_data);
void *click_handle_work(void *work);

/**
 * Return the pool based on destructor
 *
 * @param destructor the destructor associated with data
 * @return pool number or -1, if buffer not part of the pool
 */
inline int click_octeon_pool(click_octeon_destructor_t destructor)
{
    int pool = 0;
    if (destructor)
	do {
	    if (destructor == click_octeon_pool_info[pool].destructor)
		return pool;
	} while (click_octeon_pool_info[pool++].destructor);
    return -1;
}


/**
 * click_octeon_init configuration parameters
 */
typedef struct {
    unsigned no_wptr:1;	/* Enable NO_WPTR mode, if supported by hw */
    unsigned dyn_rs:1;  /* Enable short packets in WQE only */
    unsigned red:1;	/* Enable Random Early drop */
} click_octeon_opt_t;

/*
 * Return default option setup
 */
click_octeon_opt_t click_octeon_opt_defaults();

/**
 * Intialize Octeon environment
 *
 * @param opt configuration options
 *
 * Initilize octeon hardware and lock the current CPU to
 * single core.
 */
void click_octeon_init(const click_octeon_opt_t opt);


/*
 * Allocate a buffer from octeon FPA
 *
 * @param size The minimum length of the buffer in bytes
 * @param destructor Set to NULL, or destructor function
 * @return the buffer pointer, or NULL, if allocation failed
 */
unsigned char *click_octeon_alloc(size_t size, click_octeon_destructor_t *destructor);

/**
 * Introduce a click thread
 *
 * Lock the thread to next avaiable free core.
 *
 * @param thread Identify the thread
 * @param index The number of thread (> 0)
 * @return 0 on success, -1 on error
 */
int click_octeon_thread(pthread_t thread, int index);

/**
 * Shut down octeon environment
 */
void click_octeon_exit(void);

__END_DECLS

#endif
