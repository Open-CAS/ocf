/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_ERR_H__
#define __OCF_ERR_H__

/**
 * @file
 * @brief OCF error codes definitions
 */

/**
 * @brief OCF error enumerator
 */
typedef enum {
	/** Invalid input parameter value */
	OCF_ERR_INVAL = 1000000,

	/** Operation interrupted */
	OCF_ERR_INTR,

	/** Out of memory */
	OCF_ERR_NO_MEM,

	/** Lock not acquired */
	OCF_ERR_NO_LOCK,

	/** Invalid volume type */
	OCF_ERR_INVAL_VOLUME_TYPE,

	/** Unknown error occurred */
	OCF_ERR_UNKNOWN,

	/*!< To many caches */
	OCF_ERR_TOO_MANY_CACHES,

	/** Not enough RAM to start cache */
	OCF_ERR_NO_FREE_RAM,

	/** Start cache failure */
	OCF_ERR_START_CACHE_FAIL,

	/** Cache is busy */
	OCF_ERR_CACHE_IN_USE,

	/** Cache ID does not exist */
	OCF_ERR_CACHE_NOT_EXIST,

	/** Cache ID already exists */
	OCF_ERR_CACHE_EXIST,

	/** Too many core devices in cache */
	OCF_ERR_TOO_MANY_CORES,

	/** Core device not available */
	OCF_ERR_CORE_NOT_AVAIL,

	/** Cannot open device exclusively*/
	OCF_ERR_NOT_OPEN_EXC,

	/** Cache device not available */
	OCF_ERR_CACHE_NOT_AVAIL,

	/** IO Class does not exist */
	OCF_ERR_IO_CLASS_NOT_EXIST,

	/** Error while writing to cache device */
	OCF_ERR_WRITE_CACHE,

	/** Error while writing to core device */
	OCF_ERR_WRITE_CORE,

	/*!< Dirty shutdown */
	OCF_ERR_DIRTY_SHUTDOWN,

	/** Cache contains dirty data */
	OCF_ERR_DIRTY_EXISTS,

	/** Flushing of core interrupted */
	OCF_ERR_FLUSHING_INTERRUPTED,

	/** Adding core to core pool failed */
	OCF_ERR_CANNOT_ADD_CORE_TO_POOL,

	/** Cache is in incomplete state */
	OCF_ERR_CACHE_IN_INCOMPLETE_STATE,

	/** Core device is in inactive state */
	OCF_ERR_CORE_IN_INACTIVE_STATE,

	/** Invalid cache mode */
	OCF_ERR_INVALID_CACHE_MODE,

	/** Invalid cache line size */
	OCF_ERR_INVALID_CACHE_LINE_SIZE,

	/** Unable to perform operation due to concurrent management request */
	OCF_ERR_MNGMT_OP_IN_PROGRESS,

} ocf_error_t;

/* TODO: get rid of linux error codes from OCF entirely */
static inline int ocf_err_linux_to_ocf(int err)
{
	switch(err) {
	case 0:
		return 0;
	case -ENOMEM:
		return -OCF_ERR_NO_MEM;
	case -EBUSY:
		return -OCF_ERR_MNGMT_OP_IN_PROGRESS;
	default:
		return -OCF_ERR_INVAL;
	}
}

#endif /* __OCF_ERR_H__ */
