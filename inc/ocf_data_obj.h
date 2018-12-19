/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_DATA_OBJ_H__
#define __OCF_DATA_OBJ_H__

/**
 * @file
 * @brief OCF data object API
 */

#include "ocf_types.h"
#include "ocf_env.h"

struct ocf_io;

/**
 * @brief OCF data object UUID maximum allowed size
 */
#define OCF_DATA_OBJ_UUID_MAX_SIZE	(4096UL - sizeof(uint32_t))

/**
 * @brief OCF data object UUID
 */
struct ocf_data_obj_uuid {
	size_t size;
		/*!< UUID data size */

	const void *data;
		/*!< UUID data content */
};

/**
 * @brief This structure describes data object capabilities
 */
struct ocf_data_obj_caps {
	uint32_t atomic_writes : 1;
		/*!< Data object supports atomic writes */
};

/**
 * @brief OCF data object interface declaration
 */
struct ocf_data_obj_ops {
	/**
	 * @brief Allocate new IO for this data object
	 *
	 * @param[in] obj Data object for which IO is created
	 * @return IO On success
	 * @return NULL On failure
	 */
	struct ocf_io *(*new_io)(ocf_data_obj_t obj);

	/**
	 * @brief Submit IO on this data object
	 *
	 * @param[in] io IO to be submitted
	 */
	void (*submit_io)(struct ocf_io *io);

	/**
	 * @brief Submit IO with flush command
	 *
	 * @param[in] io IO to be submitted
	 */
	void (*submit_flush)(struct ocf_io *io);

	/**
	 * @brief Submit IO with metadata
	 *
	 * @param[in] io IO to be submitted
	 */
	void (*submit_metadata)(struct ocf_io *io);

	/**
	 * @brief Submit IO with discard command
	 *
	 * @param[in] io IO to be submitted
	 */
	void (*submit_discard)(struct ocf_io *io);

	/**
	 * @brief Submit operation to write zeroes to target address (including
	 *        metadata extended LBAs in atomic mode)
	 *
	 * @param[in] io IO description (addr, size)
	 */
	void (*submit_write_zeroes)(struct ocf_io *io);

	/**
	 * @brief Open data object
	 *
	 * @note This function performs data object initialization and should
	 *	 be called before any other operation on data object
	 *
	 * @param[in] obj Data object
	 */
	int (*open)(ocf_data_obj_t obj);

	/**
	 * @brief Close data object
	 *
	 * @param[in] obj Data object
	 */
	void (*close)(ocf_data_obj_t obj);

	/**
	 * @brief Close data object
	 *
	 * @param[in] obj Data object
	 */
	unsigned int (*get_max_io_size)(ocf_data_obj_t obj);

	/**
	 * @brief Close data object
	 *
	 * @param[in] obj Data object
	 */
	uint64_t (*get_length)(ocf_data_obj_t obj);
};

/**
 * @brief This structure describes data object properties
 */
struct ocf_data_obj_properties {
	const char *name;
		/*!< The name of data object operations */

	uint32_t io_context_size;
		/*!< Size of io context structure */

	struct ocf_data_obj_caps caps;
		/*!< Data object capabilities */

	struct ocf_data_obj_ops ops;
		/*!< Data object operations */
};

static inline struct ocf_data_obj_uuid ocf_str_to_uuid(char *str)
{
	struct ocf_data_obj_uuid uuid = {
		.data = str,
		.size = env_strnlen(str, OCF_DATA_OBJ_UUID_MAX_SIZE),
	};

	return uuid;
}

/**
 * @brief Get data object type
 *
 * @param[in] obj Data object
 *
 * @return Data object type
 */
ocf_data_obj_type_t ocf_data_obj_get_type(ocf_data_obj_t obj);

/**
 * @brief Get private context of data object
 *
 * @param[in] obj Data object
 *
 * @return Data object private context
 */
void *ocf_data_obj_get_priv(ocf_data_obj_t obj);

/**
 * @brief Set private context for data object
 *
 * @param[in] obj Data object
 * @param[in] priv Data object private context to be set
 */
void ocf_data_obj_set_priv(ocf_data_obj_t obj, void *priv);

/**
 * @brief Get data object UUID
 *
 * @param[in] obj Data object
 *
 * @return UUID of data object
 */
const struct ocf_data_obj_uuid *ocf_data_obj_get_uuid(ocf_data_obj_t obj);

/**
 * @brief Get data object length
 *
 * @param[in] obj Data object
 *
 * @return Length of data object in bytes
 */
uint64_t ocf_data_obj_get_length(ocf_data_obj_t obj);

/**
 * @brief Get cache handle for given data object
 *
 * @param obj data object handle
 *
 * @return Handle to cache for which data object belongs to
 */
ocf_cache_t ocf_data_obj_get_cache(ocf_data_obj_t obj);

/**
 * @brief Initialize data object
 *
 * @param[in] obj data object handle
 * @param[in] type cache/core object type
 * @param[in] uuid OCF data object UUID
 * @param[in] uuid_copy crate copy of uuid data
 *
 * @return Zero when success, othewise en error
 */
int ocf_data_obj_init(ocf_data_obj_t obj, ocf_data_obj_type_t type,
		struct ocf_data_obj_uuid *uuid, bool uuid_copy);

/**
 * @brief Deinitialize data object
 *
 * @param[in] obj data object handle
 */
void ocf_data_obj_deinit(ocf_data_obj_t obj);

/**
 * @brief Allocate and initialize data object
 *
 * @param[out] obj pointer to data object handle
 * @param[in] type cache/core object type
 * @param[in] uuid OCF data object UUID
 *
 * @return Zero when success, othewise en error
 */
int ocf_data_obj_create(ocf_data_obj_t *obj, ocf_data_obj_type_t type,
		struct ocf_data_obj_uuid *uuid);

/**
 * @brief Deinitialize and free data object
 *
 * @param[in] obj data object handle
 */
void ocf_data_obj_destroy(ocf_data_obj_t obj);

/**
 * @brief Allocate new io from data object allocator
 *
 * @param[in] obj data object handle
 */
struct ocf_io *ocf_data_obj_new_io(ocf_data_obj_t obj);

/**
 * @brief Delete io from data object allocator
 *
 * @param[in] io handle to previously allocated io
 */
void ocf_data_obj_del_io(struct ocf_io* io);

/**
 * @brief Return io context data
 *
 * @param[in] io ocf io handle
 */
void *ocf_data_obj_get_data_from_io(struct ocf_io* io);

#endif /* __OCF_DATA_OBJ_H__ */
