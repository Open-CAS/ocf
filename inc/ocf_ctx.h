/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_CTX_H__
#define __OCF_CTX_H__

/**
 * @file
 * @brief OCF library context API
 */

#include "ocf_types.h"
#include "ocf_data_obj.h"
#include "ocf_logger.h"

/**
 * @brief Seeking start position in environment data buffer
 */
typedef enum {
	ctx_data_seek_begin,
		/*!< Seeking from the beginning of environment data buffer */
	ctx_data_seek_current,
		/*!< Seeking from current position in environment data buffer */
} ctx_data_seek_t;

/**
 * @brief OCF context specific operation
 */
struct ocf_ctx_ops {
	/**
	 * @brief The name of the environment which provides platform
	 * interface for cache engine
	 */
	const char *name;

	/**
	 * @name Context data buffer operations
	 * @{
	 */

	/**
	 * @brief Allocate contest data buffer
	 *
	 * @param[in] pages The size of data buffer in pages
	 *
	 * @return Context data buffer
	 */
	ctx_data_t *(*data_alloc)(uint32_t pages);

	/**
	 * @brief Free context data buffer
	 *
	 * @param[in] data Contex data buffer which shall be freed
	 */
	void (*data_free)(ctx_data_t *data);

	/**
	 * @brief Lock context data buffer to disable swap-out
	 *
	 * @param[in] data Contex data buffer which shall be locked
	 *
	 * @retval 0 Memory locked successfully
	 * @retval Non-zero Memory locking failure
	 */
	int (*data_mlock)(ctx_data_t *data);

	/**
	 * @brief Unlock context data buffer
	 *
	 * @param[in] data Contex data buffer which shall be unlocked
	 */
	void (*data_munlock)(ctx_data_t *data);

	/**
	 * @brief Read from environment data buffer into raw data buffer
	 *
	 * @param[in,out] dst Destination raw memory buffer
	 * @param[in] src Source context data buffer
	 * @param[in] size Number of bytes to be read
	 *
	 * @return Number of read bytes
	 */
	uint32_t (*data_rd)(void *dst, ctx_data_t *src, uint32_t size);

	/**
	 * @brief Write raw data buffer into context data buffer
	 *
	 * @param[in,out] dst Destination context data buffer
	 * @param[in] src Source raw memory buffer
	 * @param[in] size Number of bytes to be written
	 *
	 * @return Number of written bytes
	 */
	uint32_t (*data_wr)(ctx_data_t *dst, const void *src, uint32_t size);

	/**
	 * @brief Zero context data buffer
	 *
	 * @param[in,out] dst Destination context data buffer to be zeroed
	 * @param[in] size Number of bytes to be zeroed
	 *
	 * @return Number of zeroed bytes
	 */
	uint32_t (*data_zero)(ctx_data_t *dst, uint32_t size);

	/**
	 * @brief Seek read/write head in context data buffer for specified
	 * offset
	 *
	 * @param[in,out] dst Destination context data buffer to be seek
	 * @param[in] seek Seek beginning offset
	 * @param[in] size Number of bytes to be seek
	 *
	 * @return Number of seek bytes
	 */
	uint32_t (*data_seek)(ctx_data_t *dst,
			ctx_data_seek_t seek, uint32_t size);

	/**
	 * @brief Copy context data buffer content
	 *
	 * @param[in,out] dst Destination context data buffer
	 * @param[in] src Source context data buffer
	 * @param[in] to Starting offset in destination buffer
	 * @param[in] from Starting offset in source buffer
	 * @param[in] bytes Number of bytes to be copied
	 *
	 * @return Number of bytes copied
	 */
	uint64_t (*data_cpy)(ctx_data_t *dst, ctx_data_t *src,
			uint64_t to, uint64_t from, uint64_t bytes);

	/**
	 * @brief Erase content of data buffer
	 *
	 * @param[in] dst Contex data buffer which shall be erased
	 */
	void (*data_secure_erase)(ctx_data_t *dst);

	/**
	 * @}
	 */

	/**
	 * @name I/O queue operations
	 * @{
	 */
	/**
	 * @brief Initialize I/O queue.
	 *
	 * This function should create worker, thread or any other queue
	 * processing related stuff specific to given environment.
	 *
	 * @param[in] q I/O queue to be initialized
	 *
	 * @retval 0 I/O queue has been initializaed successfully
	 * @retval Non-zero I/O queue initialization failure
	 */
	int (*queue_init)(ocf_queue_t q);

	/**
	 * @brief Kick I/O queue processing
	 *
	 * This function should inform worker, thread or any other queue
	 * processing mechanism, that there are new requests in queue to
	 * be processed. Processing requests inside current call is not allowed.
	 *
	 * @param[in] q I/O queue to be kicked
	 */
	void (*queue_kick)(ocf_queue_t q);

	/**
	 * @brief Kick I/O queue processing
	 *
	 * This function should inform worker, thread or any other queue
	 * processing mechanism, that there are new requests in queue to
	 * be processed. Kick function is allowed to process requests in current
	 * call
	 *
	 * @param[in] q I/O queue to be kicked
	 */
	void (*queue_kick_sync)(ocf_queue_t q);

	/**
	 * @brief Stop I/O queue
	 *
	 * @param[in] q I/O queue beeing stopped
	 */
	void (*queue_stop)(ocf_queue_t q);

	/**
	 * @}
	 */

	/**
	 * @name Cleaner operations
	 * @{
	 */
	/**
	 * @brief Initialize cleaner.
	 *
	 * This function should create worker, thread, timer or any other
	 * mechanism responsible for calling cleaner routine.
	 *
	 * @param[in] c Descriptor of cleaner to be initialized
	 *
	 * @retval 0 Cleaner has been initializaed successfully
	 * @retval Non-zero Cleaner initialization failure
	 */
	int (*cleaner_init)(ocf_cleaner_t c);

	/**
	 * @brief Stop cleaner
	 *
	 * @param[in] c Descriptor of cleaner beeing stopped
	 */
	void (*cleaner_stop)(ocf_cleaner_t c);

	/**
	 * @}
	 */

	/**
	 * @name Metadata updater operations
	 * @{
	 */
	/**
	 * @brief Initialize metadata updater.
	 *
	 * This function should create worker, thread, timer or any other
	 * mechanism responsible for calling metadata updater routine.
	 *
	 * @param[in] mu Handle to metadata updater to be initialized
	 *
	 * @retval 0 Metadata updater has been initializaed successfully
	 * @retval Non-zero I/O queue initialization failure
	 */
	int (*metadata_updater_init)(ocf_metadata_updater_t mu);

	/**
	 * @brief Kick metadata updater processing
	 *
	 * This function should inform worker, thread or any other mechanism,
	 * that there are new metadata requests to be processed.
	 *
	 * @param[in] mu Metadata updater to be kicked
	 */
	void (*metadata_updater_kick)(ocf_metadata_updater_t mu);

	/**
	 * @brief Stop metadata updater
	 *
	 * @param[in] mu Metadata updater beeing stopped
	 */
	void (*metadata_updater_stop)(ocf_metadata_updater_t mu);

	/**
	 * @}
	 */
};

/**
 * @brief Register data object interface
 *
 * @note Type of data object operations is unique and cannot be repeated.
 *
 * @param[in] ctx OCF context
 * @param[in] properties Reference to data object properties
 * @param[in] type_id Type id of data object operations
 *
 * @retval 0 Data object operations registered successfully
 * @retval Non-zero Data object registration failure
 */
int ocf_ctx_register_data_obj_type(ocf_ctx_t ctx, uint8_t type_id,
		const struct ocf_data_obj_properties *properties);

/**
 * @brief Unregister data object interface
 *
 * @param[in] ctx OCF context
 * @param[in] type_id Type id of data object operations
 */
void ocf_ctx_unregister_data_obj_type(ocf_ctx_t ctx, uint8_t type_id);

/**
 * @brief Get data object type operations by type id
 *
 * @param[in] ctx OCF context
 * @param[in] type_id Type id of data object operations which were registered
 *
 * @return Data object type
 * @retval NULL When data object operations were not registered
 * for requested type
 */
ocf_data_obj_type_t ocf_ctx_get_data_obj_type(ocf_ctx_t ctx, uint8_t type_id);

/**
 * @brief Get data object type id by type
 *
 * @param[in] ctx OCF context
 * @param[in] type Type of data object operations which were registered
 *
 * @return Data object type id
 * @retval -1 When data object operations were not registered
 * for requested type
 */
int ocf_ctx_get_data_obj_type_id(ocf_ctx_t ctx, ocf_data_obj_type_t type);

/**
 * @brief Create data object of given type
 *
 * @param[in] ctx handle to object designating ocf context
 * @param[out] obj data object handle
 * @param[in] uuid OCF data object UUID
 * @param[in] type_id cache/core object type id
 *
 * @return Zero when success, othewise en error
 */

int ocf_ctx_data_obj_create(ocf_ctx_t ctx, ocf_data_obj_t *obj,
		struct ocf_data_obj_uuid *uuid, uint8_t type_id);

/**
 * @brief Set OCF context logger
 *
 * @param[in] ctx OCF context
 * @param[in] logger Structure describing logger
 *
 * @return Zero when success, otherwise an error
 */
int ocf_ctx_set_logger(ocf_ctx_t ctx, const struct ocf_logger *logger);

/**
 * @brief Initialize OCF context
 *
 * @param[out] ctx OCF context
 * @param[in] ops OCF context operations
 *
 * @return Zero when success, otherwise an error
 */
int ocf_ctx_init(ocf_ctx_t *ctx, const struct ocf_ctx_ops *ops);

/**
 * @brief De-Initialize OCF context
 *
 * @param[in] ctx OCF context
 *
 * @note Precondition is stopping all cache instances
 *
 * @return Zero when success, otherwise an error
 */
int ocf_ctx_exit(ocf_ctx_t ctx);

#endif /* __OCF_CTX_H__ */
