/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_VOLUME_H__
#define __OCF_VOLUME_H__

/**
 * @file
 * @brief OCF volume API
 */

#include "ocf_types.h"
#include "ocf_env_headers.h"
#include "ocf/ocf_err.h"
#include "ocf/ocf_io.h"

/**
 * @brief OCF volume UUID maximum allowed size
 */
#define OCF_VOLUME_UUID_MAX_SIZE	(4096UL - sizeof(uint32_t))

/**
 * @brief OCF volume UUID
 */
struct ocf_volume_uuid {
	size_t size;
		/*!< UUID data size */

	void *data;
		/*!< UUID data content */
};

/**
 * @brief This structure describes volume capabilities
 */
struct ocf_volume_caps {
	uint32_t atomic_writes : 1;
		/*!< Volume supports atomic writes */

	uint32_t composite_volume : 1;
		/*!< Volume may be composed of multiple sub-volumes */
};

/**
 * @brief OCF volume interface declaration
 */
struct ocf_volume_ops {
	/**
	 * @brief Submit IO on this volume
	 *
	 * @param[in] io IO to be submitted
	 */
	void (*submit_io)(ocf_io_t io);

	/**
	 * @brief Submit IO with flush command
	 *
	 * @param[in] io IO to be submitted
	 */
	void (*submit_flush)(ocf_io_t io);

	/**
	 * @brief Submit IO with metadata
	 *
	 * @param[in] io IO to be submitted
	 */
	void (*submit_metadata)(ocf_io_t io);

	/**
	 * @brief Submit IO with discard command
	 *
	 * @param[in] io IO to be submitted
	 */
	void (*submit_discard)(ocf_io_t io);

	/**
	 * @brief Submit operation to write zeroes to target address (including
	 *        metadata extended LBAs in atomic mode)
	 *
	 * @param[in] io IO description (addr, size)
	 */
	void (*submit_write_zeroes)(ocf_io_t io);

	/**
	 * @brief Forward the original io directly to the volume
	 *
	 * @param[in] volume Volume to which IO is being submitted
	 * @param[in] token Token representing IO to be forwarded
	 * @param[in] dir Direction OCF_READ/OCF_WRITE
	 * @param[in] addr Address to which IO is being submitted
	 * @param[in] bytes Length of the IO
	 * @param[in] offset Offset within the IO data
	 */
	void (*forward_io)(ocf_volume_t volume, ocf_forward_token_t token,
			int dir, uint64_t addr, uint64_t bytes,
			uint64_t offset);

	/**
	 * @brief Forward the original flush io directly to the volume
	 *
	 * @param[in] volume Volume to which IO is being submitted
	 * @param[in] token Token representing IO to be forwarded
	 */
	void (*forward_flush)(ocf_volume_t volume, ocf_forward_token_t token);

	/**
	 * @brief Forward the original discard io directly to the volume
	 *
	 * @param[in] volume Volume to which IO is being submitted
	 * @param[in] token Token representing IO to be forwarded
	 * @param[in] addr Address to which IO is being submitted
	 * @param[in] bytes Length of the IO
	 */
	void (*forward_discard)(ocf_volume_t volume, ocf_forward_token_t token,
			uint64_t addr, uint64_t bytes);

	/**
	 * @brief Froward operation to write zeros to target address (including
	 *        metadata extended LBAs in atomic mode)
	 *
	 * @param[in] volume Volume to which IO is being submitted
	 * @param[in] token Token representing IO to be forwarded
	 * @param[in] addr Address to which IO is being submitted
	 * @param[in] bytes Length of the IO
	 */
	void (*forward_write_zeros)(ocf_volume_t volume,
			ocf_forward_token_t token, uint64_t addr,
			uint64_t bytes);

	/**
	 * @brief Forward the metadata io directly to the volume
	 *
	 * @param[in] volume Volume to which IO is being submitted
	 * @param[in] token Token representing IO to be forwarded
	 * @param[in] dir Direction OCF_READ/OCF_WRITE
	 * @param[in] addr Address to which IO is being submitted
	 * @param[in] bytes Length of the IO
	 * @param[in] offset Offset within the IO data
	 */
	void (*forward_metadata)(ocf_volume_t volume, ocf_forward_token_t token,
			int dir, uint64_t addr, uint64_t bytes,
			uint64_t offset);

	/**
	 * @brief Forward the io directly to the volume in context
	 *	  where cache is not initialized yet
	 *
	 * @param[in] volume Volume to which IO is being submitted
	 * @param[in] token Token representing IO to be forwarded
	 * @param[in] dir Direction OCF_READ/OCF_WRITE
	 * @param[in] addr Address to which IO is being submitted
	 * @param[in] bytes Length of the IO
	 */
	void (*forward_io_simple)(ocf_volume_t volume,
			ocf_forward_token_t token, int dir,
			uint64_t addr, uint64_t bytes);

	/**
	 * @brief Volume initialization callback, called when volume object
	 *        is being initialized
	 *
	 * @param[in] volume Volume
	 *
	 * @return Zero on success, otherwise error code
	 */
	int (*on_init)(ocf_volume_t volume);

	/**
	 * @brief Volume deinitialization callback, called when volume object
	 *        is being deinitialized
	 *
	 * @param[in] volume Volume
	 */
	void (*on_deinit)(ocf_volume_t volume);

	/**
	 * @brief Open volume
	 *
	 * @note This function performs volume initialization and should
	 *	 be called before any other operation on volume
	 *
	 * @param[in] volume Volume
	 * @param[in] volume_params optional volume parameters, opaque to OCF
	 *
	 * @return Zero on success, otherwise error code
	 */
	int (*open)(ocf_volume_t volume, void *volume_params);

	/**
	 * @brief Close volume
	 *
	 * @param[in] volume Volume
	 */
	void (*close)(ocf_volume_t volume);

	/**
	 * @brief Get volume length
	 *
	 * @param[in] volume Volume
	 *
	 * @return Volume length in bytes
	 */
	uint64_t (*get_length)(ocf_volume_t volume);

	/**
	 * @brief Get maximum io size
	 *
	 * @param[in] volume Volume
	 *
	 * @return Maximum io size in bytes
	 */
	unsigned int (*get_max_io_size)(ocf_volume_t volume);

	/**
	 * @brief Add subvolume to composite volume
	 *
	 * @param[in] volume composite volume handle
	 * @param[in] type type of added subvolume
	 * @param[in] uuid UUID of added subvolume
	 * @param[in] volume_params params to be passed to subvolume open
	 *
	 * @return Zero when success, otherwise an error
	 */
	int (*composite_volume_add)(ocf_volume_t cvolume,
			ocf_volume_type_t type, struct ocf_volume_uuid *uuid,
			void *volume_params);

	/**
	 * @brief Attach subvolume to composite volume
	 *
	 * @param[in] volume composite volume handle
	 * @param[in] uuid UUID of added subvolume
	 * @param[in] tgt_id Target subvolume id
	 * @param[in] type type of added subvolume
	 * @param[in] volume_params params to be passed to subvolume open
	 *
	 * @return Zero when success, otherwise an error
	 */
	int (*composite_volume_attach_member)(ocf_volume_t volume,
			struct ocf_volume_uuid *uuid, uint8_t tgt_id,
			ocf_volume_type_t type, void *volume_params);
};

/**
 * @brief This structure describes volume properties
 */
struct ocf_volume_properties {
	const char *name;
		/*!< The name of volume operations */

	uint32_t volume_priv_size;
		/*!< Size of volume private context structure */

	struct ocf_volume_caps caps;
		/*!< Volume capabilities */

	void (*deinit)(void);
		/*!< Deinitialize volume type */

	struct ocf_volume_ops ops;
		/*!< Volume operations */
};

/**
 * @brief Initialize UUID from string
 *
 * @param[in] uuid UUID to be initialized
 * @param[in] str NULL-terminated string
 *
 * @return Zero when success, othewise error
 */
int ocf_uuid_set_str(ocf_uuid_t uuid, char *str);

/**
 * @brief Obtain string from UUID
 * @param[in] uuid pointer to UUID
 * @return String contained within UUID
 */
static inline const char *ocf_uuid_to_str(const struct ocf_volume_uuid *uuid)
{
	return (const char *)uuid->data;
}

/**
 * @brief Initialize volume
 *
 * @param[in] volume volume handle
 * @param[in] type cache/core volume type
 * @param[in] uuid OCF volume UUID
 * @param[in] uuid_copy crate copy of uuid data
 *
 * @return Zero when success, othewise error
 */
int ocf_volume_init(ocf_volume_t volume, ocf_volume_type_t type,
		struct ocf_volume_uuid *uuid, bool uuid_copy);

/**
 * @brief Deinitialize volume
 *
 * @param[in] volume volume handle
 */
void ocf_volume_deinit(ocf_volume_t volume);

/**
 * @brief Allocate and initialize volume
 *
 * @param[out] volume pointer to volume handle
 * @param[in] type cache/core volume type
 * @param[in] uuid OCF volume UUID
 *
 * @return Zero when success, othewise en error
 */
int ocf_volume_create(ocf_volume_t *volume, ocf_volume_type_t type,
		struct ocf_volume_uuid *uuid);

/**
 * @brief Deinitialize and free volume
 *
 * @param[in] volume volume handle
 */
void ocf_volume_destroy(ocf_volume_t volume);

/**
 * @brief Get volume type
 *
 * @param[in] volume Volume
 *
 * @return Volume type
 */
ocf_volume_type_t ocf_volume_get_type(ocf_volume_t volume);

/**
 * @brief Get volume UUID
 *
 * @param[in] volume Volume
 *
 * @return UUID of volume
 */
const struct ocf_volume_uuid *ocf_volume_get_uuid(ocf_volume_t volume);

/**
 * @brief Get private context of volume
 *
 * @param[in] volume Volume
 *
 * @return Volume private context
 */
void *ocf_volume_get_priv(ocf_volume_t volume);

/**
 * @brief Get cache handle for given volume
 *
 * @param volume volume handle
 *
 * @return Handle to cache for which volume belongs to
 */
ocf_cache_t ocf_volume_get_cache(ocf_volume_t volume);

/**
 * @brief Check if volume supports atomic mode
 *
 * @param[in] volume Volume
 *
 * @return Non-zero value if volume is atomic, otherwise zero
 */
int ocf_volume_is_atomic(ocf_volume_t volume);

/**
 * @brief Check if volume is composited of multiple sub-volumes
 *
 * @param[in] volume Volume
 *
 * @return True if volume is composite, otherwise false
 */
bool ocf_volume_is_composite(ocf_volume_t volume);

/**
 * @brief Allocate new io
 *
 * @param[in] volume Volume
 * @param[in] queue IO queue handle
 * @param[in] addr OCF IO destination address
 * @param[in] bytes OCF IO size in bytes
 * @param[in] dir OCF IO direction
 * @param[in] io_class OCF IO destination class
 * @param[in] flags OCF IO flags
 *
 * @return ocf_io on success atomic, otherwise NULL
 */
ocf_io_t ocf_volume_new_io(ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir,
		uint32_t io_class, uint64_t flags);


/**
 * @brief Submit io to volume
 *
 * @param[in] io IO
 */
void ocf_volume_submit_io(ocf_io_t io);

/**
 * @brief Submit flush to volume
 *
 * @param[in] io IO
 */
void ocf_volume_submit_flush(ocf_io_t io);

/**
 * @brief Submit discard to volume
 *
 * @param[in] io IO
 */
void ocf_volume_submit_discard(ocf_io_t io);

/**
 * @brief Open volume
 *
 * @param[in] volume Volume
 * @param[in] volume_params Opaque volume params
 *
 * @return Zero when success, othewise en error
 */
int ocf_volume_open(ocf_volume_t volume, void *volume_params);

/**
 * @brief Get volume max io size
 *
 * @param[in] volume Volume
 */
void ocf_volume_close(ocf_volume_t volume);

/**
 * @brief Attach subvolume to composite volume
 *
 * @param[in] volume composite volume handle
 * @param[in] tgt_id Target subvolume id
 * @param[in] uuid UUID of added subvolume
 * @param[in] type type of added subvolume
 * @param[in] volume_params params to be passed to subvolume open
 *
 * @return Zero when success, otherwise an error
 */
int ocf_composite_volume_attach_member(ocf_volume_t volume, ocf_uuid_t uuid,
		uint8_t tgt_id, ocf_volume_type_t vol_type, void *vol_params);

/**
 * @brief Get volume max io size
 *
 * @param[in] volume Volume
 *
 * @return Volume max io size in bytes
 */
unsigned int ocf_volume_get_max_io_size(ocf_volume_t volume);

/**
 * @brief Add subvolume to composite volume
 *
 * @param[in] volume composite volume handle
 * @param[in] type type of added subvolume
 * @param[in] uuid UUID of added subvolume
 * @param[in] volume_params params to be passed to subvolume open
 *
 * @return Zero when success, otherwise an error
 */
int ocf_composite_volume_add(ocf_volume_t volume, ocf_volume_type_t type,
		struct ocf_volume_uuid *uuid, void *volume_params);

/**
 * @brief Get volume length
 *
 * @param[in] volume Volume
 *
 * @return Length of volume in bytes
 */
uint64_t ocf_volume_get_length(ocf_volume_t volume);
/*
 * @brief Check if uuid instances contain the same data
 *
 * @param[in] a first uuid
 * @param[in] b second uuid
 * @param[out] diff 0 if equal, non-0 otherwise
 *
 * @retval 0 if comparison successful
 * @retval other value if comparison failed
 */
int ocf_uuid_compare(const struct ocf_volume_uuid * const a,
		const struct ocf_volume_uuid * const b, int *diff);

#endif /* __OCF_VOLUME_H__ */
