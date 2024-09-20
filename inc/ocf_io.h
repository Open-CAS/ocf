/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */


#ifndef __OCF_IO_H__
#define __OCF_IO_H__

#include "ocf_types.h"

/**
 * @file
 * @brief OCF IO definitions
 */

/**
 * @brief OCF IO start
 *
 * @note OCF IO start notification callback
 *
 * @param[in] io OCF IO being started
 */
typedef void (*ocf_start_io_t)(ocf_io_t io);

/**
 * @brief OCF IO handle
 *
 * @note OCF IO handle callback
 *
 * @param[in] io OCF IO to handle
 */
typedef void (*ocf_handle_io_t)(ocf_io_t io, void *opaque);

/**
 * @brief OCF IO completion
 *
 * @note Completion function for OCF IO
 *
 * @param[in] io OCF IO being completed
 * @param[in] priv1 Completion priv 1
 * @param[in] priv2 Completion priv 2
 * @param[in] error Completion status code
 */
typedef void (*ocf_end_io_t)(ocf_io_t io, void *priv1, void *priv2, int error);

/**
 * @brief Increase reference counter in OCF IO
 *
 * @note Wrapper for get IO operation
 *
 * @param[in] io OCF IO
 */
void ocf_io_get(ocf_io_t io);

/**
 * @brief Decrease reference counter in OCF IO
 *
 * @note If IO don't have any reference - deallocate it
 *
 * @param[in] io OCF IO
 */
void ocf_io_put(ocf_io_t io);

/**
 * @brief Set OCF IO completion function
 *
 * @param[in] io OCF IO
 * @param[in] context Context for completion function
 * @param[in] fn Completion function
 */
void ocf_io_set_cmpl(ocf_io_t io, void *context,
		void *context2, ocf_end_io_t fn);

/**
 * @brief Set OCF IO start function
 *
 * @param[in] io OCF IO
 * @param[in] fn Start callback function
 */
void ocf_io_set_start(ocf_io_t io, ocf_start_io_t fn);

/**
 * @brief Set OCF IO handle function
 *
 * @param[in] io OCF IO
 * @param[in] fn Handle callback function
 */
void ocf_io_set_handle(ocf_io_t io, ocf_handle_io_t fn);

/**
 * @brief Set up data vector in OCF IO
 *
 * @param[in] io OCF IO to set up
 * @param[in] data Source data vector
 * @param[in] offset Data offset in source data vector
 *
 * @retval 0 Data set up successfully
 * @retval Non-zero Data set up failure
 */
int ocf_io_set_data(ocf_io_t io, ctx_data_t *data, uint32_t offset);

/**
 * @brief Get data vector from OCF IO
 *
 * @param[in] io OCF IO to get data
 *
 * @return Data vector from IO
 */
ctx_data_t *ocf_io_get_data(ocf_io_t io);

/**
 * @brief Get offset within the data from OCF IO
 *
 * @param[in] io OCF IO to get data
 *
 * @return Offset within data
 */
uint32_t ocf_io_get_offset(ocf_io_t io);

/**
 * @brief Handle IO in cache engine
 *
 * @param[in] io OCF IO to be handled
 * @param[in] opaque OCF opaque
 */
void ocf_io_handle(ocf_io_t io, void *opaque);

/**
 * @brief Get volume associated with io
 *
 * @param[in] io OCF IO to be handled
 */
ocf_volume_t ocf_io_get_volume(ocf_io_t io);

/**
 * @brief Get the data to be submitted
 *
 * @param[in] token Forward token
 */
ctx_data_t *ocf_forward_get_data(ocf_forward_token_t token);

/**
 * @brief Get io queue of forwarded io
 *
 * @param[in] token Forward token
 */
ocf_queue_t ocf_forward_get_io_queue(ocf_forward_token_t token);

/**
 * @brief Get io class of forwarded io
 *
 * @param[in] token Forward token
 */
uint8_t ocf_forward_get_io_class(ocf_forward_token_t token);

/**
 * @brief Get flags of forwarded io
 *
 * @param[in] token Forward token
 */
uint64_t ocf_forward_get_flags(ocf_forward_token_t token);

/**
 * @brief Forward io to another subvolume
 *
 * Forwarding automatically increases forwarded io refcount, so at some
 * point additional ocf_forward_end() needs to be called to balance it.
 *
 * @param[in] token Forward token
 * @param[in] volume Volume to which IO is being submitted
 * @param[in] token Token representing IO to be forwarded
 * @param[in] dir Direction OCF_READ/OCF_WRITE
 * @param[in] addr Address to which IO is being submitted
 * @param[in] bytes Length of the IO
 * @param[in] offset Offset within the IO data
 */
void ocf_forward_io(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset);

/**
 * @brief Forward flush to another subvolume
 *
 * Forwarding automatically increases forwarded io refcount, so at some
 * point additional ocf_forward_end() needs to be called to balance it.
 *
 * @param[in] volume Volume to which IO is being submitted
 * @param[in] token Token representing IO to be forwarded
 */
void ocf_forward_flush(ocf_volume_t volume, ocf_forward_token_t token);

/**
 * @brief Forward discard to another subvolume
 *
 * Forwarding automatically increases forwarded io refcount, so at some
 * point additional ocf_forward_end() needs to be called to balance it.
 *
 * @param[in] volume Volume to which IO is being submitted
 * @param[in] token Token representing IO to be forwarded
 * @param[in] addr Address to which IO is being submitted
 * @param[in] bytes Length of the IO
 */
void ocf_forward_discard(ocf_volume_t volume, ocf_forward_token_t token,
		uint64_t addr, uint64_t bytes);

/**
 * @brief Forward write_zeros to another subvolume
 *
 * Forwarding automatically increases forwarded io refcount, so at some
 * point additional ocf_forward_end() needs to be called to balance it.
 *
 * @param[in] volume Volume to which IO is being submitted
 * @param[in] token Token representing IO to be forwarded
 * @param[in] addr Address to which IO is being submitted
 * @param[in] bytes Length of the IO
 */
void ocf_forward_write_zeros(ocf_volume_t volume, ocf_forward_token_t token,
		uint64_t addr, uint64_t bytes);

/**
 * @brief Forward metadata io to another subvolume
 *
 * Forwarding automatically increases forwarded io refcount, so at some
 * point additional ocf_forward_end() needs to be called to balance it.
 *
 * @param[in] token Forward token
 * @param[in] volume Volume to which IO is being submitted
 * @param[in] token Token representing IO to be forwarded
 * @param[in] dir Direction OCF_READ/OCF_WRITE
 * @param[in] addr Address to which IO is being submitted
 * @param[in] bytes Length of the IO
 * @param[in] offset Offset within the IO data
 */
void ocf_forward_metadata(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset);

/**
 * @brief Forward io simple to another subvolume
 *
 * Forwarding automatically increases forwarded io refcount, so at some
 * point additional ocf_forward_end() needs to be called to balance it.
 *
 * @param[in] token Forward token
 * @param[in] volume Volume to which IO is being submitted
 * @param[in] token Token representing IO to be forwarded
 * @param[in] dir Direction OCF_READ/OCF_WRITE
 * @param[in] addr Address to which IO is being submitted
 * @param[in] bytes Length of the IO
 */
void ocf_forward_io_simple(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes);

/**
 * @brief Increment forwarded io refcount
 *
 * @param[in] token Forward token
 */
void ocf_forward_get(ocf_forward_token_t token);

/**
 * @brief Complete the forwarded io
 *
 * @param[in] token Forward token to be completed
 * @param[in] error Completion status code
 */
void ocf_forward_end(ocf_forward_token_t token, int error);

#endif /* __OCF_IO_H__ */
