#ifndef _LINUX_VC_RPMSG_SERVICE_H
#define _LINUX_VC_RPMSG_SERVICE_H

/*
 * NOTE: This file defines the protocol shared between VC, userspace and
 * kernel. VC and userspace use a different header file outside the kernel
 * tree (rpmsg_service_msgs.h). The two header files defining the protocol
 * must remain compatible, bumping the version number when appropriate.
 *
 * See rpmsg_service_msgs.h for more extensive documentation of the protocol.
 */

/*
 * Latest vc_rpmsg_service protocol version supported by the kernel.
 */
#define VC_RPMSG_SERVICE_VERSION 2
#define VC_RPMSG_SERVICE_VERSION_MIN 1

/*
 * Maximum message length.
 * Must be <= RPMSG_BUF_SIZE - sizeof(struct rpmsg_hdr)
 */
#define VC_SERVICE_MSG_MAX_LENGTH 496


enum VC_SERVICE_MSG_TYPE {
	VC_SERVICE_MSG_INVALID,
	VC_SERVICE_MSG_FATAL_ERROR,

	VC_SERVICE_MSG_OPEN,
	VC_SERVICE_MSG_OPEN_REPLY,
	VC_SERVICE_MSG_RELEASE,
	VC_SERVICE_MSG_RELEASE_REPLY,
	VC_SERVICE_MSG_UNMAP_BUFFERS,

	VC_SERVICE_MSG_MAX = 999,
};

enum VC_SERVICE_ERROR_REASON {
	VC_SERVICE_ERROR_UNKNOWN,
	VC_SERVICE_ERROR_BAD_MSG,
	VC_SERVICE_ERROR_TOO_MANY_CLIENTS,
	VC_SERVICE_ERROR_CALL_FAILED,
	VC_SERVICE_ERROR_INCOMPATIBLE_VERSION,
	VC_SERVICE_ERROR_UNKNOWN_CLIENT,
};

/*
 * Userspace interface for sending ION buffers.
 */
struct VC_SERVICE_BUFFER_USER_T {
	int32_t fd;		/* file descriptor received from ION */
	uint32_t size;		/* size of buffer */
	int32_t reserved;	/* write as 0, read as don't-care */
};

/*
 * VC interface for receiving ION buffers.
 */
struct VC_SERVICE_BUFFER_VC_T {
	uint32_t addr;		/* VC virtual address */
	uint32_t size;		/* size of buffer */
	int32_t kernel_id;	/* opaque handle returned in */
				/*  UNMAP_BUFFERS messages   */
};

struct VC_SERVICE_MSG_HEADER_T {
	uint16_t type;
	uint8_t num_buffers;	/* number of VC_SERVICE_BUFFER_USER_T */
				/*  that are appended to the message  */
	uint8_t reserved;
};

struct VC_SERVICE_MSG_FATAL_ERROR_T {
	struct VC_SERVICE_MSG_HEADER_T hdr;
	int32_t reason;		/* VC_SERVICE_ERROR_REASON */
	int32_t data;
};

struct VC_SERVICE_MSG_OPEN_T {
	struct VC_SERVICE_MSG_HEADER_T hdr;
	int32_t version;
	int32_t version_min;
	int32_t service_version;
	int32_t service_version_min;
};

struct VC_SERVICE_MSG_OPEN_REPLY_T {
	struct VC_SERVICE_MSG_HEADER_T hdr;
	int32_t version;
	int32_t service_version;
};

struct VC_SERVICE_MSG_RELEASE_T {
	struct VC_SERVICE_MSG_HEADER_T hdr;
};

struct VC_SERVICE_MSG_RELEASE_REPLY_T {
	struct VC_SERVICE_MSG_HEADER_T hdr;
};

struct VC_SERVICE_MSG_UNMAP_BUFFERS_T {
	struct VC_SERVICE_MSG_HEADER_T hdr;
	struct VC_SERVICE_BUFFER_USER_T buffers[0];
};

#endif /* _LINUX_VC_RPMSG_SERVICE_H */
