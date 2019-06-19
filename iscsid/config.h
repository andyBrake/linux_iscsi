/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <sys/types.h>
#include <byteswap.h>
#include <endian.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_be16(x)		(x)
#define be16_to_cpu(x)		(x)
#define cpu_to_be32(x)		(x)
#define be32_to_cpu(x)		(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_be16(x)		bswap_16(x)
#define be16_to_cpu(x)		bswap_16(x)
#define cpu_to_be32(x)		bswap_32(x)
#define be32_to_cpu(x)		bswap_32(x)
#else
#error "unknown endianess!"
#endif

typedef u_int8_t u8;
typedef u_int16_t u16;
typedef u_int32_t u32;
typedef u_int64_t u64;

#define PROC_TARGETDIR		"/proc/iscsi/target"
#define PROC_DEVICEDIR		"/proc/iscsi/device"


#endif	/* CONFIG_H */
