/*
 * Copyright 2012 Luke Dashjr
 * Copyright 2012 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>

#include "config.h"

#include "fpgautils.h"
#include "miner.h"


struct device_api bitforce_api;

#define BFopen(devpath)  serial_open(devpath, 0, -1, true)

static void BFgets(char *buf, size_t bufLen, int fd)
{
	do
		--bufLen;
	while (likely(bufLen && read(fd, buf, 1) && (buf++)[0] != '\n'))
		;
	buf[0] = '\0';
}

static ssize_t BFwrite2(int fd, const void *buf, ssize_t bufLen)
{
	return write(fd, buf, bufLen);
}

#define BFwrite(fd, buf, bufLen)  do {  \
	if ((bufLen) != BFwrite2(fd, buf, bufLen)) {  \
		applog(LOG_ERR, "Error writing to BitForce (" #buf ")");  \
		return 0;  \
	}  \
} while(0)

#define BFclose(fd) close(fd)

static bool bitforce_detect_one(const char *devpath)
{
	char *s;
	char pdevbuf[0x100];

	applog(LOG_DEBUG, "BitForce Detect: Attempting to open %s", devpath);

	int fdDev = BFopen(devpath);
	if (unlikely(fdDev == -1)) {
		applog(LOG_ERR, "BitForce Detect: Failed to open %s", devpath);
		return false;
	}
	BFwrite(fdDev, "ZGX", 3);
	BFgets(pdevbuf, sizeof(pdevbuf), fdDev);
	if (unlikely(!pdevbuf[0])) {
		applog(LOG_ERR, "Error reading from BitForce (ZGX)");
		return 0;
	}
	BFclose(fdDev);
	if (unlikely(!strstr(pdevbuf, "SHA256"))) {
		applog(LOG_DEBUG, "BitForce Detect: Didn't recognise BitForce on %s", devpath);
		return false;
	}

	// We have a real BitForce!
	struct cgpu_info *bitforce;
	bitforce = calloc(1, sizeof(*bitforce));
	bitforce->api = &bitforce_api;
	bitforce->device_path = strdup(devpath);
	bitforce->deven = DEV_ENABLED;
	bitforce->threads = 1;
	if (likely((!memcmp(pdevbuf, ">>>ID: ", 7)) && (s = strstr(pdevbuf + 3, ">>>"))))
	{
		s[0] = '\0';
		bitforce->name = strdup(pdevbuf + 7);
	}

	return add_cgpu(bitforce);
}

static char bitforce_detect_auto()
{
	return
	serial_autodetect_udev     (bitforce_detect_one, "BitFORCE*SHA256") ?:
	serial_autodetect_devserial(bitforce_detect_one, "BitFORCE_SHA256") ?:
	0;
}

static void bitforce_detect()
{
	serial_detect_auto(bitforce_api.dname, bitforce_detect_one, bitforce_detect_auto);
}

struct bitforce_state {
	const char*job_cmd;
	unsigned char job_data[69];
	ssize_t job_data_len;
	uint32_t job_max_nonce;

	char buf[0x100];
};

static void get_bitforce_statline_before(char *buf, struct cgpu_info *bitforce)
{
	float gt = bitforce->temp;
	if (gt > 0)
		tailsprintf(buf, "%5.1fC ", gt);
	else
		tailsprintf(buf, "       ", gt);
	tailsprintf(buf, "        | ");
}

static uint64_t bitforce_can_limit_work(__maybe_unused struct thr_info *thr)
{
	return 0xffffffff;
}

static bool bitforce_thread_init(struct thr_info *thr)
{
	struct cgpu_info *bitforce = thr->cgpu;

	struct timeval now;
	char pdevbuf[3];

	int fdDev = BFopen(bitforce->device_path);
	if (unlikely(-1 == fdDev)) {
		applog(LOG_ERR, "Failed to open BitForce on %s", bitforce->device_path);
		return false;
	}

	struct bitforce_state *state;
	state = thr->cgpu_data = calloc(1, sizeof(struct bitforce_state));

	BFwrite(fdDev, "ZUX0", 4);
	if (unlikely(read(fdDev, pdevbuf, 3) != 3 || !pdevbuf[0])) {
badZUX:
		applog(LOG_ERR, "%s %u: Unexpected response to ZUX0", bitforce->api->name, bitforce->device_id);
		return false;
	}
	else if (!strncmp("ERR", pdevbuf, 3)) {
		// Old protocol, full nonce ranges only
		BFgets(pdevbuf, sizeof(pdevbuf), fdDev);

		state->job_cmd = "ZDX";
		state->job_data_len = 60;
		state->job_max_nonce = 0xffffffff;
		thr->can_limit_work = false;
	}
	else if (!strncmp(">>>", pdevbuf, 3)) {
		// New protocol, nonce range supported

		if (read(fdDev, pdevbuf, 2) != 2)
			goto badZUX;
		char lastc = (pdevbuf[1] == '>') ? '\n' : '>';
		int cl = 0;
		while (1) {
			if (read(fdDev, pdevbuf, 1) != 1)
				goto badZUX;
			if (cl == 3) {
				if (pdevbuf[0] == lastc)
					break;
				if (pdevbuf[0] != '>')
					cl = 0;
			}
			else {
				if (pdevbuf[0] == '>')
					++cl;
				else
					cl = 0;
			}
		}

		state->job_cmd = "ZPX";
		state->job_data_len = 68;
		thr->can_limit_work = true;
	}
	memset(&state->job_data[0], '>', 8);
	memset(&state->job_data[state->job_data_len-8], '>', 8);

	thr->job_idle_usec = 10000;
	thr->results_delayed = true;

	bitforce->device_fd = fdDev;

	applog(LOG_INFO, "Opened BitForce on %s (%s)", bitforce->device_path, state->job_cmd);
	gettimeofday(&now, NULL);
	get_datestamp(bitforce->init, &now);

	return true;
}

static bool bitforce_job_prepare(struct thr_info*thr, struct work*work, uint64_t __maybe_unused last_nonce)
{
	struct bitforce_state *state = thr->cgpu_data;
	memcpy(&state->job_data[8], work->midstate, 32);
	memcpy(&state->job_data[40], work->data + 64, 12);
	if (state->job_data_len == 68) {
		uint32_t first_nonce = work->blk.nonce;
		first_nonce = 0;
		static uint32_t foo = 0xffffffff;
		last_nonce = foo;
		foo = foo /3*2;
		state->job_data[52] = (first_nonce >> 24);
		state->job_data[53] = (first_nonce >> 16) & 0xff;
		state->job_data[54] = (first_nonce >>  8) & 0xff;
		state->job_data[55] = (first_nonce >>  0) & 0xff;
		state->job_data[56] = ( last_nonce >> 24);
		state->job_data[57] = ( last_nonce >> 16) & 0xff;
		state->job_data[58] = ( last_nonce >>  8) & 0xff;
		state->job_data[59] = ( last_nonce >>  0) & 0xff;
		state->job_max_nonce = last_nonce - first_nonce;
		work->blk.nonce = last_nonce;
//		if (last_nonce != 0xffffffff)
	//		++work->blk.nonce;
	}
	else
	work->blk.nonce = 0xffffffff;
	return true;
}

static void bitforce_job_start(struct thr_info*thr)
{
	struct cgpu_info *bitforce = thr->cgpu;
	struct bitforce_state *state = thr->cgpu_data;
	int fdDev = bitforce->device_fd;

	char pdevbuf[0x100], *s, *s2;

	if (3 != BFwrite2(fdDev, state->job_cmd, 3)) {
		applog(LOG_ERR, "Error writing to BitForce (%s)", state->job_cmd);
		return;
	}

	BFgets(pdevbuf, sizeof(pdevbuf), fdDev);
	if (unlikely(!pdevbuf[0])) {
		applog(LOG_ERR, "Error reading from BitForce (%s)", state->job_cmd);
		return;
	}
	if (unlikely(pdevbuf[0] != 'O' || pdevbuf[1] != 'K')) {
		applog(LOG_ERR, "BitForce ZDX reports: %s", pdevbuf);
		return;
	}

	if (state->job_data_len != BFwrite2(fdDev, state->job_data, state->job_data_len)) {
		applog(LOG_ERR, "Error writing to BitForce (job data)");
		return;
	}
	if (opt_debug) {
		s = bin2hex(state->job_data, state->job_data_len);
		applog(LOG_DEBUG, "BitForce job data: %s", s);
		free(s);
	}

	BFgets(pdevbuf, sizeof(pdevbuf), fdDev);
	if (unlikely(!pdevbuf[0])) {
		applog(LOG_ERR, "Error reading from BitForce (block data)");
		return;
	}
	if (unlikely(pdevbuf[0] != 'O' || pdevbuf[1] != 'K')) {
		applog(LOG_ERR, "BitForce block data reports: %s", pdevbuf);
		return;
	}

	thr->job_running = true;
}

static long bitforce_read_temperature(struct thr_info*thr)
{
	struct cgpu_info *bitforce = thr->cgpu;
	int fdDev = bitforce->device_fd;

	char pdevbuf[0x100], *s;

	BFwrite(fdDev, "ZLX", 3);
	BFgets(pdevbuf, sizeof(pdevbuf), fdDev);
	if (unlikely(!pdevbuf[0])) {
		applog(LOG_ERR, "Error reading from BitForce (ZKX)");
		return 0;
	}
	if ((!strncasecmp(pdevbuf, "TEMP", 4)) && (s = strchr(pdevbuf + 4, ':'))) {
		float temp = strtof(s + 1, NULL);
		return (long)(temp * 0x100);
	}
	return 0;
}

static int64_t bitforce_job_get_results(struct thr_info*thr, __maybe_unused struct work*work)
{
	struct cgpu_info *bitforce = thr->cgpu;
	struct bitforce_state *state = thr->cgpu_data;
	int fdDev = bitforce->device_fd;

	if (3 != BFwrite2(fdDev, "ZFX", 3)) {
		applog(LOG_ERR, "Error writing to BitForce (ZFX)");
		return -2;
	}
	BFgets(state->buf, sizeof(state->buf), fdDev);
	if (unlikely(!state->buf[0])) {
		applog(LOG_ERR, "Error reading from BitForce (ZFX)");
		return -2;
	}
	if (state->buf[0] == 'B')
	    return 0;

	thr->job_running = false;
	if (unlikely(state->buf[2] == '-'))
		state->buf[0] = 'B';
	else
	if (unlikely(strncasecmp(state->buf, "NONCE-FOUND", 11))) {
		applog(LOG_ERR, "BitForce result reports: %s", state->buf);
		return -2;
	}
	return (uint64_t)work->blk.nonce;
}

static int64_t bitforce_job_process_results(struct thr_info*thr, struct work*work)
{
	struct bitforce_state *state = thr->cgpu_data;

	if (state->buf[0] == 'B')
		return 0;  // ignored

	char*pnoncebuf = &state->buf[12];
	uint32_t nonce;

	while (1) {
		hex2bin((void*)&nonce, pnoncebuf, 4);
#ifndef __BIG_ENDIAN__
		nonce = swab32(nonce);
#endif

		submit_nonce(thr, work, nonce);
		if (pnoncebuf[8] != ',')
			break;
		pnoncebuf += 9;
	}

	state->buf[0] = '\0';

	return 0;  // ignored
}

struct device_api bitforce_api = {
	.dname = "bitforce",
	.name = "BFL",
	.api_detect = bitforce_detect,
	.get_statline_before = get_bitforce_statline_before,
	.can_limit_work = bitforce_can_limit_work,
	.thread_init = bitforce_thread_init,
	.read_temperature = bitforce_read_temperature,
	.job_prepare = bitforce_job_prepare,
	.job_start = bitforce_job_start,
	.job_get_results = bitforce_job_get_results,
	.job_process_results = bitforce_job_process_results,
};
