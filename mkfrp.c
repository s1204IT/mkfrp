/*
 * Copyright (c) 2026 Syuugo
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/blkpg.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/system_properties.h>
#include <unistd.h>

#define SECTOR_SIZE 512u
#define GPT_ENTRY_COUNT 128u
#define GPT_ENTRY_SIZE 128u
#define GPT_SIGNATURE "EFI PART"
#define GPT_SIGNATURE_LEN 8
#define GPT_PRIMARY_HEADER_LBA 1u
#define EXP_DB_SHRINK_SECTORS 2048u
#define FRP_SIZE_BYTES (1024u * 1024u)
#define FRP_FLAG_OFFSET (FRP_SIZE_BYTES - 1u)
#define FRP_FLAG_VALUE 0x01
#define PREFERRED_FRP_ENTRY_INDEX 23u
#define DEVICE_NAME "TAB-A04-BR3"
#define BLOCK_DEVICE "/dev/block/mmcblk0"

typedef struct __attribute__((packed)) {
	char signature[GPT_SIGNATURE_LEN];
	uint32_t revision;
	uint32_t header_size;
	uint32_t header_crc;
	uint32_t reserved;
	uint64_t my_lba;
	uint64_t alternate_lba;
	uint64_t first_usable_lba;
	uint64_t last_usable_lba;
	uint8_t disk_guid[16];
	uint64_t entries_lba;
	uint32_t entry_count;
	uint32_t entry_size;
	uint32_t entries_crc;
} GptHeader;

typedef struct __attribute__((packed)) {
	uint8_t type_guid[16];
	uint8_t partition_guid[16];
	uint64_t first_lba;
	uint64_t last_lba;
	uint64_t attributes;
	uint16_t name[36];
} GptEntry;

static const uint8_t MSFT_BASIC_DATA_GUID[16] = {
	0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
	0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
};

static uint32_t crc32(const void *data, size_t len) {
	const uint8_t *p = data;
	uint32_t crc = 0xFFFFFFFFu;
	while (len--) {
		crc ^= *p++;
		for (int bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
	}
	return ~crc;
}

static int entry_is_used(const GptEntry *entry) {
	for (int i = 0; i < 16; i++)
		if (entry->type_guid[i])
			return 1;
	return 0;
}

static int entry_has_name(const GptEntry *entry, const char *name) {
	for (int i = 0; i < 36; i++) {
		uint16_t c = entry->name[i];
		if (name[i] == '\0')
			return c == 0;
		if (c != (uint8_t)name[i])
			return 0;
	}
	return 0;
}

static void entry_set_name(GptEntry *entry, const char *name) {
	memset(entry->name, 0, sizeof entry->name);
	for (int i = 0; name[i] && i < 35; i++)
		entry->name[i] = (uint8_t)name[i];
}

static int find_entry(const GptEntry *entries, const char *name) {
	for (unsigned i = 0; i < GPT_ENTRY_COUNT; i++)
		if (entry_is_used(&entries[i]) && entry_has_name(&entries[i], name))
			return (int)i;
	return -1;
}

static int find_free_entry(const GptEntry *entries) {
	for (unsigned i = 0; i < GPT_ENTRY_COUNT; i++)
		if (!entry_is_used(&entries[i]))
			return (int)i;
	return -1;
}

static int resize_partition(int fd, int op, int number, uint64_t start, uint64_t length, const char *name) {
	struct blkpg_partition part;
	struct blkpg_ioctl_arg arg;
	memset(&part, 0, sizeof part);
	part.pno = number;
	part.start = start;
	part.length = length;
	strncpy(part.devname, name, sizeof part.devname - 1);
	memset(&arg, 0, sizeof arg);
	arg.op = op;
	arg.datalen = sizeof part;
	arg.data = &part;
	return ioctl(fd, BLKPG, &arg);
}

static int read_gpt(int fd, GptHeader *header, GptEntry entries[GPT_ENTRY_COUNT]) {
	if (pread(fd, header, sizeof *header, GPT_PRIMARY_HEADER_LBA * SECTOR_SIZE) != sizeof *header)
		return -1;
	if (memcmp(header->signature, GPT_SIGNATURE, GPT_SIGNATURE_LEN))
		return -1;
	if (header->entry_count != GPT_ENTRY_COUNT || header->entry_size != GPT_ENTRY_SIZE)
		return -1;
	if (pread(fd, entries, GPT_ENTRY_COUNT * GPT_ENTRY_SIZE, header->entries_lba * SECTOR_SIZE) != GPT_ENTRY_COUNT * GPT_ENTRY_SIZE)
		return -1;
	if (crc32(entries, GPT_ENTRY_COUNT * GPT_ENTRY_SIZE) != header->entries_crc)
		return -1;
	return 0;
}

static int write_gpt(int fd, GptHeader *header, const GptEntry entries[GPT_ENTRY_COUNT]) {
	const size_t entries_size = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE;
	GptHeader backup;
	uint64_t backup_lba, backup_entries_lba;
	header->entries_crc = crc32(entries, entries_size);
	header->header_crc = 0;
	header->header_crc = crc32(header, header->header_size);
	if (pwrite(fd, entries, entries_size, header->entries_lba * SECTOR_SIZE) != entries_size)
		return -1;
	if (pwrite(fd, header, sizeof *header, GPT_PRIMARY_HEADER_LBA * SECTOR_SIZE) != sizeof *header)
		return -1;
	backup_lba = header->alternate_lba;
	if (pread(fd, &backup, sizeof backup, backup_lba * SECTOR_SIZE) != sizeof backup)
		return -1;
	backup_entries_lba = backup_lba - entries_size / SECTOR_SIZE;
	if (pwrite(fd, entries, entries_size, backup_entries_lba * SECTOR_SIZE) != entries_size)
		return -1;
	backup.my_lba = backup_lba;
	backup.alternate_lba = GPT_PRIMARY_HEADER_LBA;
	backup.entries_lba = backup_entries_lba;
	backup.entries_crc = header->entries_crc;
	backup.header_crc = 0;
	backup.header_crc = crc32(&backup, backup.header_size);
	if (pwrite(fd, &backup, sizeof backup, backup_lba * SECTOR_SIZE) != sizeof backup)
		return -1;
	return 0;
}

static int write_frp_area(int fd, uint64_t start_lba) {
	static const uint8_t zeros[4096];
	const uint64_t base = start_lba * SECTOR_SIZE;
	const uint8_t flag = FRP_FLAG_VALUE;
	for (uint64_t offset = 0; offset < FRP_SIZE_BYTES; offset += sizeof zeros)
		if (pwrite(fd, zeros, sizeof zeros, base + offset) != sizeof zeros)
			return -1;
	if (pwrite(fd, &flag, sizeof flag, base + FRP_FLAG_OFFSET) != sizeof flag)
		return -1;
	return 0;
}

static int create_guid(uint8_t guid[16]) {
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, guid, 16);
	close(fd);
	if (n != 16)
		return -1;
	guid[7] = (guid[7] & 0x0F) | 0x40;
	guid[8] = (guid[8] & 0x3F) | 0x80;
	return 0;
}

static unsigned long long sectors_to_mib(uint64_t sectors) {
	return (unsigned long long)(sectors * SECTOR_SIZE / (1024u * 1024u));
}

static int clear_frp_flag(int fd, uint64_t last_lba) {
	const uint8_t zero = 0;
	if (pwrite(fd, &zero, sizeof zero, (last_lba + 1) * SECTOR_SIZE - 1) != (ssize_t)sizeof zero)
		return -1;
	return 0;
}

static int create_frp(int fd, GptHeader *header, GptEntry entries[GPT_ENTRY_COUNT], int do_write) {
	GptEntry *expdb, *frp;
	uint64_t old_last, frp_first, frp_last;
	int expdb_index, frp_index;

	expdb_index = find_entry(entries, "expdb");
	frp_index = find_entry(entries, "frp");
	if (frp_index >= 0) {
		printf("frp exists (entry %d); nothing to do\n", frp_index + 1);
		return 0;
	}
	if (expdb_index < 0) {
		fprintf(stderr, "expdb not found\n");
		return 1;
	}
	expdb = &entries[expdb_index];
	old_last = expdb->last_lba;
	printf("expdb entry %d: %llu..%llu\n", expdb_index + 1, (unsigned long long)expdb->first_lba, (unsigned long long)old_last);
	if (old_last <= expdb->first_lba + EXP_DB_SHRINK_SECTORS) {
		fprintf(stderr, "expdb too small\n");
		return 1;
	}
	frp_first = old_last - EXP_DB_SHRINK_SECTORS + 1;
	frp_last = old_last;
	if (!do_write) {
		printf("dry-run: would create frp %llu..%llu\n", (unsigned long long)frp_first, (unsigned long long)frp_last);
		return 0;
	}
	frp_index = find_free_entry(entries);
	if (frp_index < 0) {
		fprintf(stderr, "no free entry\n");
		return 1;
	}
	if (!entry_is_used(&entries[PREFERRED_FRP_ENTRY_INDEX]))
		frp_index = (int)PREFERRED_FRP_ENTRY_INDEX;
	expdb->last_lba -= EXP_DB_SHRINK_SECTORS;
	frp = &entries[frp_index];
	memset(frp, 0, sizeof *frp);
	memcpy(frp->type_guid, MSFT_BASIC_DATA_GUID, sizeof MSFT_BASIC_DATA_GUID);
	(void)create_guid(frp->partition_guid);
	frp->first_lba = frp_first;
	frp->last_lba = frp_last;
	entry_set_name(frp, "frp");
	if (write_gpt(fd, header, entries)) {
		perror("write GPT");
		return 1;
	}
	resize_partition(fd, BLKPG_DEL_PARTITION, expdb_index + 1, 0, 0, "");
	resize_partition(fd, BLKPG_ADD_PARTITION, expdb_index + 1, expdb->first_lba * SECTOR_SIZE, (expdb->last_lba - expdb->first_lba + 1) * SECTOR_SIZE, "expdb");
	resize_partition(fd, BLKPG_ADD_PARTITION, frp_index + 1, frp->first_lba * SECTOR_SIZE, (frp->last_lba - frp->first_lba + 1) * SECTOR_SIZE, "frp");
	fsync(fd);
	if (write_frp_area(fd, frp->first_lba)) {
		perror("write frp area");
		return 1;
	}
	printf("created frp %llu..%llu (entry %d), expdb now ends %llu\n", (unsigned long long)frp->first_lba, (unsigned long long)frp->last_lba, frp_index + 1, (unsigned long long)expdb->last_lba);
	return 0;
}

static int remove_frp(int fd, GptHeader *header, GptEntry entries[GPT_ENTRY_COUNT]) {
	GptEntry *expdb, *frp;
	uint64_t expdb_first, expdb_last, frp_first, frp_last;
	int expdb_index, frp_index;

	expdb_index = find_entry(entries, "expdb");
	frp_index = find_entry(entries, "frp");
	if (frp_index < 0) {
		printf("frp not found; nothing to do\n");
		return 0;
	}
	if (expdb_index < 0) {
		fprintf(stderr, "expdb not found\n");
		return 1;
	}
	expdb = &entries[expdb_index];
	frp = &entries[frp_index];
	expdb_first = expdb->first_lba;
	expdb_last = expdb->last_lba;
	frp_first = frp->first_lba;
	frp_last = frp->last_lba;
	printf("frp entry %d: %llu..%llu\n", frp_index + 1, (unsigned long long)frp_first, (unsigned long long)frp_last);
	printf("expdb entry %d: %llu..%llu (%llu MiB)\n", expdb_index + 1, (unsigned long long)expdb_first, (unsigned long long)expdb_last, sectors_to_mib(expdb_last - expdb_first + 1));
	if (frp_first > frp_last || frp_first != expdb_last + 1) {
		fprintf(stderr, "frp (%llu..%llu) is not adjacent to expdb (%llu..%llu); refusing to resize\n",
			(unsigned long long)frp_first, (unsigned long long)frp_last,
			(unsigned long long)expdb_first, (unsigned long long)expdb_last);
		return 1;
	}
	expdb->last_lba = frp_last;
	memset(frp, 0, sizeof *frp);
	if (write_gpt(fd, header, entries)) {
		perror("write GPT");
		return 1;
	}
	resize_partition(fd, BLKPG_DEL_PARTITION, frp_index + 1, 0, 0, "");
	resize_partition(fd, BLKPG_DEL_PARTITION, expdb_index + 1, 0, 0, "");
	resize_partition(fd, BLKPG_ADD_PARTITION, expdb_index + 1, expdb_first * SECTOR_SIZE, (expdb->last_lba - expdb_first + 1) * SECTOR_SIZE, "expdb");
	fsync(fd);
	if (clear_frp_flag(fd, frp_last)) {
		perror("clear frp flag");
		return 1;
	}
	printf("removed frp (entry %d); expdb now %llu..%llu (%llu MiB)\n",
		frp_index + 1, (unsigned long long)expdb_first, (unsigned long long)expdb->last_lba,
		sectors_to_mib(expdb->last_lba - expdb_first + 1));
	return 0;
}

int main(int argc, char **argv) {
	int do_write = 0, do_remove = 0;
	char device[PROP_VALUE_MAX] = {0};
	GptHeader header;
	GptEntry entries[GPT_ENTRY_COUNT];
	int fd;

	__system_property_get("ro.product.device", device);
	if (strcmp(device, DEVICE_NAME)) {
		fprintf(stderr, "unsupported device: %s\n", device);
		return 1;
	}
	if (geteuid() != 0) {
		fprintf(stderr, "root required\n");
		return 1;
	}

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-w"))
			do_write = 1;
		else if (!strcmp(argv[i], "-r"))
			do_remove = 1;
		else {
			fprintf(stderr, "unknown option: %s\n", argv[i]);
			return 1;
		}
	}
	if (do_remove && do_write) {
		fprintf(stderr, "these options are mutually exclusive\n");
		return 1;
	}
	fd = open(BLOCK_DEVICE, O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (read_gpt(fd, &header, entries)) {
		fprintf(stderr, "invalid GPT\n");
		return 1;
	}
	if (do_remove)
		return remove_frp(fd, &header, entries);
	return create_frp(fd, &header, entries, do_write);
}
