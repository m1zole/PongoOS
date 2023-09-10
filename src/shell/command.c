/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <stdbool.h>
#include <stdlib.h>
#include <pongo.h>
struct task* command_task;
char command_buffer[0x200];
int command_buffer_idx = 0;

struct command {
    const char* name;
    const char* desc;
    void (*cb)(const char* cmd, char* args);
    bool hidden;
} commands[64];
static lock command_lock;

static int cmp_cmd(const void *a, const void *b)
{
    const struct command *x = a, *y = b;
    if(!x->name && !y->name) return 0;
    if(!x->name) return 1;
    if(!y->name) return -1;
    return strcmp(x->name, y->name);
}

void command_unregister(const char* name) {
    lock_take(&command_lock);
    for (int i=0; i<64; i++) {
        if (commands[i].name && strcmp(commands[i].name, name) == 0) {
            commands[i].name = 0;
            commands[i].desc = 0;
            commands[i].cb = 0;
            commands[i].hidden = false;
        }
    }
    qsort(commands, 64, sizeof(struct command), &cmp_cmd);
    lock_release(&command_lock);
}
void _command_register_internal(const char* name, const char* desc, void (*cb)(const char* cmd, char* args), bool hidden) {
    lock_take(&command_lock);
    for (int i=0; i<64; i++) {
        if (!commands[i].name || strcmp(commands[i].name, name) == 0) {
            commands[i].name = name;
            commands[i].desc = desc;
            commands[i].cb = cb;
            commands[i].hidden = hidden;
            qsort(commands, 64, sizeof(struct command), &cmp_cmd);
            lock_release(&command_lock);
            return;
        }
    }
    lock_release(&command_lock);
    panic("too many commands");
}
void command_register(const char* name, const char* desc, void (*cb)(const char* cmd, char* args)) {
    _command_register_internal(name, desc, cb, false);
}

char* command_tokenize(char* str, uint32_t strbufsz) {
    char* bound = &str[strbufsz];
    while (*str) {
        if (str > bound) return NULL;
        if (*str == ' ') {
            *str++ = 0;
            while (*str) {
                if (str > bound) return NULL;
                if (*str == ' ') {
                    str++;
                } else
                    break;
            }
            if (str > bound) return NULL;
            if (!*str) return "";
            return str;
        }
        str++;
    }
    return "";
}

char is_executing_command;
uint32_t command_flags;
#define COMMAND_NOTFOUND 1
void command_execute(char* cmd) {
    char* arguments = command_tokenize(cmd, 0x1ff);
    if (arguments) {
        lock_take(&command_lock);
        for (int i=0; i<64; i++) {
            if (commands[i].name && !strcmp(cmd, commands[i].name)) {
                void (*cb)(const char* cmd, char* args) = commands[i].cb;
                lock_release(&command_lock);
                cb(command_buffer, arguments);
                return;
            }
        }
        lock_release(&command_lock);
    }
    if(cmd[0] != '\0')
    {
        iprintf("Bad command: %s\n", cmd);
    }
    if (*cmd)
        command_flags |= COMMAND_NOTFOUND;
}

extern uint32_t uart_should_drop_rx;
char command_handler_ready = 0;
volatile uint8_t command_in_progress = 0;
struct event command_handler_iter;

static inline void put_serial_modifier(const char* str) {
    while (*str) serial_putc(*str++);
}

void command_main() {
    while (1) {
        if (!uart_should_drop_rx) {
            fflush(stdout);
            putchar('\r');
            if (command_flags & COMMAND_NOTFOUND) {
                put_serial_modifier("\x1b[31m");
            }
            iprintf("pongoOS> ");
            fflush(stdout);
            if (command_flags & COMMAND_NOTFOUND) {
                put_serial_modifier("\x1b[0m");
                command_flags &= ~COMMAND_NOTFOUND;
            }
        }
        fflush(stdout);
        event_fire(&command_handler_iter);
        command_handler_ready = 1;
        command_in_progress = 0;
        fgets(command_buffer,512,stdin);
        command_in_progress = 1;
        char* cmd_end = command_buffer + strlen(command_buffer);
        while (cmd_end != command_buffer) {
            cmd_end --;
            if (cmd_end[0] == '\n' || cmd_end[0] == '\r')
                cmd_end[0] = 0;
        }
        command_execute(command_buffer);
    }
}

void help(const char * cmd, char* arg) {
    lock_take(&command_lock);
    for (int i=0; i<64; i++) {
        if (commands[i].name && !commands[i].hidden) {
            iprintf("%16s | %s\n", commands[i].name, commands[i].desc ? commands[i].desc : "no description");
        }
    }
    lock_release(&command_lock);
}

void dump_system_regs() {
    lock_take(&command_lock);

    iprintf("hello there 123 123 testing\n");

    unsigned long long buf;

    iprintf("-------- Feature registers --------\n");

    asm volatile ("mrs %0, ID_AA64ISAR0_EL1" : "=r"(buf) ::);
    iprintf("1. ID_AA64ISAR0_EL1: 0x%llx\n", buf);

    asm volatile ("mrs %0, ID_AA64PFR0_EL1" : "=r"(buf) ::);
    iprintf("2. ID_AA64PFR0_EL1: 0x%llx\n", buf);

    asm volatile ("mrs %0, ID_AA64PFR1_EL1" : "=r"(buf) ::);
    iprintf("3. ID_AA64PFR1_EL1: 0x%llx\n", buf);

    asm volatile ("mrs %0, MIDR_EL1" : "=r"(buf) ::);
    iprintf("4. MIDR_EL1: 0x%llx\n", buf);

    asm volatile ("mrs %0, ID_AA64ISAR1_EL1" : "=r"(buf) ::);
    iprintf("5. ID_AA64ISAR1_EL1: 0x%llx\n", buf);

    asm volatile ("mrs %0, ID_AA64MMFR0_EL1" : "=r"(buf) ::);
    iprintf("6. ID_AA64MMFR0_EL1: 0x%llx\n", buf);

    asm volatile ("mrs %0, ID_AA64MMFR2_EL1" : "=r"(buf) ::);
    iprintf("7. ID_AA64MMFR2_EL1: 0x%llx\n", buf);

    //apple clang doesnt like it probably because armv8.0 has no business having sve lol
    // asm volatile ("mrs %0, ID_AA64ZFR0_EL1" : "=r"(buf) ::);
    // iprintf("8. ID_AA64ZFR0_EL1: %llx\n", buf);


    iprintf("-------- Other regsiters --------\n");

    asm volatile ("mrs %0, CNTFRQ_EL0" : "=r"(buf) ::);
    iprintf("CNTFRQ_EL0: 0x%llx\n", buf);

    asm volatile ("mrs %0, CurrentEL" : "=r"(buf) ::);
    iprintf("CurrentEL [2:3]: 0x%llx\n", buf >> 2);

    asm volatile ("mrs %0, CLIDR_EL1" : "=r"(buf) ::);
    iprintf("CLIDR_EL1: 0x%llx\n", buf);

    lock_release(&command_lock);
}

void fix_a7() {
    __asm__ volatile(
        // "unlock the core for debugging"
        "msr OSLAR_EL1, xzr\n"

            //good
            "mrs x28, S3_0_C15_C4_0\n"
            "and x28, x28, #0xfffffffffffff7ff\n" // ~ARM64_REG_HID4_DisDcMVAOps
            "msr S3_0_C15_C4_0, x28\n"
            "isb sy\n"
#if 0
            //cyclone is so baaaaaaad
            "dsb sy\n"

            "mov x0, xzr\n"
            "mov x1, 0x10000\n"
            "mov     x28, #0x3f\n"
            "and     x1, x0, x28\n"
            "bic     x0, x0, x28\n"
            "add     x3, x3, x1\n"
            "sub     x3, x3, #0x1\n"
            "lsr     x3, x3, #6\n"
            "dsb     sy\n"

            // "L_cpcdr_loop:\n"
            // "dc      civac, x0\n"
            // "add     x0, x0, #0x40\n"
            // "dc      civac, x0\n"
            // "add     x0, x0, #0x40\n"
            // "dc      civac, x0\n"
            // "add     x0, x0, #0x40\n"
            // "dc      civac, x0\n"
            // "add     x0, x0, #0x40\n"
            // "dc      civac, x0\n"
            // "add     x0, x0, #0x40\n"
            // "dc      civac, x0\n"
            // "add     x0, x0, #0x40\n"
            
            // "b.pl    L_cpcdr_loop\n"
            // "dsb sy\n"
            // "isb sy\n"
#endif
            //surely bad on its own
            "mrs    x28, S3_0_C15_C4_0\n"
            // "orr    x28, x28, #0x800\n" //ARM64_REG_HID4_DisDcMVAOps this makes it go haywire lol //or not? //or most of the time?
            "orr    x28, x28, #0x100000000000\n" //ARM64_REG_HID4_DisDcSWL2Ops
            
            // "orr    x28, x28, #0x100000000800\n" //or'd ARM64_REG_HID4_DisDcSWL2Ops | ARM64_REG_HID4_DisDcMVAOps
            "msr    S3_0_C15_C4_0, x28\n"
            "isb    sy\n"

        /* Cyclone / typhoon specific init thing */
            "mrs     x28, S3_0_C15_C0_0\n"
            "orr     x28, x28, #0x100000\n"//ARM64_REG_HID0_LoopBuffDisb
            "msr     S3_0_C15_C0_0, x28\n"

            "mrs     x28, S3_0_C15_C1_0\n"
            "orr     x28, x28, #0x1000000\n"//ARM64_REG_HID1_rccDisStallInactiveIexCtl
            "orr     x28, x28, #0x2000000\n"//ARM64_REG_HID1_disLspFlushWithContextSwitch
            "msr     S3_0_C15_C1_0, x28\n"

            "mrs     x28, S3_0_C15_C3_0\n"
            "orr     x28, x28, #0x40000000000000\n"//ARM64_REG_HID3_DisXmonSnpEvictTriggerL2StarvationMode
            "msr     S3_0_C15_C3_0, x28\n"

            "mrs     x28, S3_0_C15_C5_0\n"
            "and     x28, x28, #0xffffefffffffffff\n" //(~ARM64_REG_HID5_DisHwpLd)
            "and     x28, x28, #0xffffdfffffffffff\n"//(~ARM64_REG_HID5_DisHwpSt)
            "msr     S3_0_C15_C5_0, x28\n"

            "mrs     x28, S3_0_C15_C8_0\n"
            "orr     x28, x28, #0xff0\n" // ARM64_REG_HID8_DataSetID0_VALUE | ARM64_REG_HID8_DataSetID1_VALUE
            "msr     S3_0_C15_C8_0, x28\n"
        /* Cyclone / typhoon specific init thing end */


        /* CPU1 Stuck in WFIWT Because of MMU Prefetch */
            "mrs     x28, S3_0_C15_C2_0\n"
            "orr     x28, x28, #0x2000\n" //ARM64_REG_HID2_disMMUmtlbPrefetch
            "msr     S3_0_C15_C2_0, x28\n"
            "dsb     sy\n"
            "isb\n"
        /* CPU1 Stuck in WFIWT Because of MMU Prefetch end */


        /* Enable deep sleep (for cpus without __ARM_GLOBAL_SLEEP_BIT__) */
        // NOTE: is deep sleep poweroff on wfi?
//            "mov     x28, #0x1000000\n"
  //          "msr     S3_5_C15_C4_0, x28\n"
        /* Enable deep sleep (for cpus without __ARM_GLOBAL_SLEEP_BIT__) end*/

        /* Set "OK to power down" */
//            "mrs     x28, S3_5_C15_C5_0\n"
  //          "orr     x28, x28, #0x3000000\n"
    //        "msr     S3_5_C15_C5_0, x28\n"
      //      "dsb     sy\n"
        //    "isb\n"
        /* Set "OK to power down" end */


        /* ARM64_REG_HID1_disLspFlushWithContextSwitch */
            "mrs     x28, S3_5_C15_C5_0\n"
            "bic     x28, x28, #0x3000000\n"
            "orr     x28, x28, #0x2000000\n"
            "msr     S3_5_C15_C5_0, x0\n"
        /* ARM64_REG_HID1_disLspFlushWithContextSwitch end */


        /* ARM64_REG_HID2_disMMUmtlbPrefetch */
            "mrs     x28, S3_0_C15_C2_0\n"
            "orr     x28, x28, #0x2000\n"
            "msr     S3_0_C15_C2_0, x28\n"
            "dsb     sy\n"
            "isb\n"
        /* ARM64_REG_HID2_disMMUmtlbPrefetch end */

	/* dont die in wfi kthx */
            "mrs     x28, S3_5_c15_c5_0\n"
            "orr     x28, x28, #(1<<13)\n"
            "msr     S3_5_c15_c5_0, x28\n"
    );
}

void command_init() {
    command_task = task_create("command", command_main);
    command_task->flags |= TASK_RESTART_ON_EXIT;
    command_task->flags &= ~TASK_CAN_EXIT;
    command_register("help", "shows this help message", help);
    command_register("dump", "dumps various system registers", dump_system_regs);
    command_register("fix", "tries to fix a7..", fix_a7);
}
