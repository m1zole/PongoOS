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
 //thanks @kok3shidoll
#include <errno.h>
#include <fcntl.h>              // open
#include <pthread.h>
#include <bthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>             // exit, strtoull
#include <string.h>             // strlen, strerror, memcpy, memmove
#include <unistd.h>             // close
#include <wordexp.h>
#include <sys/mman.h>           // mmap, munmap
#include <sys/stat.h>           // fstst
#include <getopt.h>

#include "headers/kpf.h"
#include "headers/ramdisk.h"
#include "headers/overlay.h"
#include "headers/legacy_kpf.h"
#include "headers/legacy_ramdisk.h"

#define checkrain_option_none               0x00000000
// KPF options
#define checkrain_option_verbose_boot       (1 << 0)

// Global options
#define checkrain_option_safemode           (1 << 0)

static char* bootArgs = NULL;
static uint32_t kpf_flags = checkrain_option_none;
static uint32_t checkra1n_flags = checkrain_option_none;

enum AUTOBOOT_STAGE {
    NONE,
    SETUP_STAGE_FUSE,
    SETUP_STAGE_SEP,
    SEND_STAGE_KPF,
    SETUP_STAGE_KPF,
    SEND_STAGE_RAMDISK,
    SETUP_STAGE_RAMDISK,
    SEND_STAGE_OVERLAY,
    SETUP_STAGE_OVERLAY,
    SETUP_STAGE_KPF_FLAGS,
    SETUP_STAGE_CHECKRAIN_FLAGS,
    SETUP_STAGE_XARGS,
    BOOTUP_STAGE,
    USB_TRANSFER_ERROR,
};

enum AUTOBOOT_STAGE CURRENT_STAGE = NONE;

int use_termux = 0;
int use_legacy = 0;
int use_safemode = 0;
int use_verbose_boot = 0;

#define LOG(fmt, ...) do { fprintf(stderr, "\x1b[1;96m" fmt "\x1b[0m\n", ##__VA_ARGS__); } while(0)
#define ERR(fmt, ...) do { fprintf(stderr, "\x1b[1;91m" fmt "\x1b[0m\n", ##__VA_ARGS__); } while(0)

// Keep in sync with Pongo
#define PONGO_USB_VENDOR    0x05ac
#define PONGO_USB_PRODUCT   0x4141
#define CMD_LEN_MAX         512
#define UPLOADSZ_MAX        (1024 * 1024 * 128)

static uint8_t gBlockIO = 1;

typedef struct stuff stuff_t;

static void io_start(stuff_t *stuff);
static void io_stop(stuff_t *stuff);

/********** ********** ********** ********** **********
 * Platform-specific code must define:
 * - usb_ret_t
 * - usb_device_handle_t
 * - USB_RET_SUCCESS
 * - USB_RET_NOT_RESPONDING
 * - usb_strerror
 * - struct stuff, which must contain the fields "handle"
 *   and "th", but may contain more than just that.
 * - USBControlTransfer
 * - USBBulkUpload
 * - pongoterm_main
 ********** ********** ********** ********** **********/

#ifdef USE_LIBUSB

#include <libusb-1.0/libusb.h>

typedef int usb_ret_t;
typedef libusb_device_handle *usb_device_handle_t;

#define USB_RET_SUCCESS         LIBUSB_SUCCESS
#define USB_RET_NOT_RESPONDING  LIBUSB_ERROR_OTHER

static inline const char *usb_strerror(usb_ret_t err)
{
    return libusb_error_name(err);
}

static usb_ret_t USBControlTransfer(usb_device_handle_t handle, uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint32_t wLength, void *data, uint32_t *wLenDone)
{
    usb_ret_t r = libusb_control_transfer(handle, bmRequestType, bRequest, wValue, wIndex, data, wLength, 0);
    if(r < 0) return r;
    if(wLenDone) *wLenDone = r;
    return USB_RET_SUCCESS;
}

static usb_ret_t USBBulkUpload(usb_device_handle_t handle, void *data, uint32_t len)
{
    static uint32_t maxLen = 0;
    int transferred = 0;
    usb_ret_t r;
    if(maxLen == 0)
    {
        r = libusb_bulk_transfer(handle, 2, data, len, &transferred, 0);
        if(r == LIBUSB_SUCCESS)
        {
            return transferred == len ? USB_RET_SUCCESS : LIBUSB_ERROR_INTERRUPTED;
        }
        else if(r != LIBUSB_ERROR_NO_MEM)
        {
            return r;
        }
        // We only get here on ENOMEM
        FILE *f = fopen("/sys/module/usbcore/parameters/usbfs_memory_mb", "r");
        if(f)
        {
            char str[32]; // More than enough to hold a uint64 in decimal
            size_t s = fread(str, 1, sizeof(str), f);
            fclose(f);
            if(s == 0 || s >= sizeof(str)) return r;
            str[s] = '\0';
            char *end = NULL;
            unsigned long long max = strtoull(str, &end, 0);
            // Using the limit as-is will lead to ENOMEM, so we multiply
            // by half a MB and impose an appropriate max value.
            if(*end == '\n') ++end;
            if(*end != '\0' || max == 0 || max >= 0x2000) return r;
            maxLen = (uint32_t)(max << 19);
        }
        else
        {
            // Just 8MB by default?
            maxLen = 0x800000;
        }
    }
    // If we get here, we have to chunk our data
    for(uint32_t done = transferred; done < len; )
    {
        uint32_t chunk = len - done;
        if(chunk > maxLen) chunk = maxLen;
        transferred = 0;
        r = libusb_bulk_transfer(handle, 2, (unsigned char*)data + done, chunk, &transferred, 0);
        done += transferred;
        if(r == LIBUSB_SUCCESS) continue;
        if(r != LIBUSB_ERROR_NO_MEM || maxLen <= 0x40) return r;
        maxLen /= 2;
    }
    return LIBUSB_SUCCESS;
}

struct stuff
{
    pthread_t th;
    libusb_device *dev;
    usb_device_handle_t handle;
};

static int FoundDevice(libusb_context *ctx, libusb_device *dev, libusb_hotplug_event event, void *arg)
{
    stuff_t *stuff = arg;
    if(stuff->handle)
    {
        return LIBUSB_SUCCESS;
    }

    libusb_device_handle *handle;
    int r = libusb_open(dev, &handle);
    if(r != LIBUSB_SUCCESS)
    {
        ERR("libusb_open: %s", libusb_error_name(r));
        return r;
    }

    r = libusb_detach_kernel_driver(handle, 0);
    if(r != LIBUSB_SUCCESS && r != LIBUSB_ERROR_NOT_FOUND)
    {
        ERR("libusb_detach_kernel_driver: %s", libusb_error_name(r));
        return r;
    }

    r = libusb_set_configuration(handle, 1);
    if(r != LIBUSB_SUCCESS)
    {
        ERR("libusb_set_configuration: %s", libusb_error_name(r));
        return r;
    }

    r = libusb_claim_interface(handle, 0);
    if(r != LIBUSB_SUCCESS)
    {
        ERR("libusb_claim_interface: %s", libusb_error_name(r));
        return r;
    }

    stuff->dev = dev;
    stuff->handle = handle;
    io_start(stuff);

    return LIBUSB_SUCCESS;
}

static int LostDevice(libusb_context *ctx, libusb_device *dev, libusb_hotplug_event event, void *arg)
{
    stuff_t *stuff = arg;
    if(stuff->dev != dev)
    {
        return LIBUSB_SUCCESS;
    }

    io_stop(stuff);
    libusb_close(stuff->handle);
    stuff->handle = NULL;
    stuff->dev = NULL;

    return LIBUSB_SUCCESS;
}

static int pongoterm_main(void)
{
    stuff_t stuff = {};
    libusb_hotplug_callback_handle hp[2];

    int r = libusb_init(NULL);
    if(r != LIBUSB_SUCCESS)
    {
        ERR("libusb_init: %s", libusb_error_name(r));
        return -1;
    }

    if(!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG))
    {
        ERR("libusb: no hotplug capability");
        libusb_exit(NULL);
        return -1;
    }

    r = libusb_hotplug_register_callback(NULL, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED, 0, PONGO_USB_VENDOR, PONGO_USB_PRODUCT, LIBUSB_HOTPLUG_MATCH_ANY, FoundDevice, &stuff, &hp[0]);
    if(r != LIBUSB_SUCCESS)
    {
        ERR("libusb_hotplug: %s", libusb_error_name(r));
        libusb_exit(NULL);
        return -1;
    }

    r = libusb_hotplug_register_callback(NULL, LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, 0, PONGO_USB_VENDOR, PONGO_USB_PRODUCT, LIBUSB_HOTPLUG_MATCH_ANY, LostDevice, &stuff, &hp[1]);
    if(r != LIBUSB_SUCCESS)
    {
        ERR("libusb_hotplug: %s", libusb_error_name(r));
        libusb_exit(NULL);
        return -1;
    }

    libusb_device **list;
    ssize_t sz = libusb_get_device_list(NULL, &list);
    if(sz < 0)
    {
        ERR("libusb_get_device_list: %s", libusb_error_name((int)sz));
        libusb_exit(NULL);
        return -1;
    }

    for(size_t i = 0; i < sz; ++i)
    {
        struct libusb_device_descriptor desc = {};
        r = libusb_get_device_descriptor(list[i], &desc);
        if(r != LIBUSB_SUCCESS)
        {
            ERR("libusb_get_device_descriptor: %s", libusb_error_name(r));
            // continue anyway
        }
        if(desc.idVendor != PONGO_USB_VENDOR || desc.idProduct != PONGO_USB_PRODUCT)
        {
            libusb_unref_device(list[i]);
            continue;
        }
        r = FoundDevice(NULL, list[i], LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED, &stuff);
        for(size_t j = i + 1; j < sz; ++j)
        {
            libusb_unref_device(list[j]);
        }
        if(r != LIBUSB_SUCCESS)
        {
            libusb_free_device_list(list, 0);
            libusb_exit(NULL);
            return -1;
        }
        break;
    }
    libusb_free_device_list(list, 0);

    while(1)
    {
        r = libusb_handle_events(NULL);
        if(r != LIBUSB_SUCCESS)
        {
            ERR("libusb_handle_events: %s", libusb_error_name(r));
            break;
        }
    }

    libusb_exit(NULL);
    return -1;
}

#elif defined(__APPLE__)

#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOCFPlugIn.h>

typedef IOReturn usb_ret_t;
typedef IOUSBInterfaceInterface245 **usb_device_handle_t;

#define USB_RET_SUCCESS         KERN_SUCCESS
#define USB_RET_NOT_RESPONDING  kIOReturnNotResponding

static inline const char *usb_strerror(usb_ret_t err)
{
    return mach_error_string(err);
}

static usb_ret_t USBControlTransfer(usb_device_handle_t handle, uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint32_t wLength, void *data, uint32_t *wLenDone)
{
    IOUSBDevRequest request =
    {
        .bmRequestType = bmRequestType,
        .bRequest = bRequest,
        .wValue = wValue,
        .wIndex = wIndex,
        .wLength = wLength,
        .pData = data,
    };
    usb_ret_t ret = (*handle)->ControlRequest(handle, 0, &request);
    if(wLenDone) *wLenDone = request.wLenDone;
    return ret;
}

static usb_ret_t USBBulkUpload(usb_device_handle_t handle, void *data, uint32_t len)
{
    return (*handle)->WritePipe(handle, 2, data, len);
}

struct stuff
{
    pthread_t th;
    volatile uint64_t regID;
    IOUSBDeviceInterface245 **dev;
    usb_device_handle_t handle;
};

static void FoundDevice(void *refCon, io_iterator_t it)
{
    stuff_t *stuff = refCon;
    if(stuff->regID)
    {
        return;
    }
    io_service_t usbDev = MACH_PORT_NULL;
    while((usbDev = IOIteratorNext(it)))
    {
        uint64_t regID;
        kern_return_t ret = IORegistryEntryGetRegistryEntryID(usbDev, &regID);
        if(ret != KERN_SUCCESS)
        {
            ERR("IORegistryEntryGetRegistryEntryID: %s", mach_error_string(ret));
            goto next;
        }
        SInt32 score = 0;
        IOCFPlugInInterface **plugin = NULL;
        ret = IOCreatePlugInInterfaceForService(usbDev, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
        if(ret != KERN_SUCCESS)
        {
            ERR("IOCreatePlugInInterfaceForService(usbDev): %s", mach_error_string(ret));
            goto next;
        }
        HRESULT result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (LPVOID*)&stuff->dev);
        (*plugin)->Release(plugin);
        if(result != 0)
        {
            ERR("QueryInterface(dev): 0x%x", result);
            goto next;
        }
        ret = (*stuff->dev)->USBDeviceOpenSeize(stuff->dev);
        if(ret != KERN_SUCCESS)
        {
            ERR("USBDeviceOpenSeize: %s", mach_error_string(ret));
        }
        else
        {
            ret = (*stuff->dev)->SetConfiguration(stuff->dev, 1);
            if(ret != KERN_SUCCESS)
            {
                ERR("SetConfiguration: %s", mach_error_string(ret));
            }
            else
            {
                IOUSBFindInterfaceRequest request =
                {
                    .bInterfaceClass = kIOUSBFindInterfaceDontCare,
                    .bInterfaceSubClass = kIOUSBFindInterfaceDontCare,
                    .bInterfaceProtocol = kIOUSBFindInterfaceDontCare,
                    .bAlternateSetting = kIOUSBFindInterfaceDontCare,
                };
                io_iterator_t iter = MACH_PORT_NULL;
                ret = (*stuff->dev)->CreateInterfaceIterator(stuff->dev, &request, &iter);
                if(ret != KERN_SUCCESS)
                {
                    ERR("CreateInterfaceIterator: %s", mach_error_string(ret));
                }
                else
                {
                    io_service_t usbIntf = MACH_PORT_NULL;
                    while((usbIntf = IOIteratorNext(iter)))
                    {
                        ret = IOCreatePlugInInterfaceForService(usbIntf, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
                        IOObjectRelease(usbIntf);
                        if(ret != KERN_SUCCESS)
                        {
                            ERR("IOCreatePlugInInterfaceForService(usbIntf): %s", mach_error_string(ret));
                            continue;
                        }
                        result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID), (LPVOID*)&stuff->handle);
                        (*plugin)->Release(plugin);
                        if(result != 0)
                        {
                            ERR("QueryInterface(intf): 0x%x", result);
                            continue;
                        }
                        ret = (*stuff->handle)->USBInterfaceOpen(stuff->handle);
                        if(ret != KERN_SUCCESS)
                        {
                            ERR("USBInterfaceOpen: %s", mach_error_string(ret));
                        }
                        else
                        {
                            io_start(stuff);
                            stuff->regID = regID;
                            while((usbIntf = IOIteratorNext(iter))) IOObjectRelease(usbIntf);
                            IOObjectRelease(iter);
                            while((usbDev = IOIteratorNext(it))) IOObjectRelease(usbDev);
                            IOObjectRelease(usbDev);
                            return;
                        }
                        (*stuff->handle)->Release(stuff->handle);
                        stuff->handle = NULL;
                    }
                    IOObjectRelease(iter);
                }
            }
        }

    next:;
        if(stuff->dev)
        {
            (*stuff->dev)->USBDeviceClose(stuff->dev);
            (*stuff->dev)->Release(stuff->dev);
            stuff->dev = NULL;
        }
        IOObjectRelease(usbDev);
    }
}

static void LostDevice(void *refCon, io_iterator_t it)
{
    stuff_t *stuff = refCon;
    io_service_t usbDev = MACH_PORT_NULL;
    while((usbDev = IOIteratorNext(it)))
    {
        uint64_t regID;
        kern_return_t ret = IORegistryEntryGetRegistryEntryID(usbDev, &regID);
        IOObjectRelease(usbDev);
        if(ret == KERN_SUCCESS && stuff->regID == regID)
        {
            io_stop(stuff);
            stuff->regID = 0;
            (*stuff->handle)->USBInterfaceClose(stuff->handle);
            (*stuff->handle)->Release(stuff->handle);
            (*stuff->dev)->USBDeviceClose(stuff->dev);
            (*stuff->dev)->Release(stuff->dev);
        }
    }
}

static int pongoterm_main(void)
{
    kern_return_t ret;
    stuff_t stuff = {};
    io_iterator_t found, lost;
    NSDictionary *dict =
    @{
        @"IOProviderClass": @"IOUSBDevice",
        @"idVendor":  @PONGO_USB_VENDOR,
        @"idProduct": @PONGO_USB_PRODUCT,
    };
    CFDictionaryRef cfdict = (__bridge CFDictionaryRef)dict;
    IONotificationPortRef notifyPort = IONotificationPortCreate(kIOMasterPortDefault);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(notifyPort), kCFRunLoopDefaultMode);

    CFRetain(cfdict);
    ret = IOServiceAddMatchingNotification(notifyPort, kIOFirstMatchNotification, cfdict, &FoundDevice, &stuff, &found);
    if(ret != KERN_SUCCESS)
    {
        ERR("IOServiceAddMatchingNotification: %s", mach_error_string(ret));
        return -1;
    }
    FoundDevice(&stuff, found);

    CFRetain(cfdict);
    ret = IOServiceAddMatchingNotification(notifyPort, kIOTerminatedNotification, cfdict, &LostDevice, &stuff, &lost);
    if(ret != KERN_SUCCESS)
    {
        ERR("IOServiceAddMatchingNotification: %s", mach_error_string(ret));
        return -1;
    }
    LostDevice(&stuff, lost);
    CFRunLoopRun();
    return -1;
}

#elif 0 /*defined(__linux__)*/

typedef int usb_ret_t;
typedef int usb_device_handle_t;

static usb_ret_t USBControlTransfer(usb_device_handle_t handle, uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint32_t wLength, void *data, uint32_t *wLenDone)
static usb_ret_t USBControlTransfer(usb_device_handle_t handle, uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint32_t wLength, void *data)
{
    struct usbdevfs_ctrltransfer transfer =
    {
        .bRequestType = bmRequestType,
        .bRequest = bRequest,
        .wValue = wValue,
        .wIndex = wIndex,
        .wLength = wLength,
        .data = data,
        .timeout = 0,
    };
    return ioctl(handle, USBDEVFS_CONTROL, &transfer);
}

static usb_ret_t USBBulkUpload(usb_device_handle_t handle, void *data, uint32_t len)
{
    struct usbdevfs_bulktransfer transfer =
    {
        .ep = 2,
        .len = len,
        .data = data,
        .timeout = 0,
    };
    return ioctl(handle, USBDEVFS_BULK, &transfer);
}

static int pongoterm_main(void)
{

}

#else
#   error "Unsupported target platform"
#endif /* LIBUSB || __APPLE__ || __linux__ */

static void write_stdout(char *buf, uint32_t len)
{
    while(len > 0)
    {
        ssize_t s = write(1, buf, len);
        if(s < 0)
        {
            ERR("write: %s", strerror(errno));
            exit(-1); // TODO: ok with libusb?
        }
        buf += s;
        len -= s;
    }
}

static void* io_main(void *arg)
{
    stuff_t *stuff = arg;
    int r = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    if(r != 0)
    {
        ERR("pthread_setcancelstate: %s", strerror(r));
        exit(-1); // TODO: ok with libusb?
    }
    LOG("[Connected]");
    usb_ret_t ret = USB_RET_SUCCESS;
    char prompt[64] = "> ";
    uint32_t plen = 2;
    while(1)
    {
        char buf[0x2000] = {};
        uint32_t outpos = 0;
        uint32_t outlen = 0;
        uint8_t in_progress = 1;
        while(in_progress)
        {
            ret = USBControlTransfer(stuff->handle, 0xa1, 2, 0, 0, (uint32_t)sizeof(in_progress), &in_progress, NULL);
            if(ret == USB_RET_SUCCESS)
            {
                ret = USBControlTransfer(stuff->handle, 0xa1, 1, 0, 0, 0x1000, buf + outpos, &outlen);
                if(ret == USB_RET_SUCCESS)
                {
                    write_stdout(buf + outpos, outlen);
                    outpos += outlen;
                    if(outpos > 0x1000)
                    {
                        memmove(buf, buf + outpos - 0x1000, 0x1000);
                        outpos = 0x1000;
                    }
                }
            }
            if(ret != USB_RET_SUCCESS)
            {
                goto bad;
            }
        }
        if(outpos > 0)
        {
            // Record prompt
            uint32_t start = outpos;
            for(uint32_t end = outpos > 64 ? outpos - 64 : 0; start > end; --start)
            {
                if(buf[start-1] == '\n')
                {
                    break;
                }
            }
            plen = outpos - start;
            memcpy(prompt, buf + start, plen);
        }
        else
        {
            // Re-emit prompt
            write_stdout(prompt, plen);
        }
        ret = USBControlTransfer(stuff->handle, 0x21, 4, 0xffff, 0, 0, NULL, NULL);
        if(ret != USB_RET_SUCCESS)
        {
            goto bad;
        }
        r = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        if(r != 0)
        {
            ERR("pthread_setcancelstate: %s", strerror(r));
            exit(-1); // TODO: ok with libusb?
        }
        size_t len = 0;
        while(1)
        {

            if(use_termux)
            {
                break;
            }

            char ch;
            ssize_t s = read(0, &ch, 1);
            if(s == 0)
            {
                break;
            }
            if(s < 0)
            {
                if(errno == EINTR)
                {
                    return NULL;
                }
                ERR("read: %s", strerror(errno));
                exit(-1); // TODO: ok with libusb?
            }
            if(len < sizeof(buf))
            {
                buf[len] = ch;
            }
            ++len;
            if(ch == '\n')
            {
                break;
            }
        }
        r = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        if(r != 0)
        {
            ERR("pthread_setcancelstate: %s", strerror(r));
            exit(-1); // TODO: ok with libusb?
        }
        if(len == 0)
        {
            if(use_termux)
            {
                
                {
                    if(CURRENT_STAGE == NONE)
                        CURRENT_STAGE = SETUP_STAGE_FUSE;
                    
                    if(CURRENT_STAGE == SETUP_STAGE_FUSE)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("fuse lock\n")), "fuse lock\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "fuse lock");
                            CURRENT_STAGE = SETUP_STAGE_SEP;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_SEP)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("sep auto\n")), "sep auto\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "sep auto");
                            CURRENT_STAGE = SEND_STAGE_KPF;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SEND_STAGE_KPF)
                    {
                        unsigned char *load_kpf;
                        unsigned int load_kpf_len;
                        if(use_legacy){
                            load_kpf = legacy_kpf;
                            load_kpf_len = legacy_kpf_len;
                        } else{
                            load_kpf = kpf;
                            load_kpf_len = kpf_len;
                        }
                        size_t size = load_kpf_len;
                        ret = USBControlTransfer(stuff->handle, 0x21, 1, 0, 0, 4, &size, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            ret = USBBulkUpload(stuff->handle, load_kpf, load_kpf_len);
                            if(ret == USB_RET_SUCCESS)
                            {
                                LOG("/send %s\n%s: %llu bytes", "kpf", "kpf", (unsigned long long)load_kpf_len);
                                CURRENT_STAGE = SETUP_STAGE_KPF;
                            }
                            else
                            {
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                            }
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_KPF)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("modload\n")), "modload\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "modload");
                            CURRENT_STAGE = SEND_STAGE_RAMDISK;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SEND_STAGE_RAMDISK)
                    {
                        unsigned char *load_ramdisk;
                        unsigned int load_ramdisk_len;
                        if(use_legacy){
                            load_ramdisk = legacy_ramdisk;
                            load_ramdisk_len = legacy_ramdisk_len;
                        } else{
                            load_ramdisk = ramdisk_dmg;
                            load_ramdisk_len = ramdisk_dmg_len;
                        }
                        size_t size = load_ramdisk_len;
                        ret = USBControlTransfer(stuff->handle, 0x21, 1, 0, 0, 4, &size, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            ret = USBBulkUpload(stuff->handle, load_ramdisk, load_ramdisk_len);
                            if(ret == USB_RET_SUCCESS)
                            {
                                LOG("/send %s\n%s: %llu bytes", "ramdisk", "ramdisk", (unsigned long long)load_ramdisk_len);
                                CURRENT_STAGE = SETUP_STAGE_RAMDISK;
                            }
                            else
                            {
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                            }
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_RAMDISK)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("ramdisk\n")), "ramdisk\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "ramdisk");
                            if(use_legacy){
                                CURRENT_STAGE = SETUP_STAGE_KPF_FLAGS;
                            } else{
                                CURRENT_STAGE = SEND_STAGE_OVERLAY;
                            }
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SEND_STAGE_OVERLAY)
                    {
                        size_t size = overlay_dmg_len;
                        ret = USBControlTransfer(stuff->handle, 0x21, 1, 0, 0, 4, &size, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            ret = USBBulkUpload(stuff->handle, overlay_dmg, overlay_dmg_len);
                            if(ret == USB_RET_SUCCESS)
                            {
                                LOG("/send %s\n%s: %llu bytes", "overlay", "overlay", (unsigned long long)overlay_dmg_len);
                                CURRENT_STAGE = SETUP_STAGE_OVERLAY;
                            }
                            else
                            {
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                            }
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_OVERLAY)
                    {
                        
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("overlay\n")), "overlay\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "overlay");
                            CURRENT_STAGE = SETUP_STAGE_KPF_FLAGS;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_KPF_FLAGS)
                    {
                        
                        if(use_verbose_boot)
                        {
                            kpf_flags |= checkrain_option_verbose_boot;
                        }
                        
                        char str[64];
                        memset(&str, 0x0, 64);
                        sprintf(str, "kpf_flags 0x%08x\n", kpf_flags);
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen(str)), str, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            memset(&str, 0x0, 64);
                            sprintf(str, "kpf_flags 0x%08x", kpf_flags);
                            LOG("%s", str);
                            CURRENT_STAGE = SETUP_STAGE_CHECKRAIN_FLAGS;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_CHECKRAIN_FLAGS)
                    {
                        if(use_safemode)
                        {
                            checkra1n_flags |= checkrain_option_safemode;
                        }
                        
                        char str[64];
                        memset(&str, 0x0, 64);
                        sprintf(str, "checkra1n_flags 0x%08x\n", checkra1n_flags);
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen(str)), str, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            memset(&str, 0x0, 64);
                            sprintf(str, "checkra1n_flags 0x%08x", checkra1n_flags);
                            LOG("%s", str);
                            CURRENT_STAGE = SETUP_STAGE_XARGS;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    
                    if(CURRENT_STAGE == SETUP_STAGE_XARGS)
                    {
                        char str[256];
                        memset(&str, 0x0, 256);
                        
                        char* defaultBootArgs = NULL;
                        
                        defaultBootArgs = "rootdev=md0";
                        
                        if(defaultBootArgs)
                        {
                            if(strlen(defaultBootArgs) > 256) {
                                ERR("defaultBootArgs is too large!");
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                                continue;
                            }
                            sprintf(str, "%s", defaultBootArgs);
                        }
                        
                        if(bootArgs)
                        {
                            // sprintf(str, "xargs %s\n", bootArgs);
                            if((strlen(str) + strlen(bootArgs)) > 256) {
                                ERR("bootArgs is too large!");
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                                continue;
                            }
                            sprintf(str, "%s %s", str, bootArgs);
                        }
                        
                        if(use_verbose_boot)
                        {
                            if((strlen(str) + sizeof("-v")) > 256) {
                                ERR("bootArgs is too large!");
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                                continue;
                            }
                            sprintf(str, "%s %s", str, "-v");
                        }
                        
                        
                        char xstr[256 + 7];
                        memset(&xstr, 0x0, 256 + 7);
                        sprintf(xstr, "xargs %s\n", str);
                        
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen(xstr)), xstr, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", str);
                            CURRENT_STAGE = BOOTUP_STAGE;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == BOOTUP_STAGE)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("bootx\n")), "bootx\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "bootx");
                            exit(0);
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == USB_TRANSFER_ERROR)
                    {
                        ERR("WTF?!");
                        exit(-1);
                    }
                }
            }

            exit(0); // TODO: ok with libusb?
        }
        if(len > sizeof(buf))
        {
            ERR("Discarding command of >%zu chars", sizeof(buf));
            continue;
        }
        if(buf[0] == '/')
        {
            buf[len-1] = '\0';
            wordexp_t we;
            r = wordexp(buf + 1, &we, WRDE_SHOWERR | WRDE_UNDEF);
            if(r != 0)
            {
                ERR("wordexp: %d", r);
                continue;
            }
            bool show_help = false;
            if(we.we_wordc == 0)
            {
                show_help = true;
            }
            else if(strcmp(we.we_wordv[0], "send") == 0)
            {
                if(we.we_wordc == 1)
                {
                    LOG("Usage: /send [file]");
                    LOG("Upload a file to PongoOS. This should be followed by a command such as \"modload\".");
                }
                else
                {
                    int fd = open(we.we_wordv[1], O_RDONLY);
                    if(fd < 0)
                    {
                        ERR("Failed to open file: %s", strerror(errno));
                    }
                    else
                    {
                        struct stat s;
                        r = fstat(fd, &s);
                        if(r != 0)
                        {
                            ERR("Failed to stat file: %s", strerror(errno));
                        }
                        else
                        {
                            void *addr = mmap(NULL, s.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
                            if(addr == MAP_FAILED)
                            {
                                ERR("Failed to map file: %s", strerror(errno));
                            }
                            else
                            {
                                uint32_t newsz = s.st_size;
                                ret = USBControlTransfer(stuff->handle, 0x21, 1, 0, 0, 4, &newsz, NULL);
                                if(ret == USB_RET_SUCCESS)
                                {
                                    ret = USBBulkUpload(stuff->handle, addr, s.st_size);
                                    if(ret == USB_RET_SUCCESS)
                                    {
                                        LOG("Uploaded %llu bytes", (unsigned long long)s.st_size);
                                    }
                                }
                                munmap(addr, s.st_size);
                            }
                        }
                        close(fd);
                    }
                }
            }
            else
            {
                ERR("Unrecognised command: /%s", we.we_wordv[0]);
                show_help = true;
            }
            if(show_help)
            {
                LOG("Available commands:");
                LOG("/send [file] - Upload a file to PongoOS");
            }
            wordfree(&we);
        }
        else
        {
            if(len > CMD_LEN_MAX)
            {
                ERR("PongoOS currently only supports commands with %u characters or less", CMD_LEN_MAX);
                continue;
            }
            if(gBlockIO)
            {
                ret = USBControlTransfer(stuff->handle, 0x21, 4, 1, 0, 0, NULL, NULL);
            }
            if(ret == USB_RET_SUCCESS)
            {
                ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)len, buf, NULL);
            }
        }
        if(ret != USB_RET_SUCCESS)
        {
            goto bad;
        }
    }
bad:;
    if(ret == USB_RET_NOT_RESPONDING)
    {
        return NULL;
    }
    ERR("USB error: %s", usb_strerror(ret));
    exit(-1); // TODO: ok with libusb?
}

static void io_start(stuff_t *stuff)
{
    int r = pthread_create(&stuff->th, NULL, &io_main, stuff);
    if(r != 0)
    {
        ERR("pthread_create: %s", strerror(r));
        exit(-1); // TODO: ok with libusb?
    }
}

static void io_stop(stuff_t *stuff)
{
    LOG("[Disconnected]");
    int r = pthread_cancel(stuff->th);
    if(r != 0)
    {
        ERR("pthread_cancel: %s", strerror(r));
        exit(-1); // TODO: ok with libusb?
    }
    r = pthread_join(stuff->th, NULL);
    if(r != 0)
    {
        ERR("pthread_join: %s", strerror(r));
        exit(-1); // TODO: ok with libusb?
    }
}

void usage(const char* s)
{
    printf("Usage: %s [-ahsv] [-e <boot-args>]\n", s);
    printf("\t-h, --help\t\t\t: show usage\n");
    printf("\t-a, --autoboot\t\t\t: enable bakera1n boot mode\n");
    printf("\t-e, --extra-bootargs <args>\t: replace bootargs\n");
    printf("\t-s, --safemode\t\t\t: enable safe mode\n");
    printf("\t-v, --verbose-boot\t\t: enable verbose boot\n");
    
    return;
}

int main(int argc, const char **argv)
{
       if(argc < 2)
    {
        usage(argv[0]);
        return -1;
    }
    
    int opt = 0;
    static struct option longopts[] = {
        { "help",               no_argument,       NULL, 'h' },
        { "termux",             no_argument,       NULL, 'a' },
        { "legacy",             no_argument,       NULL, 'l' },
        { "extra-bootargs",     required_argument, NULL, 'e' },
        { "safemode",           no_argument,       NULL, 's' },
        { "verbose-boot",       no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 }
    };
    
    while ((opt = getopt_long(argc, argv, "alhe:sv", longopts, NULL)) > 0) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                return 0;
                
            case 'a':
                use_termux = 1;
                LOG("selected: autoboot mode");
                break;
                
            case 'e':
                if (optarg) {
                    bootArgs = strdup(optarg);
                    LOG("set bootArgs: [%s]", bootArgs);
                }
                break;
            
            case 'l':
                use_legacy = 1;
                break;

            case 's':
                use_safemode = 1;
                break;
                
            case 'v':
                use_verbose_boot = 1;
                break;
                
            default:
                usage(argv[0]);
                return -1;
        }
    }
    return pongoterm_main();
}
