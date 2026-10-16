#!/usr/bin/env python3
"""Exercise the real NT36672C IRQ path with host-side SPI/input shims."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "drivers/input/touchscreen/NT36672C/nt36xxx.c"
MT = ROOT / "drivers/input/input-mt.c"
MT_HEADER = ROOT / "include/linux/input/mt.h"


def function(source, name, required=True):
    match = re.search(
        r"(?m)^(?:(?:static|inline)\s+)*[A-Za-z_]\w*\s+"
        + re.escape(name) + r"\([^;{}]*?\)\s*\{", source)
    if not match:
        if required:
            raise ValueError("Function definition not found: " + name)
        return ""
    depth = 1
    end = match.end()
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


def run():
    source = DRIVER.read_text()
    mt = MT.read_text()
    header = MT_HEADER.read_text()
    irq = function(source, "nvt_ts_work_func")
    helpers = "\n".join(function(source, name) for name in (
        "nvt_fw_recovery", "nvt_wdt_fw_recovery", "nvt_ts_point_data_checksum"))
    helpers += function(source, "nvt_check_palm", required=False)
    mt_helpers = "\n".join(function(header, name) for name in (
        "input_mt_get_value", "input_mt_new_trkid", "input_mt_slot"))
    mt_helpers += function(mt, "input_mt_report_slot_state")
    nvt_header = (ROOT / "include/touch/nova36672c/nt36xxx.h").read_text()
    protocol = "\n".join(re.search(r"(?m)^#define\s+" + name + r"\s+[^\n]+", text)[0]
                         for name, text in (("DATA_PROTOCOL", source),
                                            ("FUNCPAGE_PALM", nvt_header))) + "\n"

    shim = r'''
#include <linux/input.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ABS_MT_FIRST ABS_MT_TOUCH_MAJOR
#define ABS_MT_LAST ABS_MT_TOOL_Y
#define TRKID_MAX 0xffff
#define WAKEUP_GESTURE 1
#define NVT_TOUCH_WDT_RECOVERY 1
#define NVT_TOUCH_ESD_PROTECT 0
#define POINT_DATA_CHECKSUM 1
#define POINT_DATA_CHECKSUM_LEN 65
#define POINT_DATA_LEN 65
#define PEN_DATA_LEN 14
#define DUMMY_BYTES 1
#define CHECK_PEN_DATA_CHECKSUM 0
#define MT_PROTOCOL_B 1
#define TOUCH_MAX_FINGER_NUM 10
#define TOUCH_KEY_NUM 0
#define TOUCH_FORCE_NUM 1000
#define NVT_LOG(...) ((void)0)
#define NVT_ERR(...) ((void)0)
#define likely(x) (x)
#define unlikely(x) (x)
#define IRQ_HANDLED 1
#define mutex_lock(p) ((void)(p))
#define mutex_unlock(p) ((void)(p))
typedef int irqreturn_t;
struct input_mt_slot { int abs[ABS_MT_LAST-ABS_MT_FIRST+1]; unsigned frame; };
struct input_mt { int trkid,slot; unsigned frame; struct input_mt_slot slots[10]; };
struct input_dev {
    struct input_mt *mt;
    int dev,abs[ABS_CNT],keys[KEY_CNT];
    unsigned syncs;
};
static struct input_mt mt_state;
static struct input_dev input_dev = { .mt=&mt_state };
static struct input_dev pen_input_dev;
static struct {
    struct input_dev *input_dev,*pen_input_dev;
    void *client;
    int lock,max_touch_num;
    bool pen_support,gesture_enabled;
} state = { .input_dev=&input_dev, .pen_input_dev=&pen_input_dev, .max_touch_num=10 }, *ts=&state;
static struct { char *BOOT_UPDATE_FIRMWARE_NAME; } parnel = { "test" };
static uint8_t recovery_cnt, bTouchIsAwake=1;
static const uint8_t *spi_packet;
static int spi_result,button;
static unsigned sync_count;
static void input_event(struct input_dev *dev,unsigned type,unsigned code,int value) {
    if(type==EV_ABS) {
        if(code==ABS_MT_SLOT) dev->mt->slot=value;
        else if(code>=ABS_MT_FIRST&&code<=ABS_MT_LAST)
            dev->mt->slots[dev->mt->slot].abs[code-ABS_MT_FIRST]=value;
        else dev->abs[code]=value;
    } else if(type==EV_KEY) {
        dev->keys[code]=value;
        if(dev==&input_dev&&code==BTN_TOUCH) button=value;
    }
}
static void input_report_abs(struct input_dev *dev,unsigned code,int value) {
    input_event(dev,EV_ABS,code,value);
}
static void input_report_key(struct input_dev *dev,unsigned code,int value) {
    input_event(dev,EV_KEY,code,value);
}
static void input_sync(struct input_dev *dev) {
    dev->syncs++;
    if(dev==&input_dev) sync_count++;
}
static int CTP_SPI_READ(void *client,uint8_t *buf,unsigned length) {
    (void)client;
    if(length!=(ts->pen_support?80U:66U)) abort();
    if(spi_result<0) return spi_result;
    memcpy(buf,spi_packet,length);
    return 0;
}
static int nvt_update_firmware(char *name) { (void)name; return 0; }
static void pm_wakeup_event(int *dev,int ms) { (void)dev; (void)ms; }
static void nvt_ts_wakeup_gesture_report(uint8_t id,uint8_t *data) {
    (void)id; (void)data; abort(); /* No test enters gesture mode. */
}
'''
    tests = r'''
#define CHECK(condition, explanation) do { \
    if(!(condition)) { fprintf(stderr,"FAIL: %s\n",explanation); return 1; } \
} while(0)
static int contacts(void) {
    int count=0;
    for(int i=0;i<10;i++) count+=mt_state.slots[i].abs[ABS_MT_TRACKING_ID-ABS_MT_FIRST]>=0;
    return count;
}
static void seal(uint8_t *packet) {
    uint8_t sum=0;
    for(int i=1;i<65;i++) sum+=packet[i];
    packet[65]=-sum;
}
static void point(uint8_t *packet,int record,int id,int x,int y) {
    int p=1+record*6;
    packet[p]=(id<<3)|2;
    packet[p+1]=x>>4; packet[p+2]=y>>4;
    packet[p+3]=((x&15)<<4)|(y&15);
}
static void feed(const uint8_t *packet,int result) {
    spi_packet=packet; spi_result=result;
    nvt_ts_work_func(0,NULL);
}
int main(void) {
    uint8_t fingers[80]={0},notification[80]={0},empty[80]={0},corrupt[80];
    for(int i=0;i<10;i++) mt_state.slots[i].abs[ABS_MT_TRACKING_ID-ABS_MT_FIRST]=-1;
    /* x=64 deliberately makes data[2]=4 without being a palm packet. */
    point(fingers,0,1,64,230); point(fingers,1,2,400,1800); seal(fingers);
    feed(fingers,0);
    CHECK(contacts()==2&&button==1,"normal two-finger packet must press both contacts");
    CHECK(mt_state.slots[0].abs[ABS_MT_TRACKING_ID-ABS_MT_FIRST]==0&&
          mt_state.slots[1].abs[ABS_MT_TRACKING_ID-ABS_MT_FIRST]==1,
          "initial contacts must have tracking IDs 0 and 1");
    for(int id=3;id<=4;id++) {
        memset(notification,0,sizeof(notification));
        notification[1]=30<<3; notification[2]=4; notification[3]=id; seal(notification);
        unsigned before=sync_count;
        feed(notification,0);
        CHECK(contacts()==2&&button==1,"palm status notification must not release held fingers");
        CHECK(sync_count==before,"palm notification must not publish a touch snapshot");
        CHECK(mt_state.slots[0].abs[ABS_MT_TRACKING_ID-ABS_MT_FIRST]==0&&
              mt_state.slots[1].abs[ABS_MT_TRACKING_ID-ABS_MT_FIRST]==1,
              "palm notification must preserve physical tracking identities");
    }
    point(fingers,0,1,65,232); seal(fingers); feed(fingers,0);
    CHECK(contacts()==2&&mt_state.trkid==2,"movement after palm events must retain the gesture");
    CHECK(mt_state.slots[0].abs[ABS_MT_POSITION_X-ABS_MT_FIRST]==65,
          "normal movement must still update coordinates");
    memcpy(corrupt,fingers,sizeof(corrupt)); corrupt[65]^=1;
    feed(corrupt,0); feed(fingers,-5);
    CHECK(contacts()==2&&button==1,"bad checksum and SPI error must not manufacture releases");
    feed(empty,0);
    CHECK(contacts()==0&&button==0,"a genuine empty touch frame must release both contacts");
    feed(fingers,0);
    CHECK(contacts()==2&&mt_state.slots[0].abs[ABS_MT_TRACKING_ID-ABS_MT_FIRST]==2&&
          mt_state.slots[1].abs[ABS_MT_TRACKING_ID-ABS_MT_FIRST]==3,
          "touches after a real release must get new identities");
    state.pen_support=true;
    memset(notification,0,sizeof(notification));
    notification[1]=30<<3; notification[2]=4; notification[3]=3;
    notification[66]=1; notification[68]=123;
    notification[69]=1; notification[70]=200; notification[72]=50;
    seal(notification);
    unsigned finger_syncs=sync_count;
    feed(notification,0);
    CHECK(contacts()==2&&button==1&&sync_count==finger_syncs,
          "a palm notification carrying pen data must not change finger contacts");
    CHECK(pen_input_dev.syncs==1&&pen_input_dev.keys[BTN_TOUCH]==1&&
          pen_input_dev.abs[ABS_X]==123&&pen_input_dev.abs[ABS_Y]==456,
          "palm notifications must not discard independent pen down data");
    notification[3]=4; notification[68]=124; notification[70]=201; seal(notification);
    feed(notification,0);
    CHECK(pen_input_dev.syncs==2&&pen_input_dev.abs[ABS_X]==124&&pen_input_dev.abs[ABS_Y]==457,
          "palm notifications must preserve independent pen movement");
    notification[66]=0xff;
    feed(notification,0);
    CHECK(pen_input_dev.syncs==3&&pen_input_dev.keys[BTN_TOUCH]==0&&pen_input_dev.keys[BTN_TOOL_PEN]==0,
          "palm notifications must not discard independent pen release data");
    CHECK(contacts()==2&&mt_state.trkid==4&&sync_count==finger_syncs,
          "pen reports accompanying palm notifications must preserve finger identities");
    puts("NT36672C palm notifications preserve fingers and pen data; real release and movement: PASS");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="nvt-palm-test-") as directory:
        cfile = Path(directory) / "test.c"
        binary = Path(directory) / "test"
        cfile.write_text(shim + protocol + mt_helpers + helpers + irq + tests)
        compiler = shlex.split(os.environ.get("HOSTCC", "cc"))
        subprocess.run(compiler + ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                                  "-Wno-unused-parameter", "-Wno-unused-variable",
                                  "-Wno-sign-compare", "-Wno-unused-but-set-variable",
                                  str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    run()
