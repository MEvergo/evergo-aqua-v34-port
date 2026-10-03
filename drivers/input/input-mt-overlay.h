/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _INPUT_MT_OVERLAY_INTERNAL_H
#define _INPUT_MT_OVERLAY_INTERNAL_H

#include <linux/input.h>
#include <linux/input/mt.h>

struct input_mt_overlay_state;

int input_mt_overlay_init(struct input_dev *dev);
void input_mt_overlay_free(struct input_dev *dev);
void input_mt_overlay_record_event_locked(struct input_dev *dev,
		unsigned int type, unsigned int code, int value,
		bool accepted, bool physical);
void input_mt_overlay_record_published_locked(struct input_dev *dev,
		const struct input_value *values, unsigned int count);
bool input_mt_overlay_sync_locked(struct input_dev *dev, bool physical,
		bool flush);
void input_mt_overlay_publish_locked(struct input_dev *dev,
		struct input_value *vals, unsigned int count);
bool input_mt_overlay_copy_keys_locked(struct input_dev *dev,
		unsigned long *keys);
bool input_mt_overlay_get_abs_locked(struct input_dev *dev,
		unsigned int code, int *value);
bool input_mt_overlay_copy_slots_locked(struct input_dev *dev,
		unsigned int code, int *values, unsigned int count);
bool input_mt_overlay_release_keys_locked(struct input_dev *dev);
void input_mt_overlay_reset_locked(struct input_dev *dev);
void input_mt_overlay_suspend_locked(struct input_dev *dev);
void input_mt_overlay_resume_locked(struct input_dev *dev);
void input_mt_overlay_shutdown_locked(struct input_dev *dev);

#endif
