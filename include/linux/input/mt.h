#ifndef _INPUT_MT_H
#define _INPUT_MT_H

/*
 * Input Multitouch Library
 *
 * Copyright (c) 2010 Henrik Rydberg
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/input.h>

#define TRKID_MAX	0xffff

#define INPUT_MT_POINTER	0x0001	/* pointer device, e.g. trackpad */
#define INPUT_MT_DIRECT		0x0002	/* direct device, e.g. touchscreen */
#define INPUT_MT_DROP_UNUSED	0x0004	/* drop contacts not seen in frame */
#define INPUT_MT_TRACK		0x0008	/* use in-kernel tracking */
#define INPUT_MT_SEMI_MT	0x0010	/* semi-mt device, finger count handled manually */

/**
 * struct input_mt_slot - represents the state of an input MT slot
 * @abs: holds current values of ABS_MT axes for this slot
 * @frame: last frame at which input_mt_report_slot_state() was called
 * @key: optional driver designation of this slot
 */
struct input_mt_slot {
	int abs[ABS_MT_LAST - ABS_MT_FIRST + 1];
	unsigned int frame;
	unsigned int key;
};

/**
 * struct input_mt - state of tracked contacts
 * @trkid: stores MT tracking ID for the next contact
 * @num_slots: number of MT slots the device uses
 * @slot: MT slot currently being transmitted
 * @flags: input_mt operation flags
 * @frame: increases every time input_mt_sync_frame() is called
 * @red: reduced cost matrix for in-kernel tracking
 * @slots: array of slots holding current values of tracked contacts
 */
struct input_mt {
	int trkid;
	int num_slots;
	int slot;
	unsigned int flags;
	unsigned int frame;
	int *red;
	struct input_mt_slot slots[];
};

/**
 * struct input_mt_overlay_axis - value for a synthetic MT axis
 * @code: supported ABS_MT axis code
 * @value: axis value
 */
struct input_mt_overlay_axis {
	unsigned int code;
	int value;
};

/**
 * struct input_mt_overlay_contact - one active synthetic contact
 * @id: caller-owned stable identity, unique among active contacts
 * @tool_type: MT_TOOL_* value; devices without ABS_MT_TOOL_TYPE support only
 *	MT_TOOL_FINGER
 * @axes: supported ABS_MT values to update for this identity
 * @num_axes: number of elements in @axes
 *
 * ABS_MT_SLOT, ABS_MT_TRACKING_ID, and ABS_MT_TOOL_TYPE are kernel-owned.
 * For an existing identity, axes omitted from an update retain their prior
 * values. For a new identity, omitted axes start at their configured minimum.
 */
struct input_mt_overlay_contact {
	u64 id;
	unsigned int tool_type;
	const struct input_mt_overlay_axis *axes;
	unsigned int num_axes;
};

struct input_mt_overlay;

static inline void input_mt_set_value(struct input_mt_slot *slot,
				      unsigned code, int value)
{
	slot->abs[code - ABS_MT_FIRST] = value;
}

static inline int input_mt_get_value(const struct input_mt_slot *slot,
				     unsigned code)
{
	return slot->abs[code - ABS_MT_FIRST];
}

static inline bool input_mt_is_active(const struct input_mt_slot *slot)
{
	return input_mt_get_value(slot, ABS_MT_TRACKING_ID) >= 0;
}

static inline bool input_mt_is_used(const struct input_mt *mt,
				    const struct input_mt_slot *slot)
{
	return slot->frame == mt->frame;
}

int input_mt_init_slots(struct input_dev *dev, unsigned int num_slots,
			unsigned int flags);
void input_mt_destroy_slots(struct input_dev *dev);

/**
 * input_mt_overlay_reserve_slot() - reserve an MT slot for physical identity
 * @dev: input device with initialized MT slots
 * @slot: physical slot to reserve
 *
 * Call during device setup, before the first overlay attachment. A physical
 * contact in this slot keeps the same output slot; synthetic contacts and
 * remapped real contacts cannot use it.
 *
 * Return: 0 on success, negative errno on failure.
 */
int input_mt_overlay_reserve_slot(struct input_dev *dev, unsigned int slot);

/**
 * input_mt_overlay_attach() - attach one overlay session to an input device
 * @dev: input device with initialized MT slots
 * @session: receives the session handle
 *
 * The session owns a device reference until detached. Only one session can
 * be attached at a time.
 *
 * Return: 0 on success, negative errno on failure.
 */
int input_mt_overlay_attach(struct input_dev *dev,
			    struct input_mt_overlay **session);

/**
 * input_mt_overlay_update() - publish an atomic synthetic contact snapshot
 * @session: attached session
 * @contacts: current active contacts; omitted prior contacts go up
 * @num_contacts: number of contacts
 *
 * The complete update is validated before any state is published. Synthetic
 * tracking IDs and output slots are assigned by input core.
 *
 * Return: 0 on success, negative errno on failure.
 */
int input_mt_overlay_update(struct input_mt_overlay *session,
		const struct input_mt_overlay_contact *contacts,
		unsigned int num_contacts);

/**
 * input_mt_overlay_detach() - release all session contacts and detach
 * @session: session to detach
 *
 * Mapped real contacts remain published in their output slots until their
 * physical contacts end. Callers serialize detach against update.
 */
void input_mt_overlay_detach(struct input_mt_overlay *session);

/**
 * input_mt_overlay_reset() - invalidate the session and release its contacts
 * @dev: input device
 *
 * The current session stays invalid until detached and a new session attaches.
 */
void input_mt_overlay_reset(struct input_dev *dev);

/**
 * input_mt_overlay_suspend() - invalidate the session before suspension
 * @dev: input device
 */
void input_mt_overlay_suspend(struct input_dev *dev);

/**
 * input_mt_overlay_resume() - allow a new session after resume
 * @dev: input device
 *
 * This does not reactivate the session invalidated by suspend.
 */
void input_mt_overlay_resume(struct input_dev *dev);

static inline int input_mt_new_trkid(struct input_mt *mt)
{
	return mt->trkid++ & TRKID_MAX;
}

static inline void input_mt_slot(struct input_dev *dev, int slot)
{
	input_event(dev, EV_ABS, ABS_MT_SLOT, slot);
}

static inline bool input_is_mt_value(int axis)
{
	return axis >= ABS_MT_FIRST && axis <= ABS_MT_LAST;
}

static inline bool input_is_mt_axis(int axis)
{
	return axis == ABS_MT_SLOT || input_is_mt_value(axis);
}

void input_mt_report_slot_state(struct input_dev *dev,
				unsigned int tool_type, bool active);

void input_mt_report_finger_count(struct input_dev *dev, int count);
void input_mt_report_pointer_emulation(struct input_dev *dev, bool use_count);
void input_mt_drop_unused(struct input_dev *dev);

void input_mt_sync_frame(struct input_dev *dev);

/**
 * struct input_mt_pos - contact position
 * @x: horizontal coordinate
 * @y: vertical coordinate
 */
struct input_mt_pos {
	s16 x, y;
};

int input_mt_assign_slots(struct input_dev *dev, int *slots,
			  const struct input_mt_pos *pos, int num_pos,
			  int dmax);

int input_mt_get_slot_by_key(struct input_dev *dev, int key);

#endif
