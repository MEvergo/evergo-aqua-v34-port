// SPDX-License-Identifier: GPL-2.0
/*
 * Per-device, per-session multitouch overlays.
 *
 * The driver's input_mt state remains the physical state. This file keeps a
 * committed physical shadow, a staged physical frame, synthetic contacts,
 * and the state published to input handlers and evdev state ioctls separate.
 */
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/hash.h>
#include <linux/input/mt.h>
#include <linux/log2.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "input-mt-overlay.h"

#define MT_OVERLAY_ABS_COUNT	(ABS_MT_LAST - ABS_MT_FIRST + 1)
#define MT_OVERLAY_NEW_SLOT	(-2)

struct input_mt_overlay_slot {
	int abs[MT_OVERLAY_ABS_COUNT];
	u64 generation;
	u64 birth;
};

struct input_mt_overlay_frame {
	unsigned long keys[BITS_TO_LONGS(KEY_CNT)];
	int abs[ABS_CNT];
	int slot;
	struct input_mt_overlay_slot slots[];
};

struct input_mt_overlay_legacy_slot {
	unsigned long valid;
	unsigned long physical;
	u64 origin_generation;
	u64 previous_generation;
	int previous_tracking_id;
	bool source_legacy;
	bool physical_restart;
	bool legacy_restart;
	u64 restart_birth;
};

struct input_mt_overlay_contact_state {
	u64 id;
	u64 birth;
	int tracking_id;
	unsigned int tool_type;
	bool active;
	bool tombstone;
	bool seen;
	int axes[MT_OVERLAY_ABS_COUNT];
};

struct input_mt_overlay_hash_entry {
	u64 id;
	int slot;
	bool valid;
	bool requested;
};

struct input_mt_overlay_state {
	struct input_dev *dev;
	unsigned int num_slots;
	unsigned int hash_size;
	unsigned int value_capacity;
	unsigned int next_tracking_id;
	u64 next_birth;
	struct input_mt_overlay_frame *pending;
	struct input_mt_overlay_frame *real;
	struct input_mt_overlay_frame *published;
	struct input_mt_overlay_frame *legacy;
	struct input_mt_overlay_frame *source;
	struct input_mt_overlay_legacy_slot *legacy_slots;
	unsigned long legacy_keys[BITS_TO_LONGS(KEY_CNT)];
	unsigned long physical_keys[BITS_TO_LONGS(KEY_CNT)];
	unsigned long legacy_abs[BITS_TO_LONGS(ABS_CNT)];
	unsigned long physical_abs[BITS_TO_LONGS(ABS_CNT)];
	bool legacy_pending;
	struct input_mt_overlay_frame *next;
	unsigned long *reserved;
	unsigned long *tracking_ids;
	int *real_output;
	int *real_tracking_id;
	int *output_real;
	struct input_mt_overlay_contact_state *synthetic;
	struct input_mt_overlay_contact_state *staged;
	struct input_mt_overlay_hash_entry *hash;
	struct input_value *values;
	struct input_mt_overlay *session;
	bool runtime_ready;
	bool enabled;
	bool shutdown;
	bool suspended;
	unsigned int suspend_depth;
};

struct input_mt_overlay {
	struct input_dev *dev;
	struct input_mt_overlay_state *state;
	bool valid;
};
static void input_mt_overlay_runtime_free(
		struct input_mt_overlay_state *state);

static size_t input_mt_overlay_frame_size(unsigned int num_slots)
{
	return sizeof(struct input_mt_overlay_frame) +
		num_slots * sizeof(struct input_mt_overlay_slot);
}

static void input_mt_overlay_frame_copy(struct input_mt_overlay_state *state,
		struct input_mt_overlay_frame *dst,
		const struct input_mt_overlay_frame *src)
{
	memcpy(dst, src, input_mt_overlay_frame_size(state->num_slots));
}

static int input_mt_overlay_init_frame(struct input_mt_overlay_state *state,
		struct input_mt_overlay_frame **frame)
{
	*frame = kzalloc(input_mt_overlay_frame_size(state->num_slots), GFP_KERNEL);
	return *frame ? 0 : -ENOMEM;
}

/* Build the committed device source without committing a partial physical R. */
static void input_mt_overlay_refresh_source(struct input_mt_overlay_state *state,
		bool physical)
{
	struct input_mt_overlay_frame *source = state->source;
	unsigned int i, axis;

	for (i = 0; i < ARRAY_SIZE(source->keys); i++)
		source->keys[i] = (state->real->keys[i] & ~state->legacy_keys[i]) |
				 (state->legacy->keys[i] & state->legacy_keys[i]);
	memcpy(source->abs, state->real->abs, sizeof(source->abs));
	for_each_set_bit(axis, state->legacy_abs, ABS_CNT)
		source->abs[axis] = state->legacy->abs[axis];
	source->slot = state->real->slot;

	for (i = 0; i < state->num_slots; i++) {
		struct input_mt_overlay_legacy_slot *mask = &state->legacy_slots[i];
		struct input_mt_overlay_slot *slot = &source->slots[i];
		const struct input_mt_overlay_slot *origin;
		u64 generation = slot->generation, birth = slot->birth;
		int old_id = slot->abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST];
		bool injected = mask->valid &
				BIT(ABS_MT_TRACKING_ID - ABS_MT_FIRST);

		mask->previous_generation = generation;
		mask->previous_tracking_id = old_id;
		memcpy(slot->abs, state->real->slots[i].abs, sizeof(slot->abs));
		for_each_set_bit(axis, &mask->valid, MT_OVERLAY_ABS_COUNT)
			slot->abs[axis] = state->legacy->slots[i].abs[axis];
		origin = injected ? &state->legacy->slots[i] :
				    &state->real->slots[i];
		if (old_id != slot->abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST] ||
		    (mask->source_legacy == injected &&
		     mask->origin_generation != origin->generation) ||
		    mask->legacy_restart || (physical && mask->physical_restart)) {
			generation++;
			birth = mask->legacy_restart ||
				(physical && mask->physical_restart) ?
				mask->restart_birth : origin->birth;
		}
		slot->generation = generation;
		slot->birth = birth;
		mask->source_legacy = injected;
		mask->origin_generation = origin->generation;
		mask->legacy_restart = false;
		if (physical)
			mask->physical_restart = false;
	}
}

static void input_mt_overlay_clear_physical_overrides(
		struct input_mt_overlay_state *state)
{
	unsigned int i;

	bitmap_andnot(state->legacy_keys, state->legacy_keys,
		      state->physical_keys, KEY_CNT);
	bitmap_zero(state->physical_keys, KEY_CNT);
	bitmap_andnot(state->legacy_abs, state->legacy_abs,
		      state->physical_abs, ABS_CNT);
	bitmap_zero(state->physical_abs, ABS_CNT);
	for (i = 0; i < state->num_slots; i++) {
		state->legacy_slots[i].valid &= ~state->legacy_slots[i].physical;
		state->legacy_slots[i].physical = 0;
	}
}

static void input_mt_overlay_discard_pending(struct input_mt_overlay_state *state)
{
	unsigned int i;

	input_mt_overlay_frame_copy(state, state->pending, state->real);
	input_mt_overlay_frame_copy(state, state->legacy, state->source);
	bitmap_zero(state->physical_keys, KEY_CNT);
	bitmap_zero(state->physical_abs, ABS_CNT);
	for (i = 0; i < state->num_slots; i++) {
		state->legacy_slots[i].physical = 0;
		state->legacy_slots[i].physical_restart = false;
		state->legacy_slots[i].legacy_restart = false;
		if (state->legacy_slots[i].source_legacy)
			state->legacy->slots[i].generation =
				state->legacy_slots[i].origin_generation;
	}
	state->legacy_pending = false;
}

static bool input_mt_overlay_slot_active(
		const struct input_mt_overlay_slot *slot)
{
	return slot->abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST] >= 0;
}

static bool input_mt_overlay_frame_slot_active(
		const struct input_mt_overlay_frame *frame, unsigned int slot)
{
	return input_mt_overlay_slot_active(&frame->slots[slot]);
}

static void input_mt_overlay_set_key(struct input_mt_overlay_frame *frame,
		unsigned int code, bool value)
{
	if (value)
		__set_bit(code, frame->keys);
	else
		__clear_bit(code, frame->keys);
}

static bool input_mt_overlay_real_owned(struct input_mt_overlay_state *state,
		unsigned int output)
{
	return state->output_real[output] >= 0;
}

static void input_mt_overlay_mark_id(struct input_mt_overlay_state *state,
		int id)
{
	if (id >= 0 && id <= TRKID_MAX)
		__set_bit(id, state->tracking_ids);
}

static int input_mt_overlay_alloc_id(struct input_mt_overlay_state *state,
		unsigned int *next_id)
{
	unsigned int i;

	for (i = 0; i <= TRKID_MAX; i++) {
		unsigned int id = *next_id & TRKID_MAX;

		*next_id = (id + 1) & TRKID_MAX;
		if (!__test_and_set_bit(id, state->tracking_ids))
			return id;
	}

	return -ENOSPC;
}

static void input_mt_overlay_prepare_ids(struct input_mt_overlay_state *state)
{
	unsigned int i;

	bitmap_zero(state->tracking_ids, TRKID_MAX + 1);
	for (i = 0; i < state->num_slots; i++) {
		int id = state->published->slots[i].abs[
			ABS_MT_TRACKING_ID - ABS_MT_FIRST];

		input_mt_overlay_mark_id(state, id);
		if (state->real_output[i] >= 0)
			input_mt_overlay_mark_id(state, state->real_tracking_id[i]);
	}
}

static void input_mt_overlay_set_inactive(
		struct input_mt_overlay_state *state,
		struct input_mt_overlay_contact_state *contact)
{
	memset(contact, 0, sizeof(*contact));
	contact->tracking_id = -1;
}

static int input_mt_overlay_hash_index(struct input_mt_overlay_state *state,
		u64 id)
{
	return hash_64(id, ilog2(state->hash_size));
}

static struct input_mt_overlay_hash_entry *
input_mt_overlay_hash_find(struct input_mt_overlay_state *state, u64 id)
{
	unsigned int index = input_mt_overlay_hash_index(state, id);
	unsigned int i;

	for (i = 0; i < state->hash_size; i++) {
		struct input_mt_overlay_hash_entry *entry =
			&state->hash[(index + i) & (state->hash_size - 1)];

		if (!entry->valid || entry->id == id)
			return entry;
	}

	return NULL;
}

static void input_mt_overlay_copy_real_contact(
		struct input_mt_overlay_state *state, unsigned int raw,
		unsigned int output)
{
	struct input_mt_overlay_slot *source = &state->source->slots[raw];
	struct input_mt_overlay_slot *dest = &state->next->slots[output];

	memcpy(dest->abs, source->abs, sizeof(dest->abs));
	dest->birth = source->birth;
	dest->abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST] =
		state->real_tracking_id[raw];
}

static void input_mt_overlay_tombstone(struct input_mt_overlay_state *state,
		unsigned int output)
{
	struct input_mt_overlay_contact_state *contact =
		&state->synthetic[output];

	if (!contact->active)
		return;

	contact->active = false;
	contact->tombstone = true;
	contact->tracking_id = -1;
	contact->seen = false;
}

static int input_mt_overlay_find_free(struct input_mt_overlay_state *state,
		unsigned int preferred)
{
	unsigned int i;

	if (preferred < state->num_slots &&
	    !test_bit(preferred, state->reserved) &&
	    !input_mt_overlay_real_owned(state, preferred) &&
	    !state->synthetic[preferred].active)
		return preferred;

	for (i = 0; i < state->num_slots; i++)
		if (!test_bit(i, state->reserved) &&
		    !input_mt_overlay_real_owned(state, i) &&
		    !state->synthetic[i].active)
			return i;

	return -ENOSPC;
}

static int input_mt_overlay_evict_synthetic(struct input_mt_overlay_state *state,
		unsigned int preferred)
{
	unsigned int i;

	if (preferred < state->num_slots &&
	    !test_bit(preferred, state->reserved) &&
	    !input_mt_overlay_real_owned(state, preferred) &&
	    state->synthetic[preferred].active) {
		input_mt_overlay_tombstone(state, preferred);
		return preferred;
	}

	for (i = 0; i < state->num_slots; i++) {
		if (!test_bit(i, state->reserved) &&
		    !input_mt_overlay_real_owned(state, i) &&
		    state->synthetic[i].active) {
			input_mt_overlay_tombstone(state, i);
			return i;
		}
	}

	return -ENOSPC;
}

static void input_mt_overlay_derive_compat(struct input_mt_overlay_state *state,
		struct input_mt_overlay_frame *frame)
{
	struct input_dev *dev = state->dev;
	struct input_mt_overlay_slot *oldest = NULL;
	unsigned int active = 0;
	unsigned int real_active = 0;
	unsigned int touching = 0;
	unsigned int fingers = 0;
	unsigned int real_fingers = 0;
	unsigned int tracked_fingers = 0;
	unsigned int pens = 0;
	unsigned int i;

	for (i = 0; i < state->num_slots; i++) {
		struct input_mt_overlay_slot *slot = &frame->slots[i];
		int id = slot->abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST];
		unsigned int tool = MT_TOOL_FINGER;
		int distance = 0;

		if (id < 0)
			continue;

		active++;
		if (test_bit(ABS_MT_TOOL_TYPE, dev->absbit))
			tool = slot->abs[ABS_MT_TOOL_TYPE - ABS_MT_FIRST];
		if (test_bit(ABS_MT_DISTANCE, dev->absbit))
			distance = slot->abs[ABS_MT_DISTANCE - ABS_MT_FIRST];
		if (distance <= 0 &&
		    !(tool == MT_TOOL_PEN &&
		      !test_bit(ABS_MT_DISTANCE, dev->absbit) &&
		      test_bit(ABS_MT_PRESSURE, dev->absbit) &&
		      slot->abs[ABS_MT_PRESSURE - ABS_MT_FIRST] == 0))
			touching++;
		if (tool == MT_TOOL_FINGER)
			fingers++;
		else if (tool == MT_TOOL_PEN)
			pens++;

		/* Tracking IDs wrap; pointer selection must follow contact age. */
		if (!oldest || (s64)(slot->birth - oldest->birth) < 0)
			oldest = slot;
	}
	for (i = 0; i < state->num_slots; i++) {
		if (!input_mt_overlay_frame_slot_active(state->source, i))
			continue;
		real_active++;
		if (!test_bit(ABS_MT_TOOL_TYPE, dev->absbit) ||
		    state->source->slots[i].abs[
			    ABS_MT_TOOL_TYPE - ABS_MT_FIRST] == MT_TOOL_FINGER)
			tracked_fingers++;
	}

	if (!real_active || (dev->mt->flags & INPUT_MT_SEMI_MT)) {
		if (test_bit(BTN_TOOL_QUINTTAP, state->source->keys))
			real_fingers = 5;
		else if (test_bit(BTN_TOOL_QUADTAP, state->source->keys))
			real_fingers = 4;
		else if (test_bit(BTN_TOOL_TRIPLETAP, state->source->keys))
			real_fingers = 3;
		else if (test_bit(BTN_TOOL_DOUBLETAP, state->source->keys))
			real_fingers = 2;
		else if (test_bit(BTN_TOOL_FINGER, state->source->keys))
			real_fingers = 1;
		if (real_fingers > tracked_fingers)
			fingers += real_fingers - tracked_fingers;
	}
	if (!real_active) {
		if (!active && !fingers && test_bit(ABS_DISTANCE, dev->absbit) &&
		    frame->abs[ABS_DISTANCE] > 0)
			fingers = 1;
		if (!active && test_bit(BTN_TOUCH, dev->keybit) &&
		    test_bit(BTN_TOUCH, state->source->keys))
			touching = 1;
		else if (active && test_bit(BTN_TOUCH, dev->keybit) &&
			 test_bit(BTN_TOUCH, state->source->keys))
			touching++;
	}

	if (test_bit(BTN_TOUCH, dev->keybit) &&
	    (active || !test_bit(BTN_TOUCH, state->source->keys)))
		input_mt_overlay_set_key(frame, BTN_TOUCH, touching != 0);
	if (test_bit(BTN_TOOL_FINGER, dev->keybit))
		input_mt_overlay_set_key(frame, BTN_TOOL_FINGER, fingers == 1);
	if (test_bit(BTN_TOOL_DOUBLETAP, dev->keybit))
		input_mt_overlay_set_key(frame, BTN_TOOL_DOUBLETAP, fingers == 2);
	if (test_bit(BTN_TOOL_TRIPLETAP, dev->keybit))
		input_mt_overlay_set_key(frame, BTN_TOOL_TRIPLETAP, fingers == 3);
	if (test_bit(BTN_TOOL_QUADTAP, dev->keybit))
		input_mt_overlay_set_key(frame, BTN_TOOL_QUADTAP, fingers == 4);
	if (test_bit(BTN_TOOL_QUINTTAP, dev->keybit))
		input_mt_overlay_set_key(frame, BTN_TOOL_QUINTTAP, fingers == 5);
	if (test_bit(BTN_TOOL_PEN, dev->keybit))
		input_mt_overlay_set_key(frame, BTN_TOOL_PEN,
					 pens || test_bit(BTN_TOOL_PEN,
							  state->source->keys));

	if (oldest) {
		if (test_bit(ABS_X, dev->absbit) &&
		    test_bit(ABS_MT_POSITION_X, dev->absbit))
			frame->abs[ABS_X] =
				oldest->abs[ABS_MT_POSITION_X - ABS_MT_FIRST];
		if (test_bit(ABS_Y, dev->absbit) &&
		    test_bit(ABS_MT_POSITION_Y, dev->absbit))
			frame->abs[ABS_Y] =
				oldest->abs[ABS_MT_POSITION_Y - ABS_MT_FIRST];
		if (test_bit(ABS_PRESSURE, dev->absbit) &&
		    test_bit(ABS_MT_PRESSURE, dev->absbit))
			frame->abs[ABS_PRESSURE] =
				oldest->abs[ABS_MT_PRESSURE - ABS_MT_FIRST];
	} else if (test_bit(ABS_PRESSURE, dev->absbit) &&
		   test_bit(ABS_MT_PRESSURE, dev->absbit)) {
		frame->abs[ABS_PRESSURE] = 0;
	}
}

static void input_mt_overlay_compose(struct input_mt_overlay_state *state)
{
	unsigned int i;

	input_mt_overlay_frame_copy(state, state->next, state->source);
	for (i = 0; i < state->num_slots; i++)
		state->next->slots[i].abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST] = -1;

	for (i = 0; i < state->num_slots; i++) {
		int output = state->real_output[i];

		if (output >= 0)
			input_mt_overlay_copy_real_contact(state, i, output);
	}

	for (i = 0; i < state->num_slots; i++) {
		struct input_mt_overlay_contact_state *contact =
			&state->synthetic[i];
		struct input_mt_overlay_slot *slot = &state->next->slots[i];

		if (!contact->active)
			continue;

		memcpy(slot->abs, contact->axes, sizeof(slot->abs));
		slot->birth = contact->birth;
		slot->abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST] =
			contact->tracking_id;
		if (test_bit(ABS_MT_TOOL_TYPE, state->dev->absbit))
			slot->abs[ABS_MT_TOOL_TYPE - ABS_MT_FIRST] =
				contact->tool_type;
	}

	/* Slot selection in M follows the last slot actually published. */
	state->next->abs[ABS_MT_SLOT] = state->published->abs[ABS_MT_SLOT];
	input_mt_overlay_derive_compat(state, state->next);
}

static void input_mt_overlay_emit_diff(struct input_mt_overlay_state *state,
		struct input_mt_overlay_frame *previous,
		struct input_mt_overlay_frame *next)
{
	struct input_dev *dev = state->dev;
	unsigned int count = 0;
	unsigned int code, slot, axis;

	for (code = 0; code < KEY_CNT; code++) {
		if (test_bit(code, dev->keybit) &&
		    test_bit(code, previous->keys) !=
		    test_bit(code, next->keys)) {
			state->values[count].type = EV_KEY;
			state->values[count].code = code;
			state->values[count].value =
				test_bit(code, next->keys);
			count++;
		}
	}

	for (code = 0; code < ABS_CNT; code++) {
		if (input_is_mt_axis(code) || !test_bit(code, dev->absbit))
			continue;
		if (previous->abs[code] == next->abs[code])
			continue;
		state->values[count].type = EV_ABS;
		state->values[count].code = code;
		state->values[count].value = next->abs[code];
		count++;
	}

	for (slot = 0; slot < state->num_slots; slot++) {
		struct input_mt_overlay_slot *old = &previous->slots[slot];
		struct input_mt_overlay_slot *new = &next->slots[slot];
		int old_id = old->abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST];
		int new_id = new->abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST];
		bool slot_changed = false;

		if (old_id != new_id) {
			state->values[count].type = EV_ABS;
			state->values[count].code = ABS_MT_SLOT;
			state->values[count].value = slot;
			count++;
			next->abs[ABS_MT_SLOT] = slot;
			slot_changed = true;

			state->values[count].type = EV_ABS;
			state->values[count].code = ABS_MT_TRACKING_ID;
			state->values[count].value = new_id;
			count++;
		}

		for (axis = 0; axis < MT_OVERLAY_ABS_COUNT; axis++) {
			unsigned int abs = ABS_MT_FIRST + axis;
			int old_value = old->abs[axis];
			int new_value = new->abs[axis];

			if (abs == ABS_MT_TRACKING_ID ||
			    !test_bit(abs, dev->absbit))
				continue;
			if (old_id != new_id && new_id < 0)
				continue;
			if (old_id == new_id && old_value == new_value)
				continue;

			if (!slot_changed) {
				state->values[count].type = EV_ABS;
				state->values[count].code = ABS_MT_SLOT;
				state->values[count].value = slot;
				count++;
				next->abs[ABS_MT_SLOT] = slot;
				slot_changed = true;
			}

			state->values[count].type = EV_ABS;
			state->values[count].code = abs;
			state->values[count].value = new_value;
			count++;
		}
	}

	input_mt_overlay_frame_copy(state, previous, next);
	if (!count)
		return;

	state->values[count].type = EV_SYN;
	state->values[count].code = SYN_REPORT;
	state->values[count].value = 1;
	count++;
	input_mt_overlay_publish_locked(dev, state->values, count);
}

static void input_mt_overlay_reconcile_real(
		struct input_mt_overlay_state *state,
		const struct input_mt_overlay_frame *incoming)
{
	unsigned int raw;
	bool ids_prepared = false;

	for (raw = 0; raw < state->num_slots; raw++) {
		int output = state->real_output[raw];
		bool active = input_mt_overlay_frame_slot_active(incoming, raw);
		bool same = active &&
			state->legacy_slots[raw].previous_tracking_id >= 0 &&
			state->legacy_slots[raw].previous_generation ==
				incoming->slots[raw].generation &&
			state->legacy_slots[raw].previous_tracking_id ==
				incoming->slots[raw].abs[
					ABS_MT_TRACKING_ID - ABS_MT_FIRST];

		if (output < 0 || same)
			continue;

		state->output_real[output] = -1;
		state->real_output[raw] = -1;
		state->real_tracking_id[raw] = -1;
	}

	for (raw = 0; raw < state->num_slots; raw++) {
		int output, id;

		if (!input_mt_overlay_frame_slot_active(incoming, raw) ||
		    state->real_output[raw] >= 0)
			continue;

		if (test_bit(raw, state->reserved)) {
			output = raw;
			if (state->output_real[output] >= 0) {
				WARN_ON_ONCE(1);
				continue;
			}
			if (state->synthetic[output].active)
				input_mt_overlay_tombstone(state, output);
		} else {
			output = input_mt_overlay_find_free(state, raw);
			if (output < 0)
				output = input_mt_overlay_evict_synthetic(state, raw);
			if (output < 0) {
				WARN_ON_ONCE(1);
				continue;
			}
		}

		if (!ids_prepared) {
			input_mt_overlay_prepare_ids(state);
			ids_prepared = true;
		}
		id = input_mt_overlay_alloc_id(state, &state->next_tracking_id);
		if (id < 0) {
			WARN_ON_ONCE(1);
			continue;
		}

		state->real_output[raw] = output;
		state->real_tracking_id[raw] = id;
		state->output_real[output] = raw;
	}

}
static void input_mt_overlay_publish_current(
		struct input_mt_overlay_state *state)
{
	if (!state->enabled) {
		input_mt_overlay_emit_diff(state, state->published, state->source);
		return;
	}

	input_mt_overlay_compose(state);
	input_mt_overlay_emit_diff(state, state->published, state->next);
}


static int input_mt_overlay_runtime_init(struct input_mt_overlay_state *state)
{
	unsigned int i;

	state->hash_size = roundup_pow_of_two(max_t(unsigned int, 4,
							state->num_slots * 4));

	state->next = kzalloc(input_mt_overlay_frame_size(state->num_slots),
			      GFP_KERNEL);
	state->real_output = kcalloc(state->num_slots,
				     sizeof(*state->real_output), GFP_KERNEL);
	state->real_tracking_id = kcalloc(state->num_slots,
					  sizeof(*state->real_tracking_id),
					  GFP_KERNEL);
	state->output_real = kcalloc(state->num_slots,
				     sizeof(*state->output_real), GFP_KERNEL);
	state->synthetic = kcalloc(state->num_slots,
				   sizeof(*state->synthetic), GFP_KERNEL);
	state->staged = kcalloc(state->num_slots, sizeof(*state->staged),
				GFP_KERNEL);
	state->hash = kcalloc(state->hash_size, sizeof(*state->hash),
			      GFP_KERNEL);
	state->tracking_ids = bitmap_zalloc(TRKID_MAX + 1, GFP_KERNEL);

	if (!state->next || !state->real_output ||
	    !state->real_tracking_id || !state->output_real ||
	    !state->synthetic || !state->staged || !state->hash ||
	    !state->tracking_ids)
		goto err_free;

	for (i = 0; i < state->num_slots; i++) {
		state->real_output[i] = -1;
		state->real_tracking_id[i] = -1;
		state->output_real[i] = -1;
		state->synthetic[i].tracking_id = -1;
		state->staged[i].tracking_id = -1;
	}


	return 0;

err_free:
	kfree(state->next);
	kfree(state->real_output);
	kfree(state->real_tracking_id);
	kfree(state->output_real);
	kfree(state->synthetic);
	kfree(state->staged);
	kfree(state->hash);
	bitmap_free(state->tracking_ids);
	state->next = NULL;
	state->real_output = NULL;
	state->real_tracking_id = NULL;
	state->output_real = NULL;
	state->synthetic = NULL;
	state->staged = NULL;
	state->hash = NULL;
	state->tracking_ids = NULL;
	return -ENOMEM;
}

static void input_mt_overlay_runtime_free(struct input_mt_overlay_state *state)
{
	kfree(state->next);
	kfree(state->real_output);
	kfree(state->real_tracking_id);
	kfree(state->output_real);
	kfree(state->synthetic);
	kfree(state->staged);
	kfree(state->hash);
	bitmap_free(state->tracking_ids);
}

static void input_mt_overlay_init_raw_frame(struct input_dev *dev,
		struct input_mt_overlay_frame *frame)
{
	unsigned int i;

	bitmap_copy(frame->keys, dev->key, KEY_CNT);
	if (dev->absinfo)
		for (i = 0; i < ABS_CNT; i++)
			frame->abs[i] = dev->absinfo[i].value;

	frame->slot = dev->mt->slot;
	for (i = 0; i < dev->mt->num_slots; i++) {
		memcpy(frame->slots[i].abs, dev->mt->slots[i].abs,
		       sizeof(frame->slots[i].abs));
		frame->slots[i].generation = 0;
	}
}

int input_mt_overlay_init(struct input_dev *dev)
{
	struct input_mt_overlay_state *state;
	int error;

	if (dev->mt_overlay)
		return 0;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	state->dev = dev;
	state->num_slots = dev->mt->num_slots;
	state->reserved = bitmap_zalloc(state->num_slots, GFP_KERNEL);
	if (!state->reserved) {
		error = -ENOMEM;
		goto err_free_state;
	}

	error = input_mt_overlay_init_frame(state, &state->pending);
	if (error)
		goto err_free_state;
	error = input_mt_overlay_init_frame(state, &state->real);
	if (error)
		goto err_free_state;
	error = input_mt_overlay_init_frame(state, &state->published);
	if (error)
		goto err_free_state;
	error = input_mt_overlay_init_frame(state, &state->legacy);
	if (error)
		goto err_free_state;
	error = input_mt_overlay_init_frame(state, &state->source);
	if (error)
		goto err_free_state;
	state->legacy_slots = kcalloc(state->num_slots,
				     sizeof(*state->legacy_slots), GFP_KERNEL);
	if (!state->legacy_slots) {
		error = -ENOMEM;
		goto err_free_state;
	}

	state->value_capacity = KEY_CNT + ABS_CNT +
		state->num_slots * (MT_OVERLAY_ABS_COUNT + 2) + 1;
	state->values = kcalloc(state->value_capacity, sizeof(*state->values),
				GFP_KERNEL);
	if (!state->values) {
		error = -ENOMEM;
		goto err_free_state;
	}

	input_mt_overlay_init_raw_frame(dev, state->pending);
	input_mt_overlay_frame_copy(state, state->real, state->pending);
	input_mt_overlay_frame_copy(state, state->published, state->pending);
	input_mt_overlay_frame_copy(state, state->legacy, state->pending);
	input_mt_overlay_frame_copy(state, state->source, state->pending);
	dev->mt_overlay = state;
	return 0;

err_free_state:
	kfree(state->pending);
	kfree(state->real);
	kfree(state->published);
	kfree(state->legacy);
	kfree(state->source);
	kfree(state->legacy_slots);
	kfree(state->values);
	bitmap_free(state->reserved);
	kfree(state);
	return error;
}

void input_mt_overlay_free(struct input_dev *dev)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;

	if (!state)
		return;

	if (state->session) {
		state->session->valid = false;
		state->session->state = NULL;
		state->session = NULL;
	}
	input_mt_overlay_runtime_free(state);
	kfree(state->pending);
	kfree(state->real);
	kfree(state->published);
	kfree(state->legacy);
	kfree(state->source);
	kfree(state->legacy_slots);
	kfree(state->values);
	bitmap_free(state->reserved);
	kfree(state);
	dev->mt_overlay = NULL;
}

void input_mt_overlay_record_event_locked(struct input_dev *dev,
		unsigned int type, unsigned int code, int value,
		bool accepted, bool physical)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;
	struct input_mt_overlay_frame *frame;
	unsigned int slot, axis;
	int old_value;

	if (!state || (!physical && !accepted &&
		       !(type == EV_ABS && code == ABS_MT_SLOT)))
		return;

	frame = physical ? state->pending : state->legacy;
	if (type == EV_KEY) {
		if (code >= KEY_CNT || !test_bit(code, dev->keybit) || value == 2)
			return;
		input_mt_overlay_set_key(frame, code, value != 0);
		if (physical) {
			__set_bit(code, state->physical_keys);
		} else {
			__set_bit(code, state->legacy_keys);
			__clear_bit(code, state->physical_keys);
			state->legacy_pending = true;
		}
		return;
	}

	if (type != EV_ABS || code >= ABS_CNT ||
	    !test_bit(code, dev->absbit))
		return;

	if (code == ABS_MT_SLOT) {
		if (value >= 0 && value < state->num_slots) {
			frame->slot = value;
			frame->abs[ABS_MT_SLOT] = value;
		}
		return;
	}

	if (input_is_mt_value(code)) {
		slot = physical ? frame->slot : dev->mt->slot;
		if (slot >= state->num_slots)
			return;
		axis = code - ABS_MT_FIRST;
		old_value = frame->slots[slot].abs[axis];
		if (code == ABS_MT_TRACKING_ID && old_value != value) {
			frame->slots[slot].generation++;
			if (value >= 0)
				frame->slots[slot].birth = ++state->next_birth;
		}
		if (code == ABS_MT_TRACKING_ID && accepted) {
			struct input_mt_overlay_legacy_slot *mask =
				&state->legacy_slots[slot];

			if (!physical)
				mask->physical_restart = false;
			if (value < 0) {
				if (physical)
					mask->physical_restart = true;
				else
					mask->legacy_restart = true;
			} else if (mask->legacy_restart || mask->physical_restart) {
				mask->restart_birth = old_value == value ?
					++state->next_birth : frame->slots[slot].birth;
			}
		}
		frame->slots[slot].abs[axis] = value;
		if (physical) {
			state->legacy_slots[slot].physical |= BIT(axis);
		} else {
			state->legacy_slots[slot].valid |= BIT(axis);
			state->legacy_slots[slot].physical &= ~BIT(axis);
			state->legacy_pending = true;
		}
		return;
	}

	frame->abs[code] = value;
	if (physical) {
		__set_bit(code, state->physical_abs);
	} else {
		__set_bit(code, state->legacy_abs);
		__clear_bit(code, state->physical_abs);
		state->legacy_pending = true;
	}
}

void input_mt_overlay_record_published_locked(struct input_dev *dev,
		const struct input_value *values, unsigned int count)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;
	struct input_mt_overlay_frame *frame;
	unsigned int i;

	/* The merged path commits M before dispatching its own value buffer. */
	if (!state || values == state->values)
		return;

	frame = state->published;
	for (i = 0; i < count; i++) {
		unsigned int code = values[i].code;
		int value = values[i].value;

		if (values[i].type == EV_KEY) {
			if (code < KEY_CNT && value != 2)
				input_mt_overlay_set_key(frame, code, value != 0);
		} else if (values[i].type == EV_ABS && code < ABS_CNT) {
			if (input_is_mt_value(code)) {
				unsigned int slot = frame->abs[ABS_MT_SLOT];

				if (slot < state->num_slots)
					frame->slots[slot].abs[
						code - ABS_MT_FIRST] = value;
			} else {
				frame->abs[code] = value;
			}
		}
	}
}


bool input_mt_overlay_sync_locked(struct input_dev *dev, bool physical,
		bool flush)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;

	if (!state)
		return false;
	if (state->shutdown)
		return true;
	if (!physical && !state->legacy_pending && !flush)
		return true;

	if (physical) {
		input_mt_overlay_clear_physical_overrides(state);
		input_mt_overlay_frame_copy(state, state->real, state->pending);
	}
	input_mt_overlay_refresh_source(state, physical);
	state->legacy_pending = false;
	if (state->enabled)
		input_mt_overlay_reconcile_real(state, state->source);
	input_mt_overlay_publish_current(state);
	return true;
}

bool input_mt_overlay_copy_keys_locked(struct input_dev *dev,
		unsigned long *keys)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;

	if (!state)
		return false;

	bitmap_copy(keys, state->published->keys, KEY_CNT);
	return true;
}
EXPORT_SYMBOL_GPL(input_mt_overlay_copy_keys_locked);


bool input_mt_overlay_get_abs_locked(struct input_dev *dev,
		unsigned int code, int *value)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;

	if (!state || code >= ABS_CNT)
		return false;

	if (input_is_mt_value(code))
		*value = state->published->slots[
			state->published->abs[ABS_MT_SLOT]].abs[code - ABS_MT_FIRST];
	else
		*value = state->published->abs[code];
	return true;
}
EXPORT_SYMBOL_GPL(input_mt_overlay_get_abs_locked);


bool input_mt_overlay_copy_slots_locked(struct input_dev *dev,
		unsigned int code, int *values, unsigned int count)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;
	const struct input_mt_overlay_frame *frame;
	unsigned int i;

	if (!state || !input_is_mt_value(code))
		return false;

	frame = state->published;
	count = min(count, state->num_slots);
	for (i = 0; i < count; i++)
		values[i] = frame->slots[i].abs[code - ABS_MT_FIRST];
	return true;
}
EXPORT_SYMBOL_GPL(input_mt_overlay_copy_slots_locked);


bool input_mt_overlay_release_keys_locked(struct input_dev *dev)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;

	if (!state)
		return false;
	bitmap_zero(state->real->keys, KEY_CNT);
	bitmap_zero(state->pending->keys, KEY_CNT);
	bitmap_zero(state->legacy_keys, KEY_CNT);
	bitmap_zero(state->physical_keys, KEY_CNT);
	bitmap_zero(state->source->keys, KEY_CNT);
	input_mt_overlay_publish_current(state);
	return true;
}


static void input_mt_overlay_clear_synthetic(
		struct input_mt_overlay_state *state)
{
	unsigned int i;

	if (!state->runtime_ready)
		return;

	for (i = 0; i < state->num_slots; i++)
		input_mt_overlay_set_inactive(state, &state->synthetic[i]);
}

void input_mt_overlay_reset_locked(struct input_dev *dev)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;

	if (!state)
		return;

	if (state->session)
		state->session->valid = false;
	input_mt_overlay_discard_pending(state);
	input_mt_overlay_clear_synthetic(state);
	dev->num_vals = 0;
	input_mt_overlay_publish_current(state);
}

void input_mt_overlay_suspend_locked(struct input_dev *dev)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;

	if (!state)
		return;

	if (state->suspend_depth != ~0U)
		state->suspend_depth++;
	state->suspended = true;
	if (state->session)
		state->session->valid = false;
	input_mt_overlay_discard_pending(state);
	input_mt_overlay_clear_synthetic(state);
	dev->num_vals = 0;
	input_mt_overlay_publish_current(state);
}

void input_mt_overlay_resume_locked(struct input_dev *dev)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;

	if (state && !state->shutdown && state->suspend_depth) {
		state->suspend_depth--;
		state->suspended = state->suspend_depth != 0;
	}
}

void input_mt_overlay_shutdown_locked(struct input_dev *dev)
{
	struct input_mt_overlay_state *state = dev->mt_overlay;
	unsigned int i;

	if (!state)
		return;

	state->shutdown = true;
	if (state->session)
		state->session->valid = false;
	bitmap_zero(state->real->keys, KEY_CNT);
	bitmap_zero(state->legacy_keys, KEY_CNT);
	bitmap_zero(state->legacy_abs, ABS_CNT);
	for (i = 0; i < state->num_slots; i++) {
		state->real->slots[i].abs[ABS_MT_TRACKING_ID - ABS_MT_FIRST] = -1;
		state->legacy_slots[i].valid = 0;
		if (state->runtime_ready) {
			state->real_output[i] = -1;
			state->real_tracking_id[i] = -1;
			state->output_real[i] = -1;
		}
	}
	input_mt_overlay_refresh_source(state, false);
	input_mt_overlay_discard_pending(state);
	input_mt_overlay_clear_synthetic(state);
	dev->num_vals = 0;
	input_mt_overlay_publish_current(state);
}

static int input_mt_overlay_hash_insert(struct input_mt_overlay_state *state,
		u64 id, int slot)
{
	struct input_mt_overlay_hash_entry *entry =
		input_mt_overlay_hash_find(state, id);

	if (!entry)
		return -ENOSPC;
	if (entry->valid)
		return -EEXIST;

	entry->valid = true;
	entry->id = id;
	entry->slot = slot;
	return 0;
}

static int input_mt_overlay_find_staged_free(
		struct input_mt_overlay_state *state)
{
	unsigned int i;

	for (i = 0; i < state->num_slots; i++)
		if (!test_bit(i, state->reserved) &&
		    !input_mt_overlay_real_owned(state, i) &&
		    !state->staged[i].active)
			return i;

	return -ENOSPC;
}

static bool input_mt_overlay_axis_supported(struct input_mt_overlay_state *state,
		unsigned int code)
{
	return input_is_mt_value(code) &&
		code != ABS_MT_TRACKING_ID &&
		code != ABS_MT_TOOL_TYPE &&
		test_bit(code, state->dev->absbit);
}

static int input_mt_overlay_validate_contact(
		struct input_mt_overlay_state *state,
		const struct input_mt_overlay_contact *contact)
{
	unsigned long axes = 0;
	unsigned int i;

	if (contact->tool_type > MT_TOOL_MAX)
		return -EINVAL;
	if (!test_bit(ABS_MT_TOOL_TYPE, state->dev->absbit) &&
	    contact->tool_type != MT_TOOL_FINGER)
		return -EOPNOTSUPP;
	if (contact->num_axes && !contact->axes)
		return -EINVAL;
	if (test_bit(ABS_MT_TOOL_TYPE, state->dev->absbit) &&
	    (!state->dev->absinfo ||
	     contact->tool_type <
		state->dev->absinfo[ABS_MT_TOOL_TYPE].minimum ||
	     contact->tool_type >
		state->dev->absinfo[ABS_MT_TOOL_TYPE].maximum))
		return -ERANGE;

	for (i = 0; i < contact->num_axes; i++) {
		unsigned int code = contact->axes[i].code;
		unsigned int index;

		if (!input_mt_overlay_axis_supported(state, code))
			return -EOPNOTSUPP;
		index = code - ABS_MT_FIRST;
		if (axes & BIT(index))
			return -EINVAL;
		axes |= BIT(index);
	}

	return 0;
}

static void input_mt_overlay_start_contact(
		struct input_mt_overlay_state *state,
		struct input_mt_overlay_contact_state *target,
		const struct input_mt_overlay_contact *source)
{
	unsigned int axis;
	unsigned int i;

	input_mt_overlay_set_inactive(state, target);
	target->id = source->id;
	target->tool_type = source->tool_type;
	target->active = true;
	for (axis = 0; axis < MT_OVERLAY_ABS_COUNT; axis++) {
		unsigned int code = ABS_MT_FIRST + axis;

		if (test_bit(code, state->dev->absbit))
			target->axes[axis] =
				state->dev->absinfo[code].minimum;
	}
	if (test_bit(ABS_MT_TOOL_TYPE, state->dev->absbit))
		target->axes[ABS_MT_TOOL_TYPE - ABS_MT_FIRST] =
			source->tool_type;

	for (i = 0; i < source->num_axes; i++)
		target->axes[source->axes[i].code - ABS_MT_FIRST] =
			source->axes[i].value;
}

static int input_mt_overlay_update_locked(
		struct input_mt_overlay *session,
		const struct input_mt_overlay_contact *contacts,
		unsigned int num_contacts)
{
	struct input_mt_overlay_state *state = session->state;
	struct input_mt_overlay_hash_entry *entry;
	unsigned int i, j, next_id;
	u64 next_birth;
	int slot, error;

	if (!session->valid || state->session != session ||
	    state->shutdown || state->suspended)
		return -ESHUTDOWN;
	if (num_contacts > state->num_slots)
		return -ENOSPC;
	if (num_contacts && !contacts)
		return -EINVAL;

	memcpy(state->staged, state->synthetic,
	       state->num_slots * sizeof(*state->staged));
	memset(state->hash, 0, state->hash_size * sizeof(*state->hash));
	for (i = 0; i < state->num_slots; i++) {
		state->staged[i].seen = false;
		if (!state->staged[i].active && !state->staged[i].tombstone)
			continue;
		error = input_mt_overlay_hash_insert(state,
				state->staged[i].id, i);
		if (error)
			return error;
	}

	for (i = 0; i < num_contacts; i++) {
		const struct input_mt_overlay_contact *contact = &contacts[i];

		error = input_mt_overlay_validate_contact(state, contact);
		if (error)
			return error;

		entry = input_mt_overlay_hash_find(state, contact->id);
		if (!entry)
			return -ENOSPC;
		if (entry->valid && entry->id == contact->id) {
			if (entry->requested)
				return -EINVAL;
			entry->requested = true;
			if (entry->slot == MT_OVERLAY_NEW_SLOT)
				return -EINVAL;
			if (state->staged[entry->slot].tombstone)
				return -EPIPE;

			state->staged[entry->slot].seen = true;
			if (state->staged[entry->slot].tool_type !=
			    contact->tool_type)
				return -EINVAL;
			for (j = 0; j < contact->num_axes; j++)
				state->staged[entry->slot].axes[
					contact->axes[j].code - ABS_MT_FIRST] =
					contact->axes[j].value;
		} else {
			entry->valid = true;
			entry->id = contact->id;
			entry->slot = MT_OVERLAY_NEW_SLOT;
			entry->requested = true;
		}
	}

	for (i = 0; i < state->num_slots; i++)
		if ((state->staged[i].active ||
		     state->staged[i].tombstone) && !state->staged[i].seen)
			input_mt_overlay_set_inactive(state, &state->staged[i]);

	for (i = 0; i < num_contacts; i++) {
		entry = input_mt_overlay_hash_find(state, contacts[i].id);
		if (!entry || !entry->valid || entry->slot != MT_OVERLAY_NEW_SLOT)
			continue;

		slot = input_mt_overlay_find_staged_free(state);
		if (slot < 0)
			return -ENOSPC;

		input_mt_overlay_start_contact(state, &state->staged[slot],
					       &contacts[i]);
		entry->slot = slot;
	}

	input_mt_overlay_prepare_ids(state);
	for (i = 0; i < state->num_slots; i++)
		if (state->staged[i].active)
			input_mt_overlay_mark_id(state,
						 state->staged[i].tracking_id);
	next_id = state->next_tracking_id;
	next_birth = state->next_birth;
	for (i = 0; i < state->num_slots; i++) {
		if (!state->staged[i].active ||
		    state->staged[i].tracking_id >= 0)
			continue;

		error = input_mt_overlay_alloc_id(state, &next_id);
		if (error < 0)
			return error;
		state->staged[i].tracking_id = error;
		state->staged[i].birth = ++next_birth;
	}

	for (i = 0; i < state->num_slots; i++)
		state->staged[i].seen = false;
	memcpy(state->synthetic, state->staged,
	       state->num_slots * sizeof(*state->synthetic));
	state->next_tracking_id = next_id;
	state->next_birth = next_birth;
	input_mt_overlay_publish_current(state);
	return 0;
}

/**
 * input_mt_overlay_reserve_slot() - reserve a physical MT slot
 * @dev: input device with initialized MT slots
 * @slot: slot that must remain at its physical index
 *
 * Reserved slots are excluded from synthetic contacts and from destinations
 * used to remap real contacts. A real contact reported in its reserved slot
 * retains that output slot. Reserve slots during device setup, before the
 * first overlay attachment.
 *
 * Return: 0 on success, -EINVAL for an invalid slot, -EBUSY after attachment
 * or while the slot is active, or -EOPNOTSUPP without MT overlay state.
 */
int input_mt_overlay_reserve_slot(struct input_dev *dev, unsigned int slot)
{
	struct input_mt_overlay_state *state;
	unsigned long flags;
	int error = 0;

	mutex_lock(&dev->mutex);
	spin_lock_irqsave(&dev->event_lock, flags);
	state = dev->mt_overlay;
	if (!state) {
		error = -EOPNOTSUPP;
	} else if (slot >= state->num_slots) {
		error = -EINVAL;
	} else if (state->enabled || state->shutdown ||
		   input_mt_overlay_frame_slot_active(state->source, slot) ||
		   input_mt_overlay_frame_slot_active(state->pending, slot) ||
		   ((state->legacy_slots[slot].valid &
		     BIT(ABS_MT_TRACKING_ID - ABS_MT_FIRST)) &&
		    input_mt_overlay_frame_slot_active(state->legacy, slot))) {
		error = -EBUSY;
	} else {
		__set_bit(slot, state->reserved);
	}
	spin_unlock_irqrestore(&dev->event_lock, flags);
	mutex_unlock(&dev->mutex);
	return error;
}
EXPORT_SYMBOL_GPL(input_mt_overlay_reserve_slot);

/**
 * input_mt_overlay_attach() - attach a synthetic-contact session
 * @dev: input device with initialized MT slots
 * @session: returned session handle
 *
 * The device may have only one attached session. The handle retains a
 * reference to @dev until input_mt_overlay_detach(). A per-device shadow
 * collected from real SYN_REPORT events seeds the last complete frame, so
 * attachment during a physical frame cannot expose its partial state.
 *
 * Return: 0 on success, -EBUSY for an existing session, -ESHUTDOWN after
 * device removal or while suspended, or -EOPNOTSUPP without MT overlay state.
 */
int input_mt_overlay_attach(struct input_dev *dev,
			    struct input_mt_overlay **session)
{
	struct input_mt_overlay_state *state;
	struct input_mt_overlay *overlay;
	unsigned long flags;
	unsigned int i;
	int error = 0;

	if (!session)
		return -EINVAL;
	*session = NULL;
	if (!input_get_device(dev))
		return -ENODEV;

	overlay = kzalloc(sizeof(*overlay), GFP_KERNEL);
	if (!overlay) {
		input_put_device(dev);
		return -ENOMEM;
	}
	overlay->dev = dev;

	mutex_lock(&dev->mutex);
	spin_lock_irqsave(&dev->event_lock, flags);
	state = dev->mt_overlay;
	if (!state) {
		error = -EOPNOTSUPP;
	} else if (state->shutdown || state->suspended) {
		error = -ESHUTDOWN;
	} else if (state->session) {
		error = -EBUSY;
	}
	spin_unlock_irqrestore(&dev->event_lock, flags);
	if (error)
		goto out_unlock;

	if (!state->next) {
		error = input_mt_overlay_runtime_init(state);
		if (error)
			goto out_unlock;
	}

	spin_lock_irqsave(&dev->event_lock, flags);
	if (state->shutdown || state->suspended) {
		error = -ESHUTDOWN;
		goto out_spin_unlock;
	}
	if (state->session) {
		error = -EBUSY;
		goto out_spin_unlock;
	}

	state->runtime_ready = true;
	overlay->state = state;
	overlay->valid = true;
	state->session = overlay;
	if (!state->enabled) {
		state->next_tracking_id = dev->mt->trkid & TRKID_MAX;
		for (i = 0; i < state->num_slots; i++) {
			if (!input_mt_overlay_frame_slot_active(state->source, i))
				continue;
			state->real_output[i] = i;
			state->real_tracking_id[i] = state->source->slots[i].abs[
				ABS_MT_TRACKING_ID - ABS_MT_FIRST];
			state->output_real[i] = i;
		}
		state->enabled = true;
		input_mt_overlay_publish_current(state);
	}

	spin_unlock_irqrestore(&dev->event_lock, flags);
	*session = overlay;
	mutex_unlock(&dev->mutex);
	return 0;

out_spin_unlock:
	spin_unlock_irqrestore(&dev->event_lock, flags);
out_unlock:
	mutex_unlock(&dev->mutex);
	kfree(overlay);
	input_put_device(dev);
	return error;
}
EXPORT_SYMBOL_GPL(input_mt_overlay_attach);

/**
 * input_mt_overlay_update() - atomically replace a session's active contacts
 * @session: session returned by input_mt_overlay_attach()
 * @contacts: complete list of currently active synthetic identities
 * @num_contacts: number of entries in @contacts
 *
 * Contact IDs are caller-stable identities. The axes array contains supported
 * ABS_MT values to update; omitted axes retain the contact's previous values,
 * while omitted contacts go up. ABS_MT_SLOT and ABS_MT_TRACKING_ID are
 * kernel-owned. A contact evicted for a real contact is tombstoned: including
 * its ID before an intervening update omits it returns -EPIPE.
 *
 * The operation does not allocate or sleep and is safe from atomic context.
 * Invalid input or insufficient capacity leaves the published frame and
 * existing contacts unchanged.
 *
 * Return: 0 on success, -EINVAL for malformed or duplicate contacts,
 * -EOPNOTSUPP for unsupported axes/tool types, -ERANGE for invalid tool
 * ranges, -ENOSPC when capacity is unavailable, -EPIPE for an evicted ID,
 * or -ESHUTDOWN after reset, suspend, or device removal.
 */
int input_mt_overlay_update(struct input_mt_overlay *session,
		const struct input_mt_overlay_contact *contacts,
		unsigned int num_contacts)
{
	struct input_mt_overlay_state *state;
	unsigned long flags;
	int error;

	if (!session)
		return -EINVAL;
	if (!session->state)
		return -ESHUTDOWN;

	state = session->state;
	spin_lock_irqsave(&session->dev->event_lock, flags);
	error = input_mt_overlay_update_locked(session, contacts,
					       num_contacts);
	spin_unlock_irqrestore(&session->dev->event_lock, flags);
	return error;
}
EXPORT_SYMBOL_GPL(input_mt_overlay_update);

/**
 * input_mt_overlay_detach() - release synthetic contacts and detach a session
 * @session: session returned by input_mt_overlay_attach()
 *
 * Synthetic contacts are released in one published frame. Real contacts keep
 * their mapped output slots and tracking identities until their physical
 * contacts end. Callers must serialize detach against update on the handle.
 */
void input_mt_overlay_detach(struct input_mt_overlay *session)
{
	struct input_mt_overlay_state *state;
	struct input_dev *dev;
	unsigned long flags;

	if (!session)
		return;

	dev = session->dev;
	state = session->state;
	spin_lock_irqsave(&dev->event_lock, flags);
	if (state && state->session == session) {
		session->valid = false;
		state->session = NULL;
		input_mt_overlay_clear_synthetic(state);
		input_mt_overlay_publish_current(state);
	}
	spin_unlock_irqrestore(&dev->event_lock, flags);

	kfree(session);
	input_put_device(dev);
}
EXPORT_SYMBOL_GPL(input_mt_overlay_detach);

/**
 * input_mt_overlay_reset() - invalidate a session and release its contacts
 * @dev: input device
 *
 * Reset does not rearm the current session. Its owner must detach and attach
 * a new session after the reset. The real frame remains governed by physical
 * SYN_REPORT events.
 */
void input_mt_overlay_reset(struct input_dev *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->event_lock, flags);
	input_mt_overlay_reset_locked(dev);
	spin_unlock_irqrestore(&dev->event_lock, flags);
}
EXPORT_SYMBOL_GPL(input_mt_overlay_reset);

/**
 * input_mt_overlay_suspend() - invalidate a session at device suspend
 * @dev: input device
 *
 * Synthetic contacts are released and the session is invalidated. Resume
 * does not restore or reactivate it.
 */
void input_mt_overlay_suspend(struct input_dev *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->event_lock, flags);
	input_mt_overlay_suspend_locked(dev);
	spin_unlock_irqrestore(&dev->event_lock, flags);
}
EXPORT_SYMBOL_GPL(input_mt_overlay_suspend);

/**
 * input_mt_overlay_resume() - permit a new session after resume
 * @dev: input device
 *
 * This does not restore the session invalidated by suspend.
 */
void input_mt_overlay_resume(struct input_dev *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->event_lock, flags);
	input_mt_overlay_resume_locked(dev);
	spin_unlock_irqrestore(&dev->event_lock, flags);
}
EXPORT_SYMBOL_GPL(input_mt_overlay_resume);
