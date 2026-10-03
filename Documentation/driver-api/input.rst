Input Subsystem
===============

Input core
----------

.. kernel-doc:: include/linux/input.h
   :internal:

.. kernel-doc:: drivers/input/input.c
   :export:

.. kernel-doc:: drivers/input/ff-core.c
   :export:

.. kernel-doc:: drivers/input/ff-memless.c
   :export:

Multitouch Library
------------------

.. kernel-doc:: include/linux/input/mt.h
   :internal:

.. kernel-doc:: drivers/input/input-mt.c
   :export:

MT overlays
~~~~~~~~~~~

Slot-based devices provide a per-device, GPL-only synthetic-contact overlay.
Use ``input_mt_overlay_attach()``, ``input_mt_overlay_update()`` and
``input_mt_overlay_detach()`` instead of reporting synthetic contacts through
``input_event()`` or ``input_inject_event()``. The overlay does not modify the
driver's physical ``dev->mt`` slots, tracking counter or frame counter, or its
raw key and absolute-axis state.

Input core stages physical key and absolute-axis changes until a physical
``SYN_REPORT``. Buffer-full flushes do not commit this staged state. An overlay
update immediately publishes the last complete physical frame plus the new
synthetic snapshot; it does not wait for another hardware interrupt. Unrelated
events, such as ``EV_MSC`` and ``EV_REL``, retain their normal dispatch path.
Legacy evdev injection remains available and changes raw state as before,
but is not an isolated synthetic source and does not commit a physical frame.

``EVIOCGKEY``, ``EVIOCGABS`` and ``EVIOCGMTSLOTS`` take a snapshot of the last
published state. ``EVIOCGABS`` changes only the queried value; axis bounds,
resolution, fuzz, flat and capabilities are unchanged. For an MT value, the
query uses the last published selected slot.

Each update supplies the complete set of active synthetic contacts.
``input_mt_overlay_contact.id`` is a caller-stable contact identity, not an
input tracking ID. Omitted contacts go up; omitted axes of an existing contact
retain their values. Input core owns output slots and tracking IDs. Duplicate
identities, unsupported axes and invalid tool types fail without publishing a
partial update.

The advertised slot count is never expanded. Physical contacts have priority,
while an existing contact retains its output slot and tracking identity until
it ends. Attach and detach do not restart physical gestures. A new synthetic
DOWN that cannot fit returns ``-ENOSPC``. A synthetic contact evicted by a
physical contact is tombstoned and cannot reappear when capacity becomes free:
an update containing that identity returns ``-EPIPE`` until an intervening
snapshot omits it. Drivers can call ``input_mt_overlay_reserve_slot()`` during
setup to keep a special physical slot fixed and unavailable to synthetic
contacts. GT9886 uses this for its final pen slot.
The compatible pointer follows the oldest merged contact using contact age
independent of tracking-ID wrap.

There is one session per device; a second attach returns ``-EBUSY``. Attach
retains a device reference until detach. The owner must detach when its own
session closes and serialize detach against updates. Attach may sleep; update
does not allocate or sleep and can run in atomic context. Call these APIs
without holding ``dev->event_lock``: input core performs the synchronization
and bounded, nonrecursive handler dispatch.

Input-core reset, suspend, disconnect and unregister invalidate the session
and release synthetic contacts. Drivers that reset or suspend hardware outside
input core must call ``input_mt_overlay_reset()`` or
``input_mt_overlay_suspend()`` at that boundary. Balance suspend calls with
``input_mt_overlay_resume()``. Resume never restores old synthetic contacts;
updates through an invalid session return ``-ESHUTDOWN``. Detach it and attach
a new session after recovery.


Polled input devices
--------------------

.. kernel-doc:: include/linux/input-polldev.h
   :internal:

.. kernel-doc:: drivers/input/input-polldev.c
   :export:

Matrix keyboards/keypads
------------------------

.. kernel-doc:: include/linux/input/matrix_keypad.h
   :internal:

Sparse keymap support
---------------------

.. kernel-doc:: include/linux/input/sparse-keymap.h
   :internal:

.. kernel-doc:: drivers/input/sparse-keymap.c
   :export:

