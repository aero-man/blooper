.. _notifications:

Working with notifications
==========================

In ``bluepy``, notifications are processed by creating a "delegate" object and 
registering it with the ``Peripheral``. A method in the delegate is called whenever
a notification is received from the peripheral, as shown below:

.. function:: handle_notification(c_handle, data)

    Called when a notification has been received from a ``Peripheral``. Normally
    you will call the peripheral's ``wait_for_notifications()`` method to allow this,
    but note that a Bluetooth LE device may transmit notifications at any time. This
    means that *handle_notification()* can potentially be called when any BluePy call
    is in progress.

    The *c_handle* parameter is the GATT 'handle' for the characteristic which is 
    sending the notification. If a peripheral sends notifications for more than one
    characteristic, this may be used to distinguish them. The 'handle' value can be
    found by calling the ``get_handle()`` method of a ``Characteristic`` object.

    The *data* parameter is a ``str`` (Python 2.x) or ``bytes`` (Python 3.x) value
    containing the notification data. It is recommended you use Python's ``struct``
    module to unpack this, to allow portability between language versions.

It is recommended that the class used for the delegate object is derived from
``btle.DefaultDelegate``. This will ensure that an appropriate default method  
exists for any future calls which may be added to the delegate interface.

Example code
------------

Code to receive notifications from a peripheral can follow the outline below::

    import btle

    class MyDelegate(btle.DefaultDelegate):
        def __init__(self, params):
            btle.DefaultDelegate.__init__(self)
            # ... initialise here

        def handle_notification(self, c_handle, data):
            # ... perhaps check c_handle
            # ... process 'data'

    
    # Initialisation  -------

    p = btle.Peripheral( address )
    p.setDelegate( MyDelegate(params) )

    # Setup to turn notifications on, e.g.
    #   svc = p.get_service_by_uuid( service_uuid )
    #   ch = svc.get_characteristics( char_uuid )[0]
    #   ch.write( setup_data )

    # Main loop --------

    while True:
        if p.wait_for_notifications(1.0):
            # handle_notification() was called
            continue

        print "Waiting..."
        # Perhaps do something else here


