Addresses and payment IDs
=========================

In Monero v0.11.x the wallet had only one address. This is changing now. A
concept of **subaddress** has been introduced.

The first, original address of the wallet is usually known as the *master
address*. All others are just *subaddresses*, even if they represent a separate
account within the wallet.

Monero addresses are base58-encoded strings. You may disassemble each of them
using the excellent `address analysis tool`_ from *luigi1111*.

While the ordinary string representation is perfectly valid to use, you may
want to use validation and other features provided by the ``monero.address``
package.

.. _`address analysis tool`: https://xmr.llcoins.net/addresstests.html

Address validation and instatination
------------------------------------

The function ``monero.address.address()`` will recognize and validate Monero
address, returning an instance that provides additional functionality.

The following example uses addresses from the wallet :doc:`we have generated in
the previous chapter <wallet>`.

Let's start with the master address:

.. code-block:: python

    In [1]: from monero.address import address

    In [2]: a = address('A2GmyHHJ9jtUhPiwoAbR2tXU9LJu2U6fJjcsv3rxgkVRWU6tEYcn6C1NBc7wqCv5V7NW3zeYuzKf6RGGgZTFTpVC4QxAiAX')

    In [3]: a.is_testnet()
    Out[3]: True

    In [4]: a.get_spend_key()
    Out[4]: 'f0481b63cb937fa5960529247ebf6db627ff1b0bb88de9feccc3c504c16aa4b0'

    In [5]: a.get_view_key()
    Out[5]: '2c5ba76d22e48a7ea4ddabea3cce66808ba0cc91265371910f893962e977af1e'

    In [6]: type(a)
    Out[6]: monero.address.Address

We may use a subaddress too:

.. code-block:: python

    In [7]: b = address('BenuGf8eyVhjZwdcxEJY1MHrUfqHjPvE3d7Pi4XY5vQz53VnVpB38bCBsf8AS5rJuZhuYrqdG9URc2eFoCNPwLXtLENT4R7')

    In [8]: b.is_testnet()
    Out[8]: True

    In [9]: b.get_spend_key()
    Out[9]: 'ae7e136f46f618fe7f4a6b323ed60864c20070bf110978d7e3868686d5677318'

    In [10]: b.get_view_key()
    Out[10]: '2bf801cdaf3a8b41020098a6d5e194f48fa62129fe9d8f09d19fee9260665baa'

    In [11]: type(b)
    Out[11]: monero.address.SubAddress

These two classes, ``Address`` and ``SubAddress`` have similar functionality
but one significant difference. Only the former may form *integrated address*.

Payment IDs and integrated addresses
------------------------------------

Each Monero transaction may carry a **payment ID**. It is a 64 or 256-bit long
number that carries additional information between parties. For example, a
merchant can generate a payment ID for each order, or an exchange can assign
one to each user, so they would know what is the purpose of incoming payment.

A short, 64-bit payment ID can be integrated into an address, creating, well...
an **integrated address**.

.. code-block:: python

    In [12]: ia = a.with_payment_id(0xfeedbadbeef)

    In [13]: ia
    Out[13]: ABySz66nm1QUhPiwoAbR2tXU9LJu2U6fJjcsv3rxgkVRWU6tEYcn6C1NBc7wqCv5V7NW3zeYuzKf6RGGgZTFTpVC623BT1ptXvVU2GjR1B

    In [14]: ia.get_base_address()
    Out[14]: A2GmyHHJ9jtUhPiwoAbR2tXU9LJu2U6fJjcsv3rxgkVRWU6tEYcn6C1NBc7wqCv5V7NW3zeYuzKf6RGGgZTFTpVC4QxAiAX

    In [15]: ia.get_base_address() == a
    Out[15]: True

    In [16]: ia.get_payment_id()
    Out[16]: 00000feedbadbeef


Since subaddresses have been introduced, merchants may generate a separate
address for each order, user or any other object they expect the payments
coming to. Therefore, it has been decided that `subaddresses cannot generate
integrated addresses`_.

.. _`subaddresses cannot generate integrated addresses`: https://monero.stackexchange.com/questions/6606/how-to-make-an-integrated-address-based-on-a-subaddress

.. code-block:: python

    In [17]: b.with_payment_id(0xfeedbadbeef)
    ---------------------------------------------------------------------------
    TypeError                                 Traceback (most recent call last)
    <ipython-input-23-5a5811a6962a> in <module>()
    ----> 1 b.with_payment_id(0xfeedbadbeef)

    ~/devel/monero-python/monero/address.py in with_payment_id(self, _)
         99 
        100     def with_payment_id(self, _):
    --> 101         raise TypeError("SubAddress cannot be integrated with payment ID")
        102 
        103 

    TypeError: SubAddress cannot be integrated with payment ID

The ``monero.numbers.PaymentID`` class validates payment IDs. It accepts both
integer and hexadecimal string representations.

.. code-block:: python

    In [18]: from monero.numbers import PaymentID

    In [19]: p1 = PaymentID(0xfeedbadbeef)

    In [20]: p2 = PaymentID('feedbadbeef')

    In [21]: p1 == p2
    Out[21]: True

    In [22]: p1.is_short()
    Out[22]: True

    In [23]: p3 = PaymentID('1234567890abcdef0')

    In [24]: p3
    Out[24]: 000000000000000000000000000000000000000000000001234567890abcdef0

    In [25]: p3.is_short()
    Out[25]: False

Long payment IDs cannot be integrated:

.. code-block:: python

    In [26]: a.with_payment_id(p3)
    ---------------------------------------------------------------------------
    TypeError                                 Traceback (most recent call last)
    <ipython-input-31-7098746f0b69> in <module>()
    ----> 1 a.with_payment_id(p3)

    ~/devel/monero-python/monero/address.py in with_payment_id(self, payment_id)
         73         payment_id = numbers.PaymentID(payment_id)
         74         if not payment_id.is_short():
    ---> 75             raise TypeError("Payment ID {0} has more than 64 bits and cannot be integrated".format(payment_id))
         76         prefix = 54 if self.is_testnet() else 19
         77         data = bytearray([prefix]) + self._decoded[1:65] + struct.pack('>Q', int(payment_id))

    TypeError: Payment ID 000000000000000000000000000000000000000000000001234567890abcdef0 has more than 64 bits and cannot be integrated

API reference
=============

.. automodule:: monero.address
   :members: