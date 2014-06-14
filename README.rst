========
Suriwire
========

Introduction
============

Suriwire is a plugin for wireshark that allow you to display
suricata alert and protocol information as element of the
protocol dissection.

.. image:: https://github.com/regit/suriwire/raw/master/doc/suriwire.png
    :alt: wireshark screenshot with suriwire generated info
    :align: center

Installation
============

Copy suriwire.lua to your wireshark plugin directory. For a user,
this is `~/.wireshark/plugins/`.

Usage
=====

Run externally suricata on the pcap file you study to create a
suitable alert file. You need to use the `EVE` output format.

In wireshark, go to `Tools->Wireshark->Activate` and enter the
name of the alert file. You will now find information about the
alerts:

 * In the detail of a packet under `Suricata analysis` element
 * In `Analyse->Expert Info Composite`

You can also filter on the `suricata` protocol. The protocol has
fields like `suricata.sid` and `suricata.msg` which can be used
in filter.

More information on https://home.regit.org/software/suriwire.
