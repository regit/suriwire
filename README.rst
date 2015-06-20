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

Suriwire has parsing for the following events:

* Alerts
* HTTP
* fileinfo
* TLS
* SSH

For example, the preceding screenshot shows how it is possible to search for
TLS session where the subject of the certificate matches a certain string.

Installation
============

Copy or link suriwire.lua to your wireshark plugin directory. For a user,
this is ``~/.wireshark/plugins/``.

Usage
=====

Run externally suricata on the pcap file you study to create a
suitable alert file. You need to use the ``EVE`` output format.
To specify a directory to output files to, you can use the ``-l``
flag in suricata ::

 suricata -r sample.pcap -l log/

Then you will be able to use the ``log/eve.json`` file.

In wireshark, open the pcap file and go to ``Tools->Suricata->Activate``.
Then enter the name of the EVE file. This will parse again the file adding
all Suricata generated information.

You can also indicate which EVE file to parse at start by running something
like: ::

 SURIWIRE_EVE_FILE=log2/eve.json wireshark sample.pcap

You will now find information about the alerts and other events:

* In the detail of a packet under ``Suricata analysis`` element
* In ``Analyse->Expert Info Composite``

You can also filter on the ``suricata`` protocol. The protocol has
fields like ``suricata.alert.sid`` and ``suricata.tls.subject`` which can be used
in filter.

If you reuse the same ``eve.json`` file, you can set the default path in the
protocol preferences inside wireshark.

More information on https://home.regit.org/software/suriwire.
