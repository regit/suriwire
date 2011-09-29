========
Suriwire
========

Introduction
============

Suriwire is a plugin for wireshark that allow you to display
suricata alert as element of the protocol dissection.

Installation
============

Copy suriwire.lua to your wireshark plugin directory. For a user,
this is `~/.wireshark/plugins/`.

Usage
=====

Run externally suricata on the pcap file you study to create a
suitable alert file.
In wireshark, go to `Tools->Wireshark->Activate` and enter the
name of the alert file. You will now find information about the
alerts::
 * In the detail of a packet under `Suricata analysis` element
 * In `Analyse->Expert Info Composite`
