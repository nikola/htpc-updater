htpc-updater
=============

Automagically install or update [MPC-HC], [LAV Filters] and [madVR] on your local Windows machine. (Starting with 0.4.0, htpc-updater will also update itself.)

Latest release of htpc-updater: [0.8.0]

![alt text][screenshot]

How to use
----------

You have 3 choices:

* Use a pre-compiled [Windows executable]. Unzip to any location. When run, UAC might notify you that the executable requires elevated privileges.
* __or__ compile your own executable, i.e. (1) Install Python 2.7.x. (2) Install requirements with pip. (3) Build with PyInstaller.
* __or__ run the Python script from a Windows shell, i.e. (1) Install requirements with pip. (2) Run /src/htpc-updater.py

Command-line arguments
----------------------

```
usage: htpc-updater [-h]
                    [--install-components = mpchc* | lavfilters* | madvr*]
                    [--install-pre-release = mpchc]
                    [--silent-install = mpchc* | lavfilters*] [--auto-exit]
                    [--relaunch RELAUNCH]

Install or update MPC-HC, LAV Filters and madVR automagically.

optional arguments:
  -h, --help            show this help message and exit
  --install-components = mpchc* | lavfilters* | madvr*
                        Install only comma-separated arguments.
  --install-pre-release = mpchc
                        Install pre-release version of comma-separated arguments if available.
  --silent-install = mpchc* | lavfilters*
                        Install comma-separated arguments without showing installer GUI.
  --auto-exit           Close htpc-updater without prompt for ENTER key.

Examples:
htpc-updater --install-components=mpchc,madvr --silent-install=mpchc
  Install only MPC-HC and madVR, and do not show the installer GUI of MPC-HC.

htpc-updater --install-pre-release=mpchc --auto-exit
  Install the latest MPC-HC nightly build and release versions of LAV Filters and madVR,
  and exit htpc-updater after completion.
```

Notes
-----

htpc-updater does not ship with any binaries for MPC-HC, LAV Filters or madVR. If necessary, it will download the latest release version of each component from the respective authors' official web hosts:

* MPC-HC: http://mpc-hc.org/, effectively from one of SourceForge's filehosts.
* LAV Filters: https://github.com/Nevcairiel/LAVFilters
* madVR: http://madshi.net/

SSL/TLS will be used for connections where available.

The default installation path for each component is {System Drive}{Program Files}, appropriately resolved to the actual location and taking into account whether your system is 32 or 64-bit.

If a component is already installed on your machine, htpc-updater (or the installer of the component) will attempt to upgrade files at the same location. You can choose to change the default installation path in the source code, and htpc-updater will happily leave a previous installation in place.

As of this writing, htpc-updater is known to work on:

* Windows 7 64-bit, Windows 8.1 32/64-bit.

It _should_ work on other versions of Windows, too.

__Disclaimer: No endorsement is implied by the authors of MPC-HC, LAV Filters or madVR.__

[MPC-HC]:http://mpc-hc.org/
[LAV Filters]:https://github.com/Nevcairiel/LAVFilters
[madVR]:http://forum.doom9.org/showthread.php?t=146228
[Windows executable]:https://github.com/nikola/htpc-updater/releases
[0.8.0]:https://github.com/nikola/htpc-updater/releases/tag/0.8.0
[screenshot]:https://raw.githubusercontent.com/nikola/htpc-updater/master/htpc-updater.png "Screenshot"
