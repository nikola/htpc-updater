# coding: iso-8859-1
"""
"""
__author__ = 'Nikola Klaric (nikola@klaric.org)'
__copyright__ = 'Copyright (c) 2014 Nikola Klaric'
__version__ = '0.1.0'

import sys
import os
import re
import types
import ctypes
import inspect
import _winreg as registry
import pefile
import requests
from zipfile import ZipFile
from cStringIO import StringIO
from operator import itemgetter
from tempfile import mkstemp


# Support unbuffered, colored console output.
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
ctypes.windll.Kernel32.GetStdHandle.restype = ctypes.c_ulong


LAVFILTERS_CLSID = '{171252A0-8820-4AFE-9DF8-5C92B2D66B04}'
MADVR_CLSID = '{E1A8B82A-32CE-4B0D-BE0D-AA68C772E423}'
HEADERS_TRACKABLE = {'User-agent': 'htpc-updater (https://github.com/nikola/htpc-updater)'}
HEADERS_SF = {'User-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36'}
URL_VERSION = 'http://madshi.net/madVR/version.txt'
URL_ZIP = 'http://madshi.net/madVR.zip'
DEFAULT_PATH = os.environ['PROGRAMFILES']
CONSOLE_HANDLER = ctypes.windll.Kernel32.GetStdHandle(ctypes.c_ulong(0xfffffff5))


def _black():
    return ctypes.windll.Kernel32.SetConsoleTextAttribute(CONSOLE_HANDLER, 15)


def _green():
    return ctypes.windll.Kernel32.SetConsoleTextAttribute(CONSOLE_HANDLER, 10)


def _red():
    return ctypes.windll.Kernel32.SetConsoleTextAttribute(CONSOLE_HANDLER, 12)


def _writeAnyText(text):
    _black() and sys.stdout.write(text)


def _writeOkText(text):
    _green() and sys.stdout.write(text)


def _writeNotOkText(text):
    _red() and sys.stdout.write(text)


def _versiontuple(version):
    version = re.sub(r'[a-z0-9]{7}', '', version)
    version = re.sub(r'[^0-9\._]', '', version)
    version = re.sub(r'^_|_$|__+', '', version)
    version = re.sub(r'_', '.', version).strip()
    return tuple(map(int, (version.split('.'))))


def _writeTempFile(payload):
    fd, pathname = mkstemp(suffix='.exe')
    fp = os.fdopen(fd, 'wb')
    fp.write(payload)
    fp.close()

    return pathname


def _getDefaultInstallationPath(component):
    pathname = os.path.join(DEFAULT_PATH, component)
    if not os.path.exists(pathname):
        os.makedirs(pathname)

    return pathname


def _getComLocationFromRegistry(clsid):
    connection = registry.ConnectRegistry(None, registry.HKEY_CLASSES_ROOT)
    key = registry.OpenKey(connection, r'CLSID\%s\InprocServer32' % clsid)
    pathname = registry.QueryValueEx(key, None)[0]
    key.Close()

    if os.path.exists(pathname):
        return pathname
    else:
        raise


def _getAppLocationFromRegistry(software):
    connection = registry.ConnectRegistry(None, registry.HKEY_CURRENT_USER)
    key = registry.OpenKey(connection, r'Software\%s' % software)
    pathname = registry.QueryValueEx(key, 'ExePath')[0]
    key.Close()

    if os.path.exists(pathname):
        return pathname
    else:
        raise


def _getComVersionLocation(key):
    try:
        location = _getComLocationFromRegistry(key)
        fields = pefile.PE(data=open(location, 'rb').read())
        version = fields.FileInfo[0].StringTable[0].entries['ProductVersion']
    except:
        return None, None
    else:
        return version, os.path.dirname(location)


def _mpcHc_getLatestReleaseVersion(self):
    try:
        latestVersion = '.'.join(map(str, max([_versiontuple(tag.get('name')) for tag in requests.get('https://api.github.com/repos/mpc-hc/mpc-hc/tags').json()])))
    except:
        latestVersion = None

    return latestVersion


def _mpcHc_getInstalledVersion(self):
    try:
        location = _getAppLocationFromRegistry(self._identifier)
        fields = pefile.PE(data=open(location, 'rb').read())
        version = '.'.join(map(str, _versiontuple(fields.FileInfo[0].StringTable[0].entries['ProductVersion'])))
    except:
        return None, None
    else:
        return version, os.path.dirname(location)


def _mpcHc_installLatestReleaseVersion(self, releaseVersion, currentMpcHcPath):
    _writeAnyText('Identifying filename of MPC-HC download ...')
    response = requests.get('http://mpc-hc.org/downloads/').text
    url = re.search('<a href="([^\"]+)">installer</a>', response).group(1)
    _writeAnyText(' done.\n')

    _writeAnyText('Selecting filehost for MPC-HC download ...')
    response = requests.get(url, headers=HEADERS_SF).text
    url = re.search('<meta[^>]*?url=(.*?)["\']', response, re.I).group(1)
    _writeAnyText(' done.\n')

    _writeAnyText('Downloading %s ...' % url)
    response = requests.get(url, headers=HEADERS_SF).content
    _writeAnyText(' done.\n')

    pathname = _writeTempFile(response)

    _writeAnyText('Installing MPC-HC %s ...' % releaseVersion)
    os.system('""%s" /VERYSILENT /NORESTART /NOCLOSEAPPLICATIONS""' % pathname)
    _writeAnyText(' done.\n')

    os.remove(pathname)

    return _mpcHc_getInstalledVersion(self)[1]


def _lavFilters_getLatestReleaseVersion(self):
    try:
        response = requests.get('https://api.github.com/repos/Nevcairiel/LAVFilters/releases').json()
        latestVersion = response[0].get('tag_name')
    except:
        latestVersion = None

    return latestVersion


def _lavFilters_getInstalledVersion(self):
    version, location = _getComVersionLocation(self._identifier)
    if location.endswith('x86') or location.endswith('x64'):
         location = os.path.abspath(os.path.join(location, os.pardir))
    return version, location


def _lavFilters_installLatestReleaseVersion(self, releaseVersion, currentLavFiltersPath):
    url = 'https://github.com/Nevcairiel/LAVFilters/releases/download/{0}/LAVFilters-{0}-Installer.exe'.format(releaseVersion)

    _writeAnyText('Downloading %s ...' % url)
    response = requests.get(url).content
    _writeAnyText(' done.\n')

    pathname = _writeTempFile(response)

    _writeAnyText('Installing LAV Filters %s ...' % releaseVersion)
    os.system('""%s" /VERYSILENT /NORESTART /NOCLOSEAPPLICATIONS""' % pathname)
    _writeAnyText(' done.\n')

    os.remove(pathname)

    return _lavFilters_getInstalledVersion(self)[1]


def _madVr_getLatestReleaseVersion(self):
    try:
        latestVersion = requests.get(URL_VERSION, headers=HEADERS_TRACKABLE).text
    except:
        latestVersion = None

    return latestVersion


def _madVr_getInstalledVersion(self):
    return _getComVersionLocation(self._identifier)


def _madVr_installLatestReleaseVersion(self, releaseVersion, currentMadVrPath):
    _writeAnyText('Downloading %s ...' % URL_ZIP)
    madVrZipFile = requests.get(URL_ZIP, headers=HEADERS_TRACKABLE).content
    _writeAnyText(' done.\n')

    _writeAnyText('Installing madVR %s ...' % releaseVersion)
    madVrInstallationPath = currentMadVrPath or _getDefaultInstallationPath('madVR')

    madVrZipArchive = ZipFile(StringIO(madVrZipFile))
    madVrZipArchive.extractall(madVrInstallationPath)

    regSvr = os.path.join(os.environ['SYSTEMROOT'], 'System32', 'regsvr32')
    cmdArg = os.path.join(madVrInstallationPath, 'madVR.ax')
    os.system('""%s" /s "%s""' % (regSvr, cmdArg))

    _writeAnyText(' done.\n')

    return madVrInstallationPath


class Component(object):

    def __init__(self, *args, **kwargs):
        self._identifier = args[0]
        for method in map(itemgetter(0), inspect.getmembers(self, predicate=inspect.ismethod)):
            if method in kwargs: setattr(self, method, types.MethodType(kwargs.get(method), self))

    def getLatestReleaseVersion(self, *args, **kwargs):
        raise NotImplementedError

    def getInstalledVersion(self, *args, **kwargs):
        raise NotImplementedError

    def installLatestReleaseVersion(self, *args, **kwargs):
        raise NotImplementedError


def run():
    components = [
        ('MPC-HC', Component(r'MPC-HC\MPC-HC',
            getLatestReleaseVersion =_mpcHc_getLatestReleaseVersion,
            getInstalledVersion = _mpcHc_getInstalledVersion,
            installLatestReleaseVersion = _mpcHc_installLatestReleaseVersion,
        )),
        ('LAV Filters', Component(LAVFILTERS_CLSID,
            getLatestReleaseVersion =_lavFilters_getLatestReleaseVersion,
            getInstalledVersion = _lavFilters_getInstalledVersion,
            installLatestReleaseVersion = _lavFilters_installLatestReleaseVersion,
        )),
         ('madVR', Component(MADVR_CLSID,
            getLatestReleaseVersion =_madVr_getLatestReleaseVersion,
            getInstalledVersion = _madVr_getInstalledVersion,
            installLatestReleaseVersion = _madVr_installLatestReleaseVersion,
        )),
    ]

    for name, instance in components:
        releaseVersion = instance.getLatestReleaseVersion()
        if releaseVersion is None:
            _writeNotOkText('ERROR: Could not retrieve version info of the latest %s release.\n' % name)
        else:
            _writeAnyText('Latest release version of %s: %s\n' % (name, releaseVersion))

            installedVersion, detectedInstallationPath = instance.getInstalledVersion()
            mustInstall = False
            if installedVersion is not None:
                _writeAnyText('Installed version: %s\n\t%s\n' % (installedVersion, detectedInstallationPath))

                if _versiontuple(installedVersion) < _versiontuple(releaseVersion):
                    mustInstall = True
                else:
                    _writeOkText('%s does not need to be updated.\n' % name)
            else:
                _writeAnyText('%s does not seem to be installed on the local machine.\n' % name)
                mustInstall = True

            if mustInstall:
                try:
                    currentInstallationPath = instance.installLatestReleaseVersion(releaseVersion, detectedInstallationPath)
                except Exception, e:
                    _writeNotOkText(' ERROR: %s\n' % e.message)
                else:
                    if detectedInstallationPath != currentInstallationPath:
                        _writeAnyText('%s %s is now installed in:\n\t%s\n' % (name, releaseVersion, currentInstallationPath))
                        if installedVersion is not None:
                            _writeAnyText('Your previous installation of %s %s remains in:\n\t%s\n' % (name, installedVersion, detectedInstallationPath))
                    _writeOkText('Successfully %s %s. No errors.\n' % ('updated' if installedVersion is not None else 'installed', name))

        _writeOkText('\n')


if __name__ == "__main__":
    run()

    _black() and raw_input('Press ENTER to exit ...')
