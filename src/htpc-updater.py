# coding: iso-8859-1
"""
"""
__author__ = 'Nikola Klaric (nikola@generic.company)'
__copyright__ = 'Copyright (c) 2014 Nikola Klaric'
__version__ = '0.5.2'

import sys
import os
import argparse
import re
import time
import random
import _winreg as registry
from inspect import getmembers, ismethod
from types import MethodType
from zipfile import ZipFile
from cStringIO import StringIO
from operator import itemgetter
from tempfile import mkstemp
from hashlib import sha1 as SHA1
from shutil import copy
from ctypes import windll, c_ulong, create_unicode_buffer

import pefile
import requests



# Support unbuffered, colored console output.
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
windll.Kernel32.GetStdHandle.restype = c_ulong


HTPC_UPDATER_RELEASES = 'https://api.github.com/repos/nikola/htpc-updater/releases'
HTPC_UPDATER_DL_PATH = 'https://github.com/nikola/htpc-updater/releases/download/{0}/htpc-updater-{0}.zip'
MPCHC_TAGS = 'https://api.github.com/repos/mpc-hc/mpc-hc/tags'
MPCHC_DOWNLADS = 'http://mpc-hc.org/downloads/'
MPCHC_NIGHTLY_URL = 'http://nightly.mpc-hc.org/'
MPCHC_NIGHTLY_H5AI_QUERY = {'action':'get', 'items': 'true', 'itemsHref':'/', 'itemsWhat': '1'}
MPCHC_NIGHTLY_DL_PATH = 'http://nightly.mpc-hc.org/MPC-HC.{0}.x86.exe'
LAVFILTERS_CLSID = '{171252A0-8820-4AFE-9DF8-5C92B2D66B04}'
LAVFILTERS_RELEASES = 'https://api.github.com/repos/Nevcairiel/LAVFilters/releases'
LAVFILTERS_DL_PATH = 'https://github.com/Nevcairiel/LAVFilters/releases/download/{0}/LAVFilters-{0}-Installer.exe'
MADVR_CLSID = '{E1A8B82A-32CE-4B0D-BE0D-AA68C772E423}'
HEADERS_TRACKABLE = {'User-agent': 'htpc-updater (https://github.com/nikola/htpc-updater)'}
HEADERS_SF = {
    'User-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.%d.116 Safari/537.36'
        % random.randint(1000, 3000)
}
MADVR_URL_VERSION = 'http://madshi.net/madVR/version.txt'
MADVR_URL_HASH = 'http://madshi.net/madVR/sha1.txt'
MADVR_URL_ZIP = 'http://madshi.net/madVR.zip'
DEFAULT_PATH = os.environ['PROGRAMFILES']
CONSOLE_HANDLER = windll.Kernel32.GetStdHandle(c_ulong(0xfffffff5))


# Enable SSL support in requests library when running as EXE.
if getattr(sys, 'frozen', None):
     os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(sys._MEIPASS, 'cacert.pem')


def _black():
    return windll.Kernel32.SetConsoleTextAttribute(CONSOLE_HANDLER, 15)


def _green():
    return windll.Kernel32.SetConsoleTextAttribute(CONSOLE_HANDLER, 10)


def _red():
    return windll.Kernel32.SetConsoleTextAttribute(CONSOLE_HANDLER, 12)


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


def _getLongPathName(pathname):
    buf = create_unicode_buffer(500)
    WinPath = windll.kernel32.GetLongPathNameW
    WinPath(unicode(pathname), buf, 500)
    return str(buf.value)


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


def _getLatestGitHubReleaseVersion(url):
    try:
        response = requests.get(url, headers=HEADERS_TRACKABLE).json()
        latestVersion = response[0].get('tag_name')
    except:
        latestVersion = None

    return latestVersion


def _mpcHc_getLatestReleaseVersion(self):
    try:
        latestReleaseVersion = '.'.join(map(str, max([_versiontuple(tag.get('name'))
            for tag in requests.get(MPCHC_TAGS, headers=HEADERS_TRACKABLE).json()])))
    except:
        latestReleaseVersion = None

    return latestReleaseVersion


def _mpcHc_getLatestPreReleaseVersion(self):
    try:
        items = requests.post(MPCHC_NIGHTLY_URL, MPCHC_NIGHTLY_H5AI_QUERY, headers=HEADERS_TRACKABLE).json().get('items')
        latestPreReleaseVersion = re.match(r'^/MPC-HC\.((\d+\.?)+)\.x86\.exe$',
            filter(lambda i: i.get('absHref').endswith('.x86.exe'), items)[0].get('absHref')).group(1)
    except:
        latestPreReleaseVersion = None

    return latestPreReleaseVersion


def _mpcHc_getInstalledVersion(self):
    try:
        location = _getAppLocationFromRegistry(self._identifier)
        fields = pefile.PE(data=open(location, 'rb').read())
        version = '.'.join(map(str, _versiontuple(fields.FileInfo[0].StringTable[0].entries['ProductVersion'])))
    except:
        return None, None
    else:
        return version, os.path.dirname(location)


def _mpcHc_install(exe, version):
    pathname = _writeTempFile(exe)

    _writeAnyText('Installing MPC-HC %s ...' % version)
    os.system('""%s" /NORESTART /NOCLOSEAPPLICATIONS""' % pathname)
    _writeAnyText(' done.\n')

    os.remove(pathname)


def _mpcHc_installLatestReleaseVersion(self, releaseVersion, currentMpcHcPath):
    _writeAnyText('Identifying filename of MPC-HC download ...')
    response = requests.get(MPCHC_DOWNLADS, headers=HEADERS_TRACKABLE).text
    initialUrl = re.search('<a href="([^\"]+)">installer</a>', response).group(1)
    _writeAnyText(' done.\n')

    retries = 0
    while True:
        _writeAnyText('Selecting filehost for MPC-HC download ...')
        response = requests.get(initialUrl, headers=HEADERS_SF).text
        filehostResolver = re.search('<meta[^>]*?url=(.*?)["\']', response, re.I).group(1)
        filehostName = re.search('use_mirror=([a-z\-]+)', filehostResolver).group(1)
        filehostUrl = filehostResolver[:filehostResolver.index('?')].replace('downloads', filehostName + '.dl')
        _writeAnyText(' done: %s.\n' % filehostName)

        time.sleep(1)

        _writeAnyText('Downloading %s ...' % filehostUrl)
        response = requests.get(filehostUrl, headers=HEADERS_SF).content
        _writeAnyText(' done.\n')

        if response.strip().endswith('</html>') or len(response) < 1e6:
            retries += 1

            if retries < 10:
                _writeNotOkText('Selected filehost is not serving MPC-HC %s, trying another filehost.\n' % releaseVersion)
                time.sleep(2)
            else:
                _writeNotOkText('It appears no filehost can be found serving MPC-HC %s, aborting for now.\n' % releaseVersion)
                return
        else:
            break

    _mpcHc_install(response, releaseVersion)

    return _mpcHc_getInstalledVersion(self)[1]


def _mpcHc_installLatestPreReleaseVersion(self, preReleaseVersion, currentMpcHcPath):
    url = MPCHC_NIGHTLY_DL_PATH.format(preReleaseVersion)
    _writeAnyText('Downloading %s ...' % url)
    response = requests.get(url, headers=HEADERS_TRACKABLE).content
    _writeAnyText(' done.\n')

    _mpcHc_install(response, preReleaseVersion)

    return _mpcHc_getInstalledVersion(self)[1]


def _lavFilters_getLatestReleaseVersion(self):
    return _getLatestGitHubReleaseVersion(LAVFILTERS_RELEASES)


def _lavFilters_getInstalledVersion(self):
    version, location = _getComVersionLocation(self._identifier)
    if location.endswith('x86') or location.endswith('x64'):
         location = os.path.abspath(os.path.join(location, os.pardir))
    return version, location


def _lavFilters_installLatestReleaseVersion(self, releaseVersion, currentLavFiltersPath):
    url = LAVFILTERS_DL_PATH.format(releaseVersion)

    _writeAnyText('Downloading %s ...' % url)
    response = requests.get(url, headers=HEADERS_TRACKABLE).content
    _writeAnyText(' done.\n')

    pathname = _writeTempFile(response)

    _writeAnyText('Installing LAV Filters %s ...' % releaseVersion)
    os.system('""%s" /NORESTART /NOCLOSEAPPLICATIONS""' % pathname)
    _writeAnyText(' done.\n')

    os.remove(pathname)

    return _lavFilters_getInstalledVersion(self)[1]


def _madVr_getLatestReleaseVersion(self):
    try:
        latestVersion = requests.get(MADVR_URL_VERSION, headers=HEADERS_TRACKABLE).text
    except:
        latestVersion = None

    return latestVersion


def _madVr_getInstalledVersion(self):
    return _getComVersionLocation(self._identifier)


def _madVr_installLatestReleaseVersion(self, releaseVersion, currentMadVrPath):
    _writeAnyText('Downloading %s ...' % MADVR_URL_ZIP)
    madVrZipFile = requests.get(MADVR_URL_ZIP, headers=HEADERS_TRACKABLE).content
    _writeAnyText(' done.\n')

    _writeAnyText('Verifying SHA1 of downloaded ZIP file ...')
    madVrZipHashShould = requests.get(MADVR_URL_HASH, headers=HEADERS_TRACKABLE).content
    sha1 = SHA1()
    sha1.update(madVrZipFile)
    madVrZipHashIs = sha1.hexdigest()
    if madVrZipHashIs == madVrZipHashShould:
        _writeAnyText(' OK!\n')
    else:
        _writeNotOkText(' ERROR: SHA1 is %s but should be %s!\n' % (madVrZipHashIs, madVrZipHashShould))
        _writeNotOkText('Aborting installation of madVR %s.\n' % releaseVersion)
        return

    _writeAnyText('Installing madVR %s ...' % releaseVersion)
    madVrInstallationPath = currentMadVrPath or _getDefaultInstallationPath('madVR')

    ZipFile(StringIO(madVrZipFile)).extractall(madVrInstallationPath)

    regSvr = os.path.join(os.environ['SYSTEMROOT'], 'System32', 'regsvr32')
    cmdArg = os.path.join(madVrInstallationPath, 'madVR.ax')
    os.system('""%s" /s "%s""' % (regSvr, cmdArg))

    _writeAnyText(' done.\n')

    return madVrInstallationPath


class Component(object):

    def __init__(self, *args, **kwargs):
        self._identifier = args[0]
        for method in map(itemgetter(0), getmembers(self, predicate=ismethod)):
            if method in kwargs: setattr(self, method, MethodType(kwargs.get(method), self))

    def getLatestReleaseVersion(self, *args, **kwargs): pass
    def getLatestPreReleaseVersion(self, *args, **kwargs): pass
    def getInstalledVersion(self, *args, **kwargs): pass
    def installLatestReleaseVersion(self, *args, **kwargs): pass
    def installLatestPreReleaseVersion(self, *args, **kwargs): pass


def updateComponents(arguments):
    installPreReleaseList = arguments.get('installPreReleaseList') or ''

    components = [
        ('MPC-HC', 'mpchc' in installPreReleaseList, Component(r'MPC-HC\MPC-HC',
            getLatestReleaseVersion =_mpcHc_getLatestReleaseVersion,
            getLatestPreReleaseVersion =_mpcHc_getLatestPreReleaseVersion,
            getInstalledVersion = _mpcHc_getInstalledVersion,
            installLatestReleaseVersion = _mpcHc_installLatestReleaseVersion,
            installLatestPreReleaseVersion = _mpcHc_installLatestPreReleaseVersion,
        )),
        ('LAV Filters', 'lavfilters' in installPreReleaseList, Component(LAVFILTERS_CLSID,
            getLatestReleaseVersion =_lavFilters_getLatestReleaseVersion,
            getInstalledVersion = _lavFilters_getInstalledVersion,
            installLatestReleaseVersion = _lavFilters_installLatestReleaseVersion,
        )),
        ('madVR', 'madvr' in installPreReleaseList, Component(MADVR_CLSID,
            getLatestReleaseVersion =_madVr_getLatestReleaseVersion,
            getInstalledVersion = _madVr_getInstalledVersion,
            installLatestReleaseVersion = _madVr_installLatestReleaseVersion,
        )),
    ]

    for name, pre, instance in components:
        prefix = 'pre-' if pre else ''

        latestVersion = instance.getLatestPreReleaseVersion() if pre else instance.getLatestReleaseVersion()
        if latestVersion is None:
            _writeNotOkText('ERROR: Could not retrieve version info of the latest %s %srelease.\n' % (name, prefix))
        else:
            _writeAnyText('Latest %srelease version of %s: %s\n' % (prefix, name, latestVersion))

            installedVersion, detectedInstallationPath = instance.getInstalledVersion()
            mustInstall = False
            if installedVersion is not None:
                _writeAnyText('Installed version: %s\n\t%s\n' % (installedVersion, detectedInstallationPath))

                if _versiontuple(installedVersion) < _versiontuple(latestVersion):
                    mustInstall = True
                else:
                    _writeOkText('%s does not need to be updated.\n' % name)
            else:
                _writeAnyText('%s does not seem to be installed on the local machine.\n' % name)
                mustInstall = True

            if mustInstall:
                try:
                    if pre:
                        currentInstallationPath = instance.installLatestPreReleaseVersion(latestVersion, detectedInstallationPath)
                    else:
                        currentInstallationPath = instance.installLatestReleaseVersion(latestVersion, detectedInstallationPath)
                except Exception, e:
                    _writeNotOkText(' ERROR: %s\n' % e.message)
                else:
                    if currentInstallationPath is not None:
                        if detectedInstallationPath != currentInstallationPath:
                            _writeAnyText('%s %s is now installed in:\n\t%s\n'
                                % (name, latestVersion, currentInstallationPath))
                            if installedVersion is not None:
                                _writeAnyText('Your previous installation of %s %s remains in:\n\t%s\n'
                                    % (name, installedVersion, detectedInstallationPath))
                        _writeOkText('Successfully %s %s. No errors.\n'
                            % ('updated' if installedVersion is not None else 'installed', name))

        _writeOkText('\n')


def _updateSelf():
    if hasattr(sys, 'frozen'):
        htpcUpdaterExecutable = _getLongPathName(sys.executable)
        htpcUpdaterDirectory = os.path.dirname(htpcUpdaterExecutable)

        _writeAnyText('Checking for new version of htpc-updater ...')
        releaseVersion = _getLatestGitHubReleaseVersion(HTPC_UPDATER_RELEASES)
        if _versiontuple(releaseVersion) > _versiontuple(__version__):
            _writeAnyText(' %s is available, starting upgrade process.\n' % releaseVersion)

            url = HTPC_UPDATER_DL_PATH.format(releaseVersion)
            _writeAnyText('Downloading %s ...' % url)
            htpcUpdaterZipFile = requests.get(url, headers=HEADERS_TRACKABLE).content
            _writeAnyText(' done.\n')

            htpcUpdaterNew = _writeTempFile(ZipFile(StringIO(htpcUpdaterZipFile)).open('htpc-updater.exe').read())

            args = sys.argv[:]
            args = ['"%s"' % arg for arg in args]
            args.append('"--relaunch=%s"' % htpcUpdaterDirectory)

            # Clear the PATH so that MSVCRT libraries are not conflicting with libraries
            # from other programs that ship their own, avoiding error R6034.
            # This only affects the currently running htpc-updater.exe.
            environ = os.environ.copy()
            environ.pop('PATH', None)

            _writeAnyText('Restarting htpc-updater ...\n\n')
            os.chdir(os.path.dirname(htpcUpdaterNew))
            os.execve(htpcUpdaterNew, args, environ)
        else:
            _writeAnyText(' %s is the latest version.\n\n' % __version__)


def _isUpdatingSelf(arguments):
    return bool(arguments.get('relaunch'))


def _cleanupUpdate(arguments):
    copy(_getLongPathName(sys.executable), os.path.join(arguments.get('relaunch'), 'htpc-updater.exe'))


if __name__ == '__main__':
    _writeAnyText('htpc-updater %s (https://github.com/nikola/htpc-updater)\n\n' % __version__)

    parser = argparse.ArgumentParser()
    parser.add_argument('--install-pre-release', dest='installPreReleaseList', action='store',
        help='Install pre-release versions of comma-separated argument if available.')
    parser.add_argument('--auto-exit', dest='autoExit', action='store_true',
        help='Close htpc-updater without prompt for ENTER key.')
    parser.add_argument('--relaunch', action='store')
    args = vars(parser.parse_args())

    if _isUpdatingSelf(args):
        _cleanupUpdate(args)
    else:
        _updateSelf()

    updateComponents(args)

    _black()
    if not args.get('autoExit'):
        raw_input('Press ENTER to exit ...')
