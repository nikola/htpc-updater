# coding: iso-8859-1
"""
"""
__author__ = 'Nikola Klaric (nikola@generic.company)'
__copyright__ = 'Copyright (c) 2014 Nikola Klaric'
__version__ = '0.6.2'

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
from ctypes import windll, c_ulong
from subprocess import check_output

import requests


# Support unbuffered, colored console output.
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
windll.Kernel32.GetStdHandle.restype = c_ulong


HTPC_UPDATER_RELEASES = 'https://api.github.com/repos/nikola/htpc-updater/releases'
HTPC_UPDATER_PROJECT = 'https://github.com/nikola/htpc-updater'
HTPC_UPDATER_DL_PATH = HTPC_UPDATER_PROJECT + '/releases/download/{0}/htpc-updater-{0}.zip'
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
BLACK, GREEN, RED = 15, 10, 12


# Enable SSL support in requests library when running as EXE.
if getattr(sys, 'frozen', None):
     os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(sys._MEIPASS, 'cacert.pem')


def _log(text, color=BLACK):
    windll.Kernel32.SetConsoleTextAttribute(CONSOLE_HANDLER, color)
    sys.stdout.write(text)


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


def _getProductVersion(pathname):
    result = check_output(
        " ".join([
            os.path.join(os.environ['SYSTEMROOT'], 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
            "(Get-Item '%s').VersionInfo.ProductVersion" % pathname,
        ]),
    ).rstrip()
    return result


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
        version = _getProductVersion(location)
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
        version = _getProductVersion(location)
    except:
        return None, None
    else:
        return version, os.path.dirname(location)


def _mpcHc_install(exe, version, silent):
    pathname = _writeTempFile(exe)

    _log('Installing MPC-HC %s ...' % version)
    verySilent = '/VERYSILENT ' if silent else ''
    os.system('""%s" /NORESTART %s/NOCLOSEAPPLICATIONS""' % (pathname, verySilent))
    os.remove(pathname)
    _log(' done.\n')


def _mpcHc_installLatestReleaseVersion(self, version, path, silent=False):
    _log('Identifying filename of MPC-HC download ...')
    response = requests.get(MPCHC_DOWNLADS, headers=HEADERS_TRACKABLE).text
    initialUrl = re.search('<a href="([^\"]+)">installer</a>', response).group(1)
    _log(' done.\n')

    retries = 0
    while True:
        _log('Selecting filehost for MPC-HC download ...')
        response = requests.get(initialUrl, headers=HEADERS_SF).text
        filehostResolver = re.search('<meta[^>]*?url=(.*?)["\']', response, re.I).group(1)
        filehostName = re.search('use_mirror=([a-z\-]+)', filehostResolver).group(1)
        filehostUrl = filehostResolver[:filehostResolver.index('?')].replace('downloads', filehostName + '.dl')
        _log(' done: %s.\n' % filehostName)

        time.sleep(1)

        _log('Downloading %s ...' % filehostUrl)
        response = requests.get(filehostUrl, headers=HEADERS_SF).content
        _log(' done.\n')

        if response.strip().endswith('</html>') or len(response) < 1e6:
            retries += 1

            if retries < 10:
                _log('Selected filehost is not serving MPC-HC %s, trying another filehost.\n' % version, RED)
                time.sleep(2)
            else:
                _log('It appears no filehost can be found serving MPC-HC %s, aborting for now.\n' % version, RED)
                return
        else:
            break

    _mpcHc_install(response, version, silent)


def _mpcHc_installLatestPreReleaseVersion(self, version, path, silent=False):
    url = MPCHC_NIGHTLY_DL_PATH.format(version)
    _log('Downloading %s ...' % url)
    response = requests.get(url, headers=HEADERS_TRACKABLE).content
    _log(' done.\n')

    _mpcHc_install(response, version, silent)


def _lavFilters_getLatestReleaseVersion(self):
    return _getLatestGitHubReleaseVersion(LAVFILTERS_RELEASES)


def _lavFilters_getInstalledVersion(self):
    version, location = _getComVersionLocation(self._identifier)
    if location.endswith('x86') or location.endswith('x64'):
         location = os.path.abspath(os.path.join(location, os.pardir))
    return version, location


def _lavFilters_installLatestReleaseVersion(self, version, path, silent=False):
    url = LAVFILTERS_DL_PATH.format(version)

    _log('Downloading %s ...' % url)
    response = requests.get(url, headers=HEADERS_TRACKABLE).content
    _log(' done.\n')

    pathname = _writeTempFile(response)

    _log('Installing LAV Filters %s ...' % version)
    os.system('""%s" /NORESTART /NOCLOSEAPPLICATIONS""' % pathname)
    os.remove(pathname)
    _log(' done.\n')


def _madVr_getLatestReleaseVersion(self):
    try:
        latestVersion = requests.get(MADVR_URL_VERSION, headers=HEADERS_TRACKABLE).text
    except:
        latestVersion = None

    return latestVersion


def _madVr_getInstalledVersion(self):
    return _getComVersionLocation(self._identifier)


def _madVr_installLatestReleaseVersion(self, version, path, silent=False):
    _log('Downloading %s ...' % MADVR_URL_ZIP)
    madVrZipFile = requests.get(MADVR_URL_ZIP, headers=HEADERS_TRACKABLE).content
    _log(' done.\n')

    _log('Verifying SHA1 of downloaded ZIP file ...')
    madVrZipHashShould = requests.get(MADVR_URL_HASH, headers=HEADERS_TRACKABLE).content
    sha1 = SHA1()
    sha1.update(madVrZipFile)
    madVrZipHashIs = sha1.hexdigest()
    if madVrZipHashIs == madVrZipHashShould:
        _log(' OK!\n')
    else:
        _log(' ERROR: SHA1 is %s but should be %s!\n' % (madVrZipHashIs, madVrZipHashShould), RED)
        _log('Aborting installation of madVR %s.\n' % version, RED)
        return

    _log('Installing madVR %s ...' % version)
    madVrInstallationPath = path or _getDefaultInstallationPath('madVR')

    ZipFile(StringIO(madVrZipFile)).extractall(madVrInstallationPath)

    os.system('""%s" /s "%s""'
        % (os.path.join(os.environ['SYSTEMROOT'], 'System32', 'regsvr32'), os.path.join(madVrInstallationPath, 'madVR.ax')))

    _log(' done.\n')


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
    silentInstallList = arguments.get('silentInstallList') or ''

    components = [
        ('MPC-HC',
            'mpchc' in installPreReleaseList,
            'mpchc' in silentInstallList,
            Component(r'MPC-HC\MPC-HC',
                getLatestReleaseVersion =_mpcHc_getLatestReleaseVersion,
                getLatestPreReleaseVersion =_mpcHc_getLatestPreReleaseVersion,
                getInstalledVersion = _mpcHc_getInstalledVersion,
                installLatestReleaseVersion = _mpcHc_installLatestReleaseVersion,
                installLatestPreReleaseVersion = _mpcHc_installLatestPreReleaseVersion,
            )
        ),
        ('LAV Filters',
            'lavfilters' in installPreReleaseList,
            'lavfilters' in silentInstallList,
            Component(LAVFILTERS_CLSID,
                getLatestReleaseVersion =_lavFilters_getLatestReleaseVersion,
                getInstalledVersion = _lavFilters_getInstalledVersion,
                installLatestReleaseVersion = _lavFilters_installLatestReleaseVersion,
            )
        ),
        ('madVR',
            'madvr' in installPreReleaseList,
            'madvr' in silentInstallList,
            Component(MADVR_CLSID,
                getLatestReleaseVersion =_madVr_getLatestReleaseVersion,
                getInstalledVersion = _madVr_getInstalledVersion,
                installLatestReleaseVersion = _madVr_installLatestReleaseVersion,
            )
        ),
    ]

    for name, pre, silent, instance in components:
        _log('\n')

        prefix = 'pre-' if pre else ''

        latestVersion = instance.getLatestPreReleaseVersion() if pre else instance.getLatestReleaseVersion()
        if latestVersion is None:
            _log('ERROR: Could not retrieve version info of the latest %s %srelease.\n' % (name, prefix), RED)
        else:
            _log('Latest %srelease version of %s: %s\n' % (prefix, name, latestVersion))

            installedVersion, detectedInstallationPath = instance.getInstalledVersion()
            mustInstall = False
            if installedVersion is not None:
                _log('Installed version: %s\n\t%s\n' % (installedVersion, detectedInstallationPath))

                if _versiontuple(installedVersion) < _versiontuple(latestVersion):
                    mustInstall = True
                else:
                    _log('%s does not need to be updated.\n' % name, GREEN)
            else:
                _log('%s does not seem to be installed on the local machine.\n' % name)
                mustInstall = True

            if mustInstall:
                try:
                    if pre:
                        instance.installLatestPreReleaseVersion(latestVersion, detectedInstallationPath, silent)
                    else:
                        instance.installLatestReleaseVersion(latestVersion, detectedInstallationPath, silent)
                except Exception, e:
                    _log(' ERROR: %s\n' % e.message, RED)
                else:
                    currentInstallationPath = instance.getInstalledVersion()[1]
                    if currentInstallationPath is not None:
                        if detectedInstallationPath != currentInstallationPath:
                            _log('%s %s is now installed in:\n\t%s\n'
                                % (name, latestVersion, currentInstallationPath))
                            if installedVersion is not None:
                                _log('Your previous installation of %s %s remains in:\n\t%s\n'
                                    % (name, installedVersion, detectedInstallationPath))
                        _log('Successfully %s %s. No errors.\n'
                            % ('updated' if installedVersion is not None else 'installed', name), GREEN)


def _updateSelf():
    if hasattr(sys, 'frozen'):
        htpcUpdaterExecutable = sys.executable
        htpcUpdaterDirectory = os.path.dirname(htpcUpdaterExecutable)

        _log('\nChecking for new version of htpc-updater ...')
        try:
            requests.get(HTPC_UPDATER_PROJECT)
        except:
            _log('ERROR: Could not connect to GitHub.\n', RED)
        else:
            releaseVersion = _getLatestGitHubReleaseVersion(HTPC_UPDATER_RELEASES)
            if _versiontuple(releaseVersion) > _versiontuple(__version__):
                _log(' %s is available, starting upgrade process.\n' % releaseVersion)

                url = HTPC_UPDATER_DL_PATH.format(releaseVersion)
                _log('Downloading %s ...' % url)
                htpcUpdaterZipFile = requests.get(url, headers=HEADERS_TRACKABLE).content
                _log(' done.\n')

                htpcUpdaterNew = _writeTempFile(ZipFile(StringIO(htpcUpdaterZipFile)).open('htpc-updater.exe').read())

                args = sys.argv[:]
                args = ['"%s"' % arg for arg in args]
                args.append('"--relaunch=%s"' % htpcUpdaterDirectory)

                # Clear the PATH so that MSVCRT libraries are not conflicting with libraries
                # from other programs that ship their own, avoiding error R6034.
                # This only affects the currently running htpc-updater.exe.
                environ = os.environ.copy()
                environ.pop('PATH', None)

                _log('Restarting htpc-updater ...\n\n')
                os.chdir(os.path.dirname(htpcUpdaterNew))
                os.execve(htpcUpdaterNew, args, environ)
            else:
                _log(' %s is the latest version.\n' % __version__)


def _isUpdatingSelf(arguments):
    return bool(arguments.get('relaunch'))


def _cleanupUpdate(arguments):
    copy(sys.executable, os.path.join(arguments.get('relaunch'), 'htpc-updater.exe'))


if __name__ == '__main__':
    _log('htpc-updater %s (%s)\n' % (__version__, HTPC_UPDATER_PROJECT))

    parser = argparse.ArgumentParser()
    parser.add_argument('--install-pre-release', dest='installPreReleaseList', action='store',
        help='Install pre-release versions of comma-separated argument if available.')
    parser.add_argument('--silent-install', dest='silentInstallList', action='store',
        help='Install comma-separated arguments without showing installer GUI.')
    parser.add_argument('--auto-exit', dest='autoExit', action='store_true',
        help='Close htpc-updater without prompt for ENTER key.')
    parser.add_argument('--relaunch', action='store')
    args = vars(parser.parse_args())

    if _isUpdatingSelf(args):
        _cleanupUpdate(args)
    else:
        _updateSelf()

    updateComponents(args)

    windll.Kernel32.SetConsoleTextAttribute(CONSOLE_HANDLER, BLACK)
    if not args.get('autoExit'):
        _log('\n')
        raw_input('Press ENTER to exit ...')
