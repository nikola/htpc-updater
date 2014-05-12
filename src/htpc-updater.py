# coding: iso-8859-1
"""
"""
__author__ = 'Nikola Klaric (nikola@generic.company)'
__copyright__ = 'Copyright (c) 2014 Nikola Klaric'
__version__ = '0.7.1'

import sys
import argparse

from shutil import copy
from ctypes import windll, c_ulong

from updater.lib import *

HTPC_UPDATER_RELEASES = 'https://api.github.com/repos/nikola/htpc-updater/releases'
HTPC_UPDATER_PROJECT = 'https://github.com/nikola/htpc-updater'
HTPC_UPDATER_DL_PATH = HTPC_UPDATER_PROJECT + '/releases/download/{0}/htpc-updater-{0}.zip'
CONSOLE_HANDLER = windll.Kernel32.GetStdHandle(c_ulong(0xfffffff5))

# Support unbuffered, colored console output.
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
windll.Kernel32.GetStdHandle.restype = c_ulong

def log(text=None, color=BLACK):
    windll.Kernel32.SetConsoleTextAttribute(CONSOLE_HANDLER, color)
    if text is not None: sys.stdout.write(text)

setLogger(log)


def _updateComponents(arguments):
    installPreReleaseList = arguments.get('installPreReleaseList') or ''
    silentInstallList = arguments.get('silentInstallList') or ''

    components = [
        ('MPC-HC',
            'mpchc' in installPreReleaseList,
            'mpchc' in silentInstallList,
            Component(r'MPC-HC\MPC-HC',
                getLatestReleaseVersion =        mpcHc_getLatestReleaseVersion,
                getLatestPreReleaseVersion =     mpcHc_getLatestPreReleaseVersion,
                getInstalledVersion =            mpcHc_getInstalledVersion,
                installLatestReleaseVersion =    mpcHc_installLatestReleaseVersion,
                installLatestPreReleaseVersion = mpcHc_installLatestPreReleaseVersion,
            )
        ),
        ('LAV Filters',
            'lavfilters' in installPreReleaseList,
            'lavfilters' in silentInstallList,
            Component(LAVFILTERS_CLSID,
                getLatestReleaseVersion =        lavFilters_getLatestReleaseVersion,
                getInstalledVersion =            lavFilters_getInstalledVersion,
                installLatestReleaseVersion =    lavFilters_installLatestReleaseVersion,
            )
        ),
        ('madVR',
            'madvr' in installPreReleaseList,
            'madvr' in silentInstallList,
            Component(MADVR_CLSID,
                getLatestReleaseVersion =        madVr_getLatestReleaseVersion,
                getInstalledVersion =            madVr_getInstalledVersion,
                installLatestReleaseVersion =    madVr_installLatestReleaseVersion,
            )
        ),
    ]

    for name, preRelease, silent, instance in components:
        log('\n')

        prefix, infix = ('pre-', 'Pre') if preRelease else ('', '')

        try:
            latestVersion = getattr(instance, 'getLatest%sReleaseVersion' % infix)()
        except:
            log('ERROR: Could not retrieve version info of the latest %s %srelease.\n' % (name, prefix), RED)
        else:
            log('Latest %srelease version of %s: %s\n' % (prefix, name, latestVersion))

            mustInstall = False
            installedVersion, detectedInstallationPath = instance.getInstalledVersion()
            if installedVersion is not None:
                log('Installed version: %s\n\t%s\n' % (installedVersion, detectedInstallationPath))

                if getVersionTuple(installedVersion) < getVersionTuple(latestVersion):
                    mustInstall = True
                else:
                    log('%s does not need to be updated.\n' % name, GREEN)
            else:
                log('%s does not seem to be installed on the local machine.\n' % name)
                mustInstall = True

            if mustInstall:
                getattr(instance, 'installLatest%sReleaseVersion' % infix)(latestVersion, detectedInstallationPath, silent)
                currentInstalledVersion, currentInstallationPath = instance.getInstalledVersion()
                if getVersionTuple(currentInstalledVersion) != getVersionTuple(latestVersion) or currentInstallationPath is None:
                    log('\nFailed to %s %s %s.\n'
                        % ('update to' if installedVersion is not None else 'install', name, latestVersion), RED)
                else:
                    log(' done.\n')
                    if detectedInstallationPath != currentInstallationPath:
                        log('%s %s is now installed in:\n\t%s\n'
                            % (name, latestVersion, currentInstallationPath))
                        if installedVersion is not None:
                            log('Your previous installation of %s %s remains in:\n\t%s\n'
                                % (name, installedVersion, detectedInstallationPath))
                    log('Successfully %s %s. No errors.\n'
                        % ('updated' if installedVersion is not None else 'installed', name), GREEN)


def _updateSelf():
    if hasattr(sys, 'frozen'):
        htpcUpdaterExecutable = sys.executable
        htpcUpdaterDirectory = os.path.dirname(htpcUpdaterExecutable)

        log('\nChecking for new version of htpc-updater ...')
        try:
            requests.get(HTPC_UPDATER_PROJECT)
        except:
            log(' ERROR: Could not connect to GitHub.\n', RED)
        else:
            releaseVersion = getLatestGitHubReleaseVersion(HTPC_UPDATER_RELEASES)
            if getVersionTuple(releaseVersion) > getVersionTuple(__version__):
                log(' %s is available, starting upgrade process.\n' % releaseVersion)

                url = HTPC_UPDATER_DL_PATH.format(releaseVersion)
                log('Downloading %s ...' % url)
                htpcUpdaterZipFile = requests.get(url, headers=HEADERS_TRACKABLE).content
                log(' done.\n')

                htpcUpdaterNew = writeTempFile(ZipFile(StringIO(htpcUpdaterZipFile)).open('htpc-updater.exe').read())

                args = ['"%s"' % arg for arg in sys.argv]
                args.append('"--relaunch=%s"' % htpcUpdaterDirectory)

                # Clear the PATH so that MSVCRT libraries are not conflicting with libraries
                # from other programs that ship their own, avoiding error R6034.
                # This only affects the currently running htpc-updater.exe.
                environ = os.environ.copy()
                environ.pop('PATH', None)

                log('Restarting htpc-updater ...\n\n')
                os.chdir(os.path.dirname(htpcUpdaterNew))
                os.execve(htpcUpdaterNew, args, environ)
            else:
                log(' %s is the latest version.\n' % __version__)


def _isUpdatingSelf(arguments):
    return bool(arguments.get('relaunch'))


def _cleanupUpdate(arguments):
    copy(sys.executable, os.path.join(arguments.get('relaunch'), 'htpc-updater.exe'))


if __name__ == '__main__':
    log('htpc-updater %s (%s)\n' % (__version__, HTPC_UPDATER_PROJECT))

    parser = argparse.ArgumentParser()
    parser.add_argument('--install-pre-release', dest='installPreReleaseList', action='store',
        help='Install pre-release versions of comma-separated argument if available.')
    parser.add_argument('--silent-install', dest='silentInstallList', action='store',
        help='Install comma-separated arguments without showing installer GUI.')
    parser.add_argument('--auto-exit', dest='autoExit', action='store_true',
        help='Close htpc-updater without prompt for ENTER key.')
    parser.add_argument('--relaunch', action='store')
    options = vars(parser.parse_args())

    if getattr(sys, 'frozen', None):
        # Enable SSL support in requests library when running as EXE.
        os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(sys._MEIPASS, 'cacert.pem')

        if _isUpdatingSelf(options):
            _cleanupUpdate(options)
        else:
            _updateSelf()

    try:
        _updateComponents(options)
    except:
        import traceback
        log('\n', RED)
        traceback.print_exc()

    log()
    if not options.get('autoExit'):
        log('\n')
        raw_input('Press ENTER to exit ...')
