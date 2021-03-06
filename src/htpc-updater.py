# coding: iso-8859-1
"""
htpc-updater
Copyright (c) 2014 Nikola Klaric (nikola@generic.company)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
__author__ = 'Nikola Klaric (nikola@generic.company)'
__copyright__ = 'Copyright (c) 2014 Nikola Klaric'
__version__ = '0.8.2'

import sys
import argparse

from shutil import copy
from ctypes import c_ulong

from updater.lib import *

HTPC_UPDATER_RELEASES = 'https://api.github.com/repos/nikola/htpc-updater/releases'
HTPC_UPDATER_PROJECT = 'https://github.com/nikola/htpc-updater'
HTPC_UPDATER_DL_PATH = HTPC_UPDATER_PROJECT + '/releases/download/{0}/htpc-updater-{0}.zip'
CONSOLE_HANDLER = windll.Kernel32.GetStdHandle(c_ulong(0xfffffff5))

CWD = os.path.dirname(sys.executable) if hasattr(sys, 'frozen') else os.path.dirname(os.path.realpath(__file__))

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
    installComponentsList = arguments.get('installComponentsList')

    components = [
        ('MPC-HC', 'mpchc',
            'mpchc' in installPreReleaseList,
            'mpchc' in silentInstallList,
            Component(r'MPC-HC\MPC-HC',
                getLatestReleaseVersion =        mpcHc_getLatestReleaseVersion,
                getLatestPreReleaseVersion =     mpcHc_getLatestPreReleaseVersion,
                getInstalledVersion =            mpcHc_getInstalledVersion,
                getPostInstallVersion =          mpcHc_getPostInstallVersion,
                installLatestReleaseVersion =    mpcHc_installLatestReleaseVersion,
                installLatestPreReleaseVersion = mpcHc_installLatestPreReleaseVersion,
            )
        ),
        ('LAV Filters', 'lavfilters',
            'lavfilters' in installPreReleaseList,
            'lavfilters' in silentInstallList,
            Component(LAVFILTERS_CLSID,
                getLatestReleaseVersion =        lavFilters_getLatestReleaseVersion,
                getInstalledVersion =            lavFilters_getInstalledVersion,
                installLatestReleaseVersion =    lavFilters_installLatestReleaseVersion,
            )
        ),
        ('madVR', 'madvr',
            'madvr' in installPreReleaseList,
            'madvr' in silentInstallList,
            Component(MADVR_CLSID,
                getLatestReleaseVersion =        madVr_getLatestReleaseVersion,
                getInstalledVersion =            madVr_getInstalledVersion,
                installLatestReleaseVersion =    madVr_installLatestReleaseVersion,
            )
        ),
    ]

    for name, identifier, preRelease, silent, instance in components:
        if not identifier in installComponentsList:
            continue

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

                currentInstalledVersion, currentInstallationPath = instance.getPostInstallVersion(cwd=CWD)
                if currentInstallationPath is None or getVersionTuple(currentInstalledVersion) != getVersionTuple(latestVersion):
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

    parser = argparse.ArgumentParser(
        prog='htpc-updater',
        formatter_class=argparse.RawTextHelpFormatter,
        description='Install or update MPC-HC, LAV Filters and madVR automagically.',
        epilog="""Examples:
htpc-updater --install-components=mpchc,madvr --silent-install=mpchc
  Install only MPC-HC and madVR, and do not show the installer GUI of MPC-HC.

htpc-updater --install-pre-release=mpchc --auto-exit
  Install the latest MPC-HC nightly build and release versions of LAV Filters and madVR, and exit htpc-updater after completion."""
    )

    parser.add_argument('--install-components', dest='installComponentsList', action='store', default='mpchc,lavfilters,madvr',
        help='Install only comma-separated arguments.', metavar='= mpchc* | lavfilters* | madvr*')
    parser.add_argument('--install-pre-release', dest='installPreReleaseList', action='store',
        help='Install pre-release version of comma-separated arguments if available.', metavar='= mpchc')
    parser.add_argument('--silent-install', dest='silentInstallList', action='store',
        help='Install comma-separated arguments without showing installer GUI.', metavar='= mpchc* | lavfilters*')
    parser.add_argument('--auto-exit', dest='autoExit', action='store_true',
        help='Close htpc-updater without prompt for ENTER key.')
    parser.add_argument('--relaunch', action='store',
        help='Do not use this option.')
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
