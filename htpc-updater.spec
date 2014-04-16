# -*- mode: python -*-
a = Analysis(['./src/htpc-updater.py'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
a.datas.append(('cacert.pem', 'cacert.pem', 'DATA'))
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts + [('O','','OPTION')],
          a.binaries,
          a.zipfiles,
          a.datas,
          name='htpc-updater.exe',
          debug=False,
          strip=None,
          upx=True,
          console=True,
          manifest='htpc-updater.exe.manifest',
)
