rem pyi-makespec --onefile --console --manifest=htpc-updater.exe.manifest ./src/htpc-updater.py
pyi-build htpc-updater.spec --distpath=dist --workpath=build --noconfirm --ascii
