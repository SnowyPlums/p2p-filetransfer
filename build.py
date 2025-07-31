import PyInstaller.__main__
import os
import shutil

# Clean up previous build
if os.path.exists('dist'):
    shutil.rmtree('dist')
if os.path.exists('build'):
    shutil.rmtree('build')

# PyInstaller configuration
pyinstaller_args = [
    'main.py',
    '--onefile',
    '--windowed',
    '--name=FileTransfer',
    '--add-data', 'firebase-key.json:.',
    '--add-data', 'config.ini:.',
    '--add-data', 'icon.ico:.',
    '--hidden-import', 'cryptography.hazmat.bindings._rust',
    '--hidden-import', 'cryptography.hazmat.bindings._padding',
    '--icon=icon.ico'
]

# Execute build
PyInstaller.__main__.run(pyinstaller_args)

# Post-build: Copy required files to dist directory
dist_dir = 'dist'
if not os.path.exists(dist_dir):
    os.makedirs(dist_dir)

shutil.copy('firebase-key.json', dist_dir)
shutil.copy('config.ini', dist_dir)
shutil.copy('icon.ico', dist_dir)

print("\nBuild complete! Executable is in the 'dist' folder")